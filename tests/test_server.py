"""Local (stdio-style) server behaviour, using a real in-process MCP client."""

import pytest
from fastmcp import Client

from mcp_secure_gateway.audit import verify
from mcp_secure_gateway.cli import main
from mcp_secure_gateway.server import Config, ConfigError, build_server

from .conftest import read_audit


def _server(tmp_path=None, audit_key=None, **overrides):
    kwargs = {}
    if tmp_path is not None:
        kwargs = {"audit_log": tmp_path / "audit.jsonl", "audit_key_file": audit_key}
    return build_server(Config(**kwargs, **overrides))


async def test_tools_are_discoverable_and_take_no_role():
    async with Client(_server(local_role="tester")) as client:
        tools = await client.list_tools()
        assert {t.name for t in tools} == {"list_fixtures", "get_fixture", "run_checks"}
        assert all("role" not in t.inputSchema.get("properties", {}) for t in tools)


async def test_tool_list_only_shows_what_the_role_may_call():
    async with Client(_server()) as client:
        names = {t.name for t in await client.list_tools()}
        assert names == {"list_fixtures", "get_fixture"}


async def test_unknown_role_sees_no_tools():
    async with Client(_server(local_role="admin")) as client:
        assert await client.list_tools() == []


async def test_successful_call_records_outcome(tmp_path, audit_key):
    async with Client(_server(tmp_path, audit_key)) as client:
        await client.call_tool("list_fixtures", {})
    records = read_audit(tmp_path / "audit.jsonl")
    assert [(r["decision"], r["reason"]) for r in records] == [
        ("allowed", "allowed"),
        ("succeeded", "ok"),
    ]


async def test_viewer_can_read():
    async with Client(_server()) as client:
        result = await client.call_tool("get_fixture", {"fixture_id": "alpha"})
        assert result.data == {"name": "Alpha Clinic", "appointments": 3}


async def test_viewer_cannot_run_checks():
    async with Client(_server()) as client:
        result = await client.call_tool("run_checks", {}, raise_on_error=False)
        assert result.is_error and "action_denied" in str(result.content)


async def test_tester_role_comes_from_operator_config():
    async with Client(_server(local_role="tester")) as client:
        result = await client.call_tool("run_checks", {})
        assert result.data["appointments_nonnegative"] is True


async def test_unknown_operator_role_denies_everything():
    async with Client(_server(local_role="admin")) as client:
        result = await client.call_tool("list_fixtures", {}, raise_on_error=False)
        assert result.is_error and "unknown_role" in str(result.content)


async def test_caller_cannot_escalate_through_arguments():
    async with Client(_server()) as client:
        result = await client.call_tool("run_checks", {"role": "tester"}, raise_on_error=False)
        assert result.is_error


async def test_unknown_fixture_is_rejected():
    async with Client(_server()) as client:
        result = await client.call_tool(
            "get_fixture", {"fixture_id": "../secrets"}, raise_on_error=False
        )
        assert result.is_error


async def test_rate_limit_blocks_bursts():
    async with Client(_server(rate_per_second=0.001, rate_burst=2)) as client:
        ok = [
            not (await client.call_tool("list_fixtures", {}, raise_on_error=False)).is_error
            for _ in range(3)
        ]
        assert ok == [True, True, False]


async def test_every_call_is_audited_without_content(tmp_path, audit_key):
    log = tmp_path / "audit.jsonl"
    async with Client(_server(tmp_path, audit_key)) as client:
        await client.call_tool(
            "get_fixture", {"fixture_id": "alpha-SECRET-ARG"}, raise_on_error=False
        )
        await client.call_tool("run_checks", {}, raise_on_error=False)
    records = read_audit(log)
    assert [(r["tool"], r["decision"]) for r in records] == [
        ("get_fixture", "allowed"),
        ("get_fixture", "failed"),  # unknown fixture: the tool raised
        ("run_checks", "denied"),
    ]
    assert "SECRET-ARG" not in log.read_text()
    assert verify(log, audit_key.read_bytes().strip()).ok


async def test_audit_failure_blocks_the_call(tmp_path, audit_key):
    server = _server(tmp_path, audit_key)
    (tmp_path / "audit.jsonl").mkdir()  # make the log unwritable
    async with Client(server) as client:
        result = await client.call_tool("list_fixtures", {}, raise_on_error=False)
        assert result.is_error and "audit_unavailable" in str(result.content)


def test_http_without_tokens_refuses_to_start(tmp_path, audit_key):
    with pytest.raises(ConfigError, match="TOKENS_FILE"):
        build_server(Config(transport="http", audit_log=tmp_path / "a", audit_key_file=audit_key))


def test_http_without_audit_refuses_to_start(token_file):
    with pytest.raises(ConfigError, match="audit"):
        build_server(Config(transport="http", tokens_file=token_file))


def test_cli_verify_audit_reports_tampering(tmp_path, audit_key, capsys):
    log = tmp_path / "audit.jsonl"
    from mcp_secure_gateway.audit import AuditLog

    writer = AuditLog(log, audit_key.read_bytes().strip())
    writer.append(client="c", tool="list_fixtures", decision="allowed", reason="allowed")
    assert main(["verify-audit", str(log), "--key-file", str(audit_key)]) == 0
    log.write_text(log.read_text().replace("allowed", "denied", 1))
    assert main(["verify-audit", str(log), "--key-file", str(audit_key)]) == 1
    assert "TAMPERED" in capsys.readouterr().out
