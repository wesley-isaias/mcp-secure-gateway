"""Network transport: real HTTP server, real MCP client, real bearer tokens."""

import httpx
import pytest
from fastmcp import Client
from fastmcp.utilities.tests import run_server_async

from mcp_secure_gateway.audit import pseudonym
from mcp_secure_gateway.server import Config, build_server

from .conftest import TESTER_TOKEN, VIEWER_TOKEN, read_audit


@pytest.fixture
async def http_server(tmp_path, token_file, audit_key):
    config = Config(
        transport="http",
        tokens_file=token_file,
        audit_log=tmp_path / "audit.jsonl",
        audit_key_file=audit_key,
    )
    async with run_server_async(build_server(config)) as url:
        yield url, tmp_path / "audit.jsonl", audit_key.read_bytes().strip()


async def test_request_without_token_gets_401(http_server):
    url, _, _ = http_server
    async with httpx.AsyncClient() as http:
        response = await http.post(url, json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert response.status_code == 401


async def test_invalid_token_is_rejected(http_server):
    url, _, _ = http_server
    with pytest.raises(Exception):  # noqa: B017 - transport raises an HTTP 401 error
        async with Client(url, auth="not-a-real-token") as client:
            await client.list_tools()


async def test_viewer_token_reads_but_cannot_run_checks(http_server):
    url, _, _ = http_server
    async with Client(url, auth=VIEWER_TOKEN) as client:
        assert (await client.call_tool("list_fixtures", {})).data == ["alpha", "beta"]
        denied = await client.call_tool("run_checks", {}, raise_on_error=False)
        assert denied.is_error


async def test_tester_token_can_run_checks(http_server):
    url, _, _ = http_server
    async with Client(url, auth=TESTER_TOKEN) as client:
        result = await client.call_tool("run_checks", {})
        assert result.data["fixtures_are_distinct"] is True


async def test_audit_identifies_clients_by_pseudonym_only(http_server):
    url, log, key = http_server
    async with Client(url, auth=TESTER_TOKEN) as client:
        await client.call_tool("run_checks", {})
    records = read_audit(log)
    assert records[-1]["client"] == pseudonym(key, "ci-bot")
    text = log.read_text()
    assert "ci-bot" not in text and TESTER_TOKEN not in text


async def test_viewer_token_does_not_see_tester_tools(http_server):
    url, _, _ = http_server
    async with Client(url, auth=VIEWER_TOKEN) as client:
        names = {t.name for t in await client.list_tools()}
    assert names == {"list_fixtures", "get_fixture"}
