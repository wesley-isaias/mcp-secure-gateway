import pytest
from fastmcp import Client

from mcp_secure_gateway.server import mcp


@pytest.mark.asyncio
async def test_mcp_tools_are_discoverable(monkeypatch):
    monkeypatch.delenv("MCP_DEMO_ROLE", raising=False)
    async with Client(mcp) as client:
        tools = await client.list_tools()
        names = {tool.name for tool in tools}
        assert {"list_fixtures", "get_fixture", "run_checks"} <= names
        assert all("role" not in str(tool.inputSchema.get("properties", {})) for tool in tools)


@pytest.mark.asyncio
async def test_mcp_authorized_call(monkeypatch):
    monkeypatch.delenv("MCP_DEMO_ROLE", raising=False)
    async with Client(mcp) as client:
        result = await client.call_tool("list_fixtures", {})
        assert not result.is_error
        assert "alpha" in str(result.content)


@pytest.mark.asyncio
async def test_mcp_denied_call(monkeypatch):
    monkeypatch.delenv("MCP_DEMO_ROLE", raising=False)
    async with Client(mcp) as client:
        result = await client.call_tool("run_checks", {}, raise_on_error=False)
        assert result.is_error


@pytest.mark.asyncio
async def test_mcp_tester_role_is_server_controlled(monkeypatch):
    monkeypatch.setenv("MCP_DEMO_ROLE", "tester")
    async with Client(mcp) as client:
        result = await client.call_tool("run_checks", {})
        assert not result.is_error


@pytest.mark.asyncio
async def test_unknown_server_role_is_denied(monkeypatch):
    monkeypatch.setenv("MCP_DEMO_ROLE", "admin")
    async with Client(mcp) as client:
        result = await client.call_tool("list_fixtures", {}, raise_on_error=False)
        assert result.is_error


@pytest.mark.asyncio
async def test_caller_cannot_escalate_role(monkeypatch):
    monkeypatch.delenv("MCP_DEMO_ROLE", raising=False)
    async with Client(mcp) as client:
        result = await client.call_tool(
            "run_checks", {"role": "tester"}, raise_on_error=False
        )
        assert result.is_error


@pytest.mark.asyncio
async def test_unknown_fixture_is_rejected(monkeypatch):
    monkeypatch.delenv("MCP_DEMO_ROLE", raising=False)
    async with Client(mcp) as client:
        result = await client.call_tool(
            "get_fixture", {"fixture_id": "../secrets"}, raise_on_error=False
        )
        assert result.is_error
