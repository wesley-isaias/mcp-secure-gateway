import pytest

from fastmcp import Client
from mcp_secure_gateway.server import mcp


@pytest.mark.asyncio
async def test_mcp_tools_are_discoverable():
    async with Client(mcp) as client:
        names = {tool.name for tool in await client.list_tools()}
        assert {"list_fixtures", "get_fixture", "run_checks"} <= names


@pytest.mark.asyncio
async def test_mcp_authorized_call():
    async with Client(mcp) as client:
        result = await client.call_tool("list_fixtures", {"role": "viewer"})
        assert not result.is_error
        assert "alpha" in str(result.content)


@pytest.mark.asyncio
async def test_mcp_denied_call():
    async with Client(mcp) as client:
        result = await client.call_tool(
            "run_checks", {"role": "viewer"}, raise_on_error=False
        )
        assert result.is_error


@pytest.mark.asyncio
async def test_unknown_fixture_is_rejected():
    async with Client(mcp) as client:
        result = await client.call_tool(
            "get_fixture", {"fixture_id": "../secrets"}, raise_on_error=False
        )
        assert result.is_error
