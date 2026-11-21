"""Read-only fictional data and deterministic checks exposed through MCP tools.

This educational example is local-only and does not provide user authentication.
The role comes from the server process environment, never from tool arguments.
"""

import os

from fastmcp import FastMCP

from .policy import authorize

mcp = FastMCP("MCP Secure Gateway Demo")

_FIXTURES = {
    "alpha": {"name": "Alpha Clinic", "appointments": 3},
    "beta": {"name": "Beta Clinic", "appointments": 0},
}


def _require(action: str) -> None:
    # Process-owned configuration; untrusted MCP clients cannot choose their role.
    decision = authorize(os.environ.get("MCP_DEMO_ROLE", "viewer"), action)
    if not decision.allowed:
        raise PermissionError(f"Denied: {decision.reason}")


@mcp.tool()
def list_fixtures() -> list[str]:
    """List fictional fixture identifiers. No real user data is used."""
    _require("list_fixtures")
    return sorted(_FIXTURES)


@mcp.tool()
def get_fixture(fixture_id: str) -> dict[str, str | int]:
    """Return a known fictional record; unknown identifiers are rejected."""
    _require("get_fixture")
    if fixture_id not in _FIXTURES:
        raise ValueError("Unknown fixture ID")
    return dict(_FIXTURES[fixture_id])


@mcp.tool()
def run_checks() -> dict[str, bool]:
    """Run deterministic in-memory checks; never execute arbitrary commands."""
    _require("run_checks")
    return {
        "fixtures_are_distinct": len(_FIXTURES) == len(set(_FIXTURES)),
        "appointments_nonnegative": all(
            record["appointments"] >= 0 for record in _FIXTURES.values()
        ),
    }


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
