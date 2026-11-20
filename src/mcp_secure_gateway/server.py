"""Read-only fictional data and deterministic checks exposed through MCP tools.

This educational example does not provide authentication. The role is supplied
by the caller and MUST NOT be treated as a trusted identity in production.
"""

from fastmcp import FastMCP

from .policy import authorize

mcp = FastMCP("MCP Secure Gateway Demo")

_FIXTURES = {
    "alpha": {"name": "Alpha Clinic", "appointments": 3},
    "beta": {"name": "Beta Clinic", "appointments": 0},
}


def _require(role: str, action: str) -> None:
    decision = authorize(role, action)
    if not decision.allowed:
        raise PermissionError(f"Denied: {decision.reason}")


@mcp.tool()
def list_fixtures(role: str = "viewer") -> list[str]:
    """List fictional fixture identifiers. No real user data is used."""
    _require(role, "list_fixtures")
    return sorted(_FIXTURES)


@mcp.tool()
def get_fixture(fixture_id: str, role: str = "viewer") -> dict[str, str | int]:
    """Return a known fictional record; unknown identifiers are rejected."""
    _require(role, "get_fixture")
    if fixture_id not in _FIXTURES:
        raise ValueError("Unknown fixture ID")
    return dict(_FIXTURES[fixture_id])


@mcp.tool()
def run_checks(role: str = "viewer") -> dict[str, bool]:
    """Run deterministic in-memory checks; never execute arbitrary commands."""
    _require(role, "run_checks")
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
