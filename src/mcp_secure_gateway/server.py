"""MCP server with fictional, read-only tools behind an enforcement middleware.

The command-line interface lives in ``cli.py``. Two ways to run the server:

* ``serve --transport stdio`` (default): local use by one operator. The role
  comes from ``MCP_DEMO_ROLE`` in the server's environment.
* ``serve --transport http``: network use. Every request needs a bearer token
  from the hashed token file, and an audit log is mandatory.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from fastmcp import FastMCP

from .audit import AuditLog, load_key
from .middleware import GatewayMiddleware
from .ratelimit import RateLimiter
from .tokens import HashedTokenVerifier

_FIXTURES = {
    "alpha": {"name": "Alpha Clinic", "appointments": 3},
    "beta": {"name": "Beta Clinic", "appointments": 0},
}


@dataclass(frozen=True)
class Config:
    transport: str = "stdio"
    local_role: str = "viewer"
    tokens_file: Path | None = None
    audit_log: Path | None = None
    audit_key_file: Path | None = None
    rate_per_second: float = 5.0
    rate_burst: int = 10

    @classmethod
    def from_env(cls, transport: str = "stdio") -> Config:
        def path(name: str) -> Path | None:
            value = os.environ.get(name)
            return Path(value) if value else None

        return cls(
            transport=transport,
            local_role=os.environ.get("MCP_DEMO_ROLE", "viewer"),
            tokens_file=path("MCP_GATEWAY_TOKENS_FILE"),
            audit_log=path("MCP_GATEWAY_AUDIT_LOG"),
            audit_key_file=path("MCP_GATEWAY_AUDIT_KEY_FILE"),
            rate_per_second=float(os.environ.get("MCP_GATEWAY_RATE_PER_SECOND", "5")),
            rate_burst=int(os.environ.get("MCP_GATEWAY_RATE_BURST", "10")),
        )


class ConfigError(ValueError):
    """The server refuses to start with an unsafe or incomplete configuration."""


def build_server(config: Config) -> FastMCP:
    """Create the server. Unsafe network configurations fail before startup."""
    network = config.transport == "http"
    auth = None
    if network:
        if config.tokens_file is None:
            raise ConfigError("HTTP transport requires MCP_GATEWAY_TOKENS_FILE")
        if config.audit_log is None or config.audit_key_file is None:
            raise ConfigError("HTTP transport requires an audit log and key")
        auth = HashedTokenVerifier.from_file(config.tokens_file)

    audit = None
    if config.audit_log is not None:
        if config.audit_key_file is None:
            raise ConfigError("MCP_GATEWAY_AUDIT_LOG requires MCP_GATEWAY_AUDIT_KEY_FILE")
        audit = AuditLog(config.audit_log, load_key(config.audit_key_file))

    mcp = FastMCP("MCP Secure Gateway", auth=auth)
    mcp.add_middleware(
        GatewayMiddleware(
            local_role=config.local_role,
            audit=audit,
            limiter=RateLimiter(config.rate_per_second, config.rate_burst),
            require_token=network,
        )
    )

    @mcp.tool()
    def list_fixtures() -> list[str]:
        """List fictional fixture identifiers. No real user data is used."""
        return sorted(_FIXTURES)

    @mcp.tool()
    def get_fixture(fixture_id: str) -> dict[str, str | int]:
        """Return a known fictional record; unknown identifiers are rejected."""
        if fixture_id not in _FIXTURES:
            raise ValueError("Unknown fixture ID")
        return dict(_FIXTURES[fixture_id])

    @mcp.tool()
    def run_checks() -> dict[str, bool]:
        """Run deterministic in-memory checks; never execute arbitrary commands."""
        return {
            "fixtures_are_distinct": len(_FIXTURES) == len(set(_FIXTURES)),
            "appointments_nonnegative": all(
                record["appointments"] >= 0 for record in _FIXTURES.values()
            ),
        }

    return mcp
