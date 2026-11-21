"""MCP server with fictional, read-only tools behind an enforcement middleware.

Two ways to run it:

* ``serve --transport stdio`` (default): local use by one operator. The role
  comes from ``MCP_DEMO_ROLE`` in the server's environment.
* ``serve --transport http``: network use. Every request needs a bearer token
  from the hashed token file, and an audit log is mandatory.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from fastmcp import FastMCP

from .audit import AuditError, AuditLog, load_key, verify
from .middleware import GatewayMiddleware
from .ratelimit import RateLimiter
from .tokens import HashedTokenVerifier, TokenFileError, generate_token, hash_token

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


def _cmd_serve(args: argparse.Namespace) -> int:
    try:
        mcp = build_server(Config.from_env(args.transport))
    except (ConfigError, TokenFileError, AuditError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.transport == "http":
        mcp.run(transport="http", host=args.host, port=args.port)
    else:
        mcp.run()
    return 0


def _cmd_new_token(args: argparse.Namespace) -> int:
    token = generate_token()
    entry = {hash_token(token): {"client_id": args.client_id, "role": args.role}}
    print("Token (give this to the client once; it is not stored):", token)
    print("Add this entry to the token file:")
    print(json.dumps(entry, indent=2))
    return 0


def _cmd_verify_audit(args: argparse.Namespace) -> int:
    try:
        result = verify(Path(args.log), load_key(Path(args.key_file)))
    except (AuditError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if result.ok:
        print(f"OK: {result.records} records, chain intact, last mac {result.last_mac[:16]}…")
        return 0
    print(f"TAMPERED: line {result.error_line}: {result.reason}")
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-secure-gateway")
    sub = parser.add_subparsers(dest="command")

    serve = sub.add_parser("serve", help="run the MCP server (default)")
    serve.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.set_defaults(func=_cmd_serve)

    new_token = sub.add_parser("new-token", help="generate a token and its file entry")
    new_token.add_argument("--client-id", required=True)
    new_token.add_argument("--role", choices=["viewer", "tester"], required=True)
    new_token.set_defaults(func=_cmd_new_token)

    check = sub.add_parser("verify-audit", help="verify an audit log's chain")
    check.add_argument("log")
    check.add_argument("--key-file", required=True)
    check.set_defaults(func=_cmd_verify_audit)

    args = parser.parse_args(argv)
    if args.command is None:
        args = parser.parse_args(["serve", *(argv or [])])
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
