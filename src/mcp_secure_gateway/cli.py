"""Command-line interface: ``serve``, ``new-token`` and ``verify-audit``."""

from __future__ import annotations

import argparse
import json
import sys
import warnings
from pathlib import Path


def _quiet_dependency_warnings() -> None:
    """Hide a third-party deprecation notice that FastMCP's auth stack prints on import.

    ``authlib`` forces its own warnings to "always", so the filter has to be added
    after that module loads and before FastMCP imports it. Only the CLI does this;
    importing the library leaves the caller's warning settings untouched.
    """
    try:
        from authlib.deprecate import AuthlibDeprecationWarning
    except ImportError:  # pragma: no cover - authlib layout changed
        return
    warnings.filterwarnings("ignore", category=AuthlibDeprecationWarning)


def _cmd_serve(args: argparse.Namespace) -> int:
    from .audit import AuditError
    from .server import Config, ConfigError, build_server
    from .tokens import TokenFileError

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
    from .tokens import generate_token, hash_token

    token = generate_token()
    entry = {hash_token(token): {"client_id": args.client_id, "role": args.role}}
    print("Token (give this to the client once; it is not stored):", token)
    print("Add this entry to the token file:")
    print(json.dumps(entry, indent=2))
    return 0


def _cmd_verify_audit(args: argparse.Namespace) -> int:
    from .audit import AuditError, load_key, verify

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
    _quiet_dependency_warnings()
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
