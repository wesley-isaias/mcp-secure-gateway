"""Bearer-token authentication backed by a file of token *hashes*.

The server never stores plaintext tokens. The token file maps the SHA-256 hex
digest of each token to a client identifier and a role::

    {
      "9f86d0...": {"client_id": "ci-bot", "role": "tester"},
      "2c26b4...": {"client_id": "dashboard", "role": "viewer"}
    }

Generate an entry with ``mcp-secure-gateway new-token --client-id NAME --role ROLE``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from pathlib import Path

from fastmcp.server.auth import TokenVerifier
from fastmcp.server.auth.auth import AccessToken

from .policy import Role

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CLIENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class TokenFileError(ValueError):
    """The token file is missing, malformed or contains an invalid entry."""


def hash_token(token: str) -> str:
    """Return the SHA-256 hex digest stored in the token file."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_token() -> str:
    """Return a new random bearer token (256 bits, URL-safe)."""
    return secrets.token_urlsafe(32)


def load_token_file(path: Path) -> dict[str, tuple[str, Role]]:
    """Load and validate the token file. Invalid content fails loudly at startup."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise TokenFileError(f"token file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise TokenFileError(f"token file is not valid JSON: {exc.msg}") from exc
    if not isinstance(raw, dict) or not raw:
        raise TokenFileError("token file must be a non-empty JSON object")

    entries: dict[str, tuple[str, Role]] = {}
    for digest, info in raw.items():
        if not isinstance(digest, str) or not _HEX64.match(digest):
            raise TokenFileError("keys must be lowercase SHA-256 hex digests, not tokens")
        if not isinstance(info, dict) or set(info) != {"client_id", "role"}:
            raise TokenFileError("each entry must have exactly 'client_id' and 'role'")
        client_id = info["client_id"]
        if not isinstance(client_id, str) or not _CLIENT_ID.match(client_id):
            raise TokenFileError(f"invalid client_id: {client_id!r}")
        try:
            role = Role(info["role"])
        except ValueError as exc:
            raise TokenFileError(f"unknown role for {client_id}: {info['role']!r}") from exc
        entries[digest] = (client_id, role)
    return entries


class HashedTokenVerifier(TokenVerifier):
    """Verifies opaque bearer tokens against hashed entries loaded at startup."""

    def __init__(self, entries: dict[str, tuple[str, Role]]):
        super().__init__()
        if not entries:
            raise TokenFileError("at least one token is required")
        self._entries = dict(entries)

    @classmethod
    def from_file(cls, path: Path) -> HashedTokenVerifier:
        return cls(load_token_file(path))

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token:
            return None
        digest = hash_token(token)
        match = None
        # Compare against every entry so timing does not depend on which entry matched.
        for stored, identity in self._entries.items():
            if hmac.compare_digest(stored, digest):
                match = identity
        if match is None:
            return None
        client_id, role = match
        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=[f"role:{role.value}"],
            claims={"role": role.value},
        )
