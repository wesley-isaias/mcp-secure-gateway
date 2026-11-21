"""The single enforcement point for every MCP tool call.

Order of checks, all before the tool runs:

1. Identity: from the verified bearer token (HTTP) or the operator-set role
   (local stdio). Tool arguments can never influence it.
2. Rate limit per client.
3. Deny-by-default policy.
4. Audit record written and flushed. If that fails, the call is refused.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import Middleware

from .audit import AuditError, AuditLog, pseudonym
from .policy import authorize
from .ratelimit import RateLimiter

_SAFE_TOOL = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


@dataclass(frozen=True)
class Identity:
    client_id: str
    role: str


class GatewayMiddleware(Middleware):
    def __init__(
        self,
        *,
        local_role: str,
        audit: AuditLog | None,
        limiter: RateLimiter | None,
        require_token: bool,
    ):
        self._local_role = local_role
        self._audit = audit
        self._limiter = limiter
        self._require_token = require_token

    def _identity(self) -> Identity | None:
        token = get_access_token()
        if token is not None:
            return Identity(token.client_id, str(token.claims.get("role", "")))
        if self._require_token:
            return None
        return Identity("local", self._local_role)

    def _record(self, identity: Identity, tool: str, decision: str, reason: str) -> None:
        if self._audit is None:
            return
        label = pseudonym(self._audit.key, identity.client_id)
        safe_tool = tool if _SAFE_TOOL.match(tool) else "other"
        try:
            self._audit.append(client=label, tool=safe_tool, decision=decision, reason=reason)
        except AuditError as exc:
            raise ToolError("Denied: audit_unavailable") from exc

    async def on_call_tool(self, context, call_next):
        tool = context.message.name
        identity = self._identity()
        if identity is None:
            raise ToolError("Denied: unauthenticated")

        if self._limiter is not None and not self._limiter.allow(identity.client_id):
            self._record(identity, tool, "rate_limited", "rate_limited")
            raise ToolError("Denied: rate_limited")

        decision = authorize(identity.role, tool)
        if not decision.allowed:
            self._record(identity, tool, "denied", decision.reason)
            raise ToolError(f"Denied: {decision.reason}")

        # Write-ahead: the record exists before the tool has any effect.
        self._record(identity, tool, "allowed", decision.reason)
        return await call_next(context)
