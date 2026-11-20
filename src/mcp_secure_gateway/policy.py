"""Pure authorization policy: deny by default, no filesystem or shell access."""

from dataclasses import dataclass
from enum import Enum


class Role(str, Enum):
    VIEWER = "viewer"
    TESTER = "tester"


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


_ALLOWED: dict[Role, frozenset[str]] = {
    Role.VIEWER: frozenset({"list_fixtures", "get_fixture"}),
    Role.TESTER: frozenset({"list_fixtures", "get_fixture", "run_checks"}),
}


def authorize(role: str, action: str) -> Decision:
    """Evaluate a request without performing the requested operation."""
    try:
        parsed_role = Role(role)
    except ValueError:
        return Decision(False, "unknown_role")
    if action not in _ALLOWED[parsed_role]:
        return Decision(False, "action_denied")
    return Decision(True, "allowed")
