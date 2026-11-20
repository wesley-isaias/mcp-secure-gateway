import pytest

from mcp_secure_gateway.policy import authorize


@pytest.mark.parametrize(
    ("role", "action", "expected"),
    [
        ("viewer", "list_fixtures", True),
        ("viewer", "get_fixture", True),
        ("viewer", "run_checks", False),
        ("tester", "run_checks", True),
        ("admin", "run_checks", False),
        ("tester", "delete_fixture", False),
        ("", "list_fixtures", False),
    ],
)
def test_policy(role, action, expected):
    assert authorize(role, action).allowed is expected


def test_unknown_role_is_explicitly_denied():
    assert authorize("admin", "list_fixtures").reason == "unknown_role"
