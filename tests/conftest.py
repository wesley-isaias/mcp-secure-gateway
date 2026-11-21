import json
import secrets

import pytest

from mcp_secure_gateway.tokens import hash_token

VIEWER_TOKEN = "viewer-" + secrets.token_urlsafe(16)
TESTER_TOKEN = "tester-" + secrets.token_urlsafe(16)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in (
        "MCP_DEMO_ROLE",
        "MCP_GATEWAY_TOKENS_FILE",
        "MCP_GATEWAY_AUDIT_LOG",
        "MCP_GATEWAY_AUDIT_KEY_FILE",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def audit_key(tmp_path):
    path = tmp_path / "audit.key"
    path.write_bytes(secrets.token_hex(32).encode())
    path.chmod(0o600)
    return path


@pytest.fixture
def token_file(tmp_path):
    path = tmp_path / "tokens.json"
    path.write_text(
        json.dumps(
            {
                hash_token(VIEWER_TOKEN): {"client_id": "dashboard", "role": "viewer"},
                hash_token(TESTER_TOKEN): {"client_id": "ci-bot", "role": "tester"},
            }
        )
    )
    return path


def read_audit(path):
    return [json.loads(line) for line in path.read_text().splitlines()]
