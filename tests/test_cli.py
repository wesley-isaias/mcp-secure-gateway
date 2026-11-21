import json
import subprocess
import sys

from mcp_secure_gateway.cli import main
from mcp_secure_gateway.tokens import hash_token, load_token_file


def test_cli_prints_no_dependency_warnings():
    result = subprocess.run(
        [sys.executable, "-W", "default", "-m", "mcp_secure_gateway.cli", "--help"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "usage: mcp-secure-gateway" in result.stdout
    assert "Warning" not in result.stderr


def test_new_token_prints_a_loadable_entry(tmp_path, capsys):
    assert main(["new-token", "--client-id", "ci-bot", "--role", "tester"]) == 0
    out = capsys.readouterr().out
    token = out.splitlines()[0].rsplit(" ", 1)[-1]
    entry = json.loads(out.split("Add this entry to the token file:\n", 1)[1])
    path = tmp_path / "tokens.json"
    path.write_text(json.dumps(entry))
    assert load_token_file(path)[hash_token(token)][0] == "ci-bot"


def test_http_without_config_exits_with_error(capsys):
    assert main(["serve", "--transport", "http"]) == 2
    assert "MCP_GATEWAY_TOKENS_FILE" in capsys.readouterr().err
