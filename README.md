# MCP Secure Gateway

A small, **real MCP server** that exposes fictional records and deterministic checks through three tools. Built as an independent engineering portfolio demonstration.

> **Security boundary:** this is an educational authorization-policy demonstration, **not** a production gateway. The client supplies its own role, so roles are **not authenticated**. Never use the supplied role as proof of identity.

## Quick start

Requires Python 3.11+.

```bash
python -m venv .venv
# Activate the virtual environment for your shell
python -m pip install -e ".[dev]"
pytest -q
ruff check .
mcp-secure-gateway
```

The last command starts the MCP server over standard input/output. Use an MCP-compatible client to connect. To test the protocol **without** external services, run the integration tests; they use a real in-process MCP client.

## Tools

| Tool | Viewer | Tester | Behavior |
| --- | --- | --- | --- |
| `list_fixtures` | Allow | Allow | Returns `alpha`, `beta` |
| `get_fixture` | Allow | Allow | Reads an allow-listed fictional record |
| `run_checks` | Deny | Allow | Performs deterministic in-memory checks |

Unknown roles and unknown actions are denied. No shell commands, external network access, credentials, user records, or real filesystem paths are used.

## Architecture

```text
MCP Client -> FastMCP tool -> authorize(role, action) -> in-memory fixtures/checks
                               |
                               +-> deny (explicit error)
```

The policy is pure and separately unit-tested. MCP integration tests verify tool discovery, an authorized call, a denied call and invalid input. GitHub Actions runs lint and tests on Python 3.11 and 3.13.

## Design trade-offs

- **Small surface:** three tools, no destructive operations.
- **Deny by default:** unrecognized role or action is rejected.
- **Reproducible:** all data is synthetic; no API keys or hosted services.
- **Explicit limitation:** caller-controlled roles demonstrate policy logic but are **not authentication**. A production system must bind identity to trusted transport/session credentials, enforce server-side authorization, apply resource isolation, rate limiting, logging and adversarial tests.
- **No relationship to private source:** this repository contains no code or configuration copied from Zayuni DevWS.

## Português

Servidor MCP funcional em Python, independente e com dados fictícios. Demonstra descoberta de ferramentas, consultas permitidas, bloqueio por política e testes de integração com cliente MCP real.

Para instalar: `python -m pip install -e ".[dev]"`. Para validar: `pytest -q` e `ruff check .`. Para iniciar via stdio: `mcp-secure-gateway`.

**Limitação importante:** o papel (`role`) é informado pelo cliente, portanto **não autentica usuários**. O exemplo demonstra uma política de autorização, não uma barreira de segurança pronta para produção. Nenhum dado, segredo ou código privado do Zayuni/DevWS foi incorporado.
