# Mellyn Security — MCP Airlock & Runtime Authorization

**Mellyn Security** is a fail-closed runtime security runtime for Model Context Protocol (MCP) tool ecosystems. This repository contains the focused **Core Runtime**:

1. **MCP Airlock (`src/mellyn/airlock/`)** — A fail-closed stdio JSON-RPC proxy enforcing strict schema typing, exact-byte AgBOM tool-definition and capability pins, payload size limits, invisible-character rejection, and downstream subprocess environment isolation.
2. **Runtime Authorization Engine & Multi-Server Gateway (`src/mellyn/`)** — Default-deny policy enforcement (`authorizer.py`, `policy.py`, `policy_loader.py`), single-use approval tokens and approval relay (`approvals.py`, `approval_relay.py`, `state_store.py`), multi-server stdio/HTTP-downstream MCP Gateway with OAuth 2.1 support (`mcp_gateway.py`, `pin_gateway.py`, `http_downstream.py`, `oauth_client.py`), and FastAPI service (`api.py`).
3. **Egress Guard & Scanner (`src/mellyn/egress/`, `src/mellyn/scanner.py`)** — Pre-egress secret, token-shape, and canary leakage detection (`scanner.py`, `guards.py`), egress benchmarking (`bench.py`), and domain-filtering forward proxy support.
4. **Forensic Flight Recorder (`src/mellyn/core/audit.py`, `src/mellyn/ir_lab/`, `src/mellyn/audit.py`)** — Redact-before-disk SHA-256 hash-chained JSONL audit logs with `artifact_sha256` digests, timeline reconstruction (`reconstruct.py`), and tamper verification (`verify_chain.py`).
5. **Optional Container & Squid Egress Stack (`deploy/`, `Dockerfile`)** — Hardened Docker Compose deployment with isolated internal networks, Squid egress allowlisting (`deploy/egress/squid.conf`), Gateway profile (`--profile gateway`), and optional Approval Relay profile (`--profile relay`).

---

## Key Security Guarantees

- **Fail-Closed Everywhere:** Malformed JSON-RPC frames, duplicate JSON keys, missing or mismatched AgBOM pins, schema violations, or unhandled errors default to `DENY`.
- **Check and Hash What Is Forwarded:** AgBOM pins, request/response `artifact_sha256` digests, and payload limits operate over exact forwarded JSON bytes (`exact_json_bytes`), while normalization only tightens deny/canary checks.
- **Redact Before Disk:** Secrets and canaries are hashed first (`artifact_sha256`), then redacted before appending to the hash-chained audit ledger.
- **Stdio Wire Purity & Env Isolation:** Airlock diagnostics never touch `stdout`, and downstream MCP servers receive an explicit minimal environment rather than inheriting ambient `os.environ`.

See [AGENTS.md](AGENTS.md), [SECURITY.md](SECURITY.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for architectural invariants and threat-model traceability.

---

## Repository Layout

- `src/mellyn/` — Unified Mellyn Security package combining the MCP Airlock (`airlock/`), core framing/normalization/audit (`core/`), egress guards/scanning/benchmarking (`egress/`), forensic IR verification (`ir_lab/`), and runtime authorizer, policy engine, state store, multi-server gateway, HTTP/OAuth downstream adapters, egress proxy, API server, and `mellyn` CLI.
- `config/` — Example configurations (`mellyn.example.toml`, `mellyn-gateway.example.toml`, `mellyn-policy.example.toml`, `mellyn-self-policy.toml`).
- `deploy/` — Optional container & Squid egress deployment (`docker-compose.yml`, `egress/`, pinned lockfiles `requirements.lock`, `requirements-ci-lint.lock`, `requirements-ci-tests.lock`, and [deploy/README.md](deploy/README.md)).
- `examples/airlock_demo/` — End-to-end Airlock walkthrough (`run_demo.py`, `sample_mcp_server.py`, `reviewed_policy.toml`).
- `scripts/` — Container & egress stack verification (`verify_container_stack.py`).
- `tests/` — Unit, security invariant, HTTP/OAuth, gateway, and end-to-end test suites.

---

## Quick Start

Run the interactive CLI demo walkthrough (prints forensic report to stdout):

```bash
python examples/airlock_demo/run_demo.py
```

Run the test suite and linters using a local virtual environment:

```bash
python -m unittest discover -s tests -v
ruff check .
ruff format --check .
```

Generate local credentials, bring up the optional container stack, or run egress scanning benchmarks via the `mellyn` CLI (`src/mellyn/cli.py`):

```bash
mellyn init
mellyn up --profile gateway
mellyn up --profile relay
mellyn bench
```

See [deploy/README.md](deploy/README.md) for container networking, secret-file configuration, and egress verification (`scripts/verify_container_stack.py`).

---

## Companion Projects & Parked Scope

This repository intentionally isolates the **Core Runtime**:

- **Guardrail & CI Policy Pack:** `OramramLLC/mellyn-guardrails` — Reusable Gitleaks/Semgrep/agent-rule/dependency verification hooks and GitHub Actions workflow, consumed here pinned by immutable commit SHA in [.pre-commit-config.yaml](.pre-commit-config.yaml) and [.github/workflows/ai-security-gate.yml](.github/workflows/ai-security-gate.yml).
- **Red-Team Evaluation Harness:** `mellyn-redteam` — Dedicated adversarial evaluation and conformance suite separated into its own sibling project.
- **Parked Monolith Scope:** The legacy web console, enterprise multi-tenant/distributed features, and full pre-split monolith remain preserved on the `archive/v1-monolith-full` reference (see Section 7 of [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)).
