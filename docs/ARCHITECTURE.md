# Mellyn Security Architecture

This document describes the architecture of the **Mellyn Security Core Runtime** (`OramramLLC/mellyn_security`), covering the MCP Airlock proxy, Runtime Authorization Engine, Multi-Server Gateway, Egress Guard, Forensic Flight Recorder, and optional Container/Squid deployment stack.

---

## 1. Architectural Overview

Mellyn mediates every action between an untrusted AI agent client and external tools, servers, or network destinations across four coordinated runtime layers:

1. **MCP Airlock (`src/mellyn/airlock/`):** Fail-closed stdio JSON-RPC proxy enforcing strict Pydantic wire schemas (`extra="forbid"`, `strict=True`, `frozen=True`), duplicate JSON key rejection, exact-byte AgBOM tool-definition and capability pins, Unicode normalization rules (stricter-only for deny/canary checks; non-NFKC or invisible tag/zero-width characters denied in allow/tool contexts), payload caps, and isolated downstream subprocess environments.
2. **Runtime Authorization Engine & Multi-Server Gateway (`src/mellyn/`):**
   - Policy and risk evaluation (`authorizer.py`, `policy.py`, `policy_loader.py`) supporting default-deny capability checks, taint tracking, and human-in-the-loop single-use approvals (`approvals.py`, `approval_relay.py`, `approve.py`, `state_store.py`).
   - Multi-server stdio and HTTP/OAuth 2.1 downstream gateway (`mcp_gateway.py`, `pin_gateway.py`, `gateway_config.py`, `http_downstream.py`, `oauth_client.py`) with pinned tool manifests.
   - CLI (`cli.py`, `init_cmd.py`) and HTTP control API (`api.py`).
3. **Egress Guard & Scanner (`src/mellyn/egress/`, `src/mellyn/scanner.py`):** Inspects outbound arguments, tool outputs, and HTTP egress requests through one shared stdlib scanning core (`mellyn.core.scan`) for high-entropy secrets (Airlock default on; gateway configurable off by default), provider token patterns, and canary tokens (`scanner.py`, `guards.py`), paired with forwarding proxy controls (`egress_proxy.py`) and throughput benchmarking (`bench.py`).
4. **Forensic Flight Recorder (`src/mellyn/core/audit.py`, `src/mellyn/ir_lab/`, `src/mellyn/audit.py`):** Captures `artifact_sha256` digests before redacting sensitive values, writes redacted records through one unified `schema_version = 2` SHA-256 hash-chained JSONL engine (`core/audit.py`) shared by Airlock, Gateway, and Authorizer (with read-only v1 verification and move-aside rotation on upgrade), and supports offline timeline reconstruction (`reconstruct.py`) and ledger verification (`verify_chain.py`, `mellyn verify`) for both Airlock and gateway/authorizer sessions.

---

## 2. Internal Package DAG (`src/mellyn/`)

`src/mellyn/` keeps strict one-way layering for the Airlock subpackages with absolute imports only:

```text
mellyn.core             (imports nothing from airlock, egress, ir_lab, or top-level mellyn)
   ▲          ▲
   │          └──────────────────────────┐
mellyn.egress       (imports core only)  │
   ▲                                     │
   └──────────────┬──────────────────────┤
mellyn.airlock        mellyn.ir_lab
```

- `mellyn.core`: Wire models (`schemas.py`), NFKC & invisible-character helpers (`normalize.py`), shared stdlib secret/canary scanning & redaction core (`scan.py`), and the unified `schema_version = 2` hash-chained JSONL ledger writer & universal verifier (`audit.py`).
- `mellyn.egress`: Destination/workspace confinement guards (`guards.py`, stdlib-only), lazy-loaded Pydantic scanner wrapper (`scanner.py`), and dual-surface scanner benchmark (`bench.py`).
- `mellyn.airlock`: Airlock models (`models.py`), decision engine (`engine.py`), AgBOM pin CLI (`pin_cli.py`), and stdio wire proxy (`proxy.py`).
- `mellyn.ir_lab`: Post-incident JSONL timeline reconstruction across Airlock, gateway, and authorizer ledgers (`reconstruct.py`) and hash-chain verification (`verify_chain.py`).

---

## 3. Trust Boundaries & Deployment Topologies

- **Client ↔ Airlock/Gateway (`stdio` or Gateway):** Untrusted JSON-RPC frames and tool call payloads are validated strictly on ingress; `stdout` stays purely reserved for JSON-RPC wire traffic while diagnostics go to `stderr` or the audit ledger.
- **Airlock/Gateway ↔ Downstream MCP Server:** Local stdio child processes receive minimal explicit environment variables (never ambient `os.environ`). HTTP downstreams validate TLS, SSRF/private-IP restrictions, and OAuth 2.1 tokens (`http_downstream.py`, `oauth_client.py`).
- **Runtime ↔ Disk (`core/audit.py` / `audit.py` / `state_store.py`):** Raw secrets and canary values are digested (`artifact_sha256` / `args_sha256`) and redacted via `mellyn.core.scan` prior to canonical `schema_version = 2` JSONL serialization, zero-canary assertion, `0o600` locked `fsync` writes with symlink refusal and line-break escaping.
- **Containerized Stack (`deploy/docker-compose.yml`):** Optional Docker Compose topology isolates runtime containers on an internal bridge network (`mellyn-internal`), routing allowed outbound HTTP traffic exclusively through the hardened Squid egress proxy (`deploy/egress/squid.conf`) under `--profile gateway` and optional `--profile relay`.

---

## 4. Repository Directory Structure

```text
.
├── .agent/
│   └── rules/
│       └── owasp-secure-ai-coding.md
├── .github/
│   └── workflows/
│       └── ai-security-gate.yml
├── AGENTS.md
├── CHANGELOG.md
├── CLAUDE.md
├── Dockerfile
├── SECURITY.md
├── pyproject.toml
├── README.md
├── config/
│   ├── mellyn.example.toml
│   ├── mellyn-gateway.example.toml
│   ├── mellyn-policy.example.toml
│   └── mellyn-self-policy.toml
├── deploy/
│   ├── README.md
│   ├── docker-compose.yml
│   ├── egress/
│   │   ├── Dockerfile
│   │   └── squid.conf
│   ├── requirements.lock
│   ├── requirements-ci-lint.lock
│   └── requirements-ci-tests.lock
├── docs/
│   ├── ARCHITECTURE.md
│   └── THREAT_MODEL.md
├── examples/
│   └── airlock_demo/
│       ├── README.md
│       ├── reviewed_policy.toml
│       ├── run_demo.py
│       └── sample_mcp_server.py
├── scripts/
│   └── verify_container_stack.py
├── src/
│   └── mellyn/
│       ├── __init__.py
│       ├── api.py
│       ├── approval_relay.py
│       ├── approvals.py
│       ├── approve.py
│       ├── audit.py
│       ├── authorizer.py
│       ├── cli.py
│       ├── credentials.py
│       ├── egress_proxy.py
│       ├── gateway_config.py
│       ├── http_downstream.py
│       ├── init_cmd.py
│       ├── legacy_env.py
│       ├── mcp_gateway.py
│       ├── models.py
│       ├── oauth_client.py
│       ├── pin_gateway.py
│       ├── policy.py
│       ├── policy_loader.py
│       ├── scanner.py
│       ├── state_store.py
│       ├── unified_config.py
│       ├── airlock/
│       │   ├── __init__.py
│       │   ├── engine.py
│       │   ├── models.py
│       │   ├── pin_cli.py
│       │   └── proxy.py
│       ├── core/
│       │   ├── __init__.py
│       │   ├── audit.py
│       │   ├── normalize.py
│       │   ├── scan.py
│       │   └── schemas.py
│       ├── egress/
│       │   ├── __init__.py
│       │   ├── bench.py
│       │   ├── guards.py
│       │   └── scanner.py
│       └── ir_lab/
│           ├── __init__.py
│           ├── reconstruct.py
│           └── verify_chain.py
└── tests/
    ├── e2e/
    │   ├── test_cli_review_fixes.py
    │   ├── test_demo_walkthrough.py
    │   ├── test_full_killchain.py
    │   ├── test_harness_mode.py
    │   ├── test_observe_gating.py
    │   ├── test_proxy_aad.py
    │   └── test_proxy_review_fixes.py
    ├── fixtures/
    │   ├── fake_mcp_server.py
    │   └── hostile_mcp_server.py
    └── unit/
        ├── test_adversarial_hardening.py
        ├── test_airlock_models_and_engine.py
        ├── test_airlock_review_fixes.py
        ├── test_core_audit.py
        ├── test_core_normalize_and_schemas.py
        └── test_egress_scanner.py
```

---

## 5. External Guardrails, Red-Team Harness & Archived Scope

- **Guardrail & CI Pack (`OramramLLC/mellyn-guardrails`):** Supplies Gitleaks, Semgrep, OWASP AI rule parity checks, dependency verification, and reusable CI gate orchestration pinned to an immutable commit SHA in [.pre-commit-config.yaml](../.pre-commit-config.yaml) and [.github/workflows/ai-security-gate.yml](../.github/workflows/ai-security-gate.yml).
- **Red-Team Evaluation (`mellyn-redteam`):** Adversarial harness and conformance reporting live in a sibling repository rather than the runtime package.
- **Parked Monolith Features:** Legacy web viewer and post-runtime enterprise components are documented under Section 7 of [docs/THREAT_MODEL.md](THREAT_MODEL.md) and preserved on `archive/v1-monolith-full`.
