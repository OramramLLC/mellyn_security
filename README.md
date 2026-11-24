# Mellyn Security — AI Security Engineering Architecture & B2B Guardrail Platform

An **OWASP-aligned AI Security Engineering Reference Architecture** and **B2B Security Platform** designed to secure AI-assisted coding workflows and runtime LLM/Agentic applications for small and medium businesses (SMBs).

---

## Status

| Plane | State |
| :--- | :--- |
| 1–2. Secure AI-assisted coding (agent rules, pre-commit, CI gate, CODEOWNERS) | **Implemented & Tested** |
| 3a. MCP Airlock & Red-Team Flight Recorder (`src/mcp_airlock/`) | **Implemented & Tested** (`mellyn-pin`, `mellyn-airlock`, `mellyn-ir`, `mellyn-bench`, AgBOM pinning, AAD kill switch, `--mode observe` harness) |
| 3b. Self-hosted MCP Control Plane (`backend/mellyn/`) | **Core, HTTP API, stdio MCP gateway & container deployment with egress proxy implemented & tested** (stack built and run; see `deploy/README.md`); persistent state planned |
| 4. B2B posture & audit viewer (`frontend/` + `backend/mellyn/viewer_server.py`) | **Implemented & Tested** (loopback fail-closed BFF, Control Assurance matrix, Airlock hash-chain verifier, Control Plane audit stream & live human approvals UI) |

Self-hosted deployment (control-plane authorizer, gateway, Squid egress proxy): [`deploy/README.md`](deploy/README.md).

## Core Capabilities

1. **OWASP Secure Coding with AI Guardrails (IDE & Agent Layer)**
   - One canonical ruleset ([`scripts/sync_agent_rules.py`](scripts/sync_agent_rules.py) keeps every agent's file in sync and rejects hidden Unicode):
     - [`.agent/rules/owasp-secure-ai-coding.md`](.agent/rules/owasp-secure-ai-coding.md)
     - [`CLAUDE.md`](CLAUDE.md)
     - [`.cursorrules`](.cursorrules)
     - [`.github/copilot-instructions.md`](.github/copilot-instructions.md)
   - Claude Code permission boundaries ([`.claude/settings.json`](.claude/settings.json)) and guardrail review enforcement ([`.github/CODEOWNERS`](.github/CODEOWNERS)).
2. **Deterministic Pre-Commit & CI/CD Security Gateways**
   - **Anti-Slopsquatting & Dependency Verification**: [`scripts/verify_dependencies.py`](scripts/verify_dependencies.py) prevents hallucinated packages, unpinned dependencies, and freshly registered packages (<90 days).
   - **AI-Targeted Static Analysis (SAST)**: [`.semgrep/owasp-ai-code-rules.yaml`](.semgrep/owasp-ai-code-rules.yaml) blocks unsafe `eval`/`exec`, `shell=True`, insecure deserialization, weak crypto defaults, and XSS sinks.
   - **AI & Cloud Secret Scanning**: [`.gitleaks.toml`](.gitleaks.toml) detects OpenAI, Anthropic, Gemini, HuggingFace, LangSmith, and cloud keys before commit.
3. **Zero-Dependency Stdio Containment Airlock & Red-Team Flight Recorder (`src/mcp_airlock/` — `pydantic`-only)**
   - **AgBOM Pinning (`mellyn-pin`)**: Quarantined discovery computes exact SHA-256 digests over downstream `tools/list` definitions and flags pre-poisoned invisible Unicode (`pin_cli.py`).
   - **Deterministic Containment Proxy (`mellyn-airlock`)**: Enforces fail-closed JSON-RPC 2.0 wire schemas (`extra="forbid"`, duplicate-key rejection), AgBOM/instructions pins, bounded stdio framing and stdin backpressure, minimal child environment isolation, workspace/resource path containment, and canary/secret scanning (`proxy.py`, `engine.py`, `scanner.py`). On canary leak, spoofed `rpc_id`, or AgBOM rug-pull, triggers an Automatic Activation Device (AAD) kill sequence (`SIGKILL` process group + Linux `PR_SET_PDEATHSIG` / Windows Job Object, exit code `78`) and appends a post-reap confirmation receipt.
   - **Red-Team Harness Telemetry (`--mode observe`)**: Operator CLI flags (`--mode observe`, `--record-redacted-payloads`, `--opaque-policy-errors`) let red-team runs traverse multi-step kill chains with true `BLOCK`/`AAD_FIRE` telemetry recorded in `AuditLedger` while keeping protocol safety bounds active. Observe mode forwards every policy violation and never kills the downstream, so it also requires `allow_observe_mode = true` in the reviewed policy (a launch flag alone is refused), and every session's first ledger record states its mode.
   - **Forensic Reconstruction & Egress Benchmark (`mellyn-ir`, `mellyn-bench`)**: `AuditLedger` computes raw `artifact_sha256`, redacts secrets and encoded/obfuscated canaries before disk flush, and maintains an unbroken SHA-256 hash chain verified by `mellyn-ir` (`reconstruct.py`); `mellyn-bench` validates scanner recall and microsecond/KB latency.
4. **Self-Hosted MCP Control Plane (`backend/mellyn/` — Optional `[gateway]` Extras)**
   - **Authorization-First Core**: Server-issued sessions with automatic cross-server taint tracking, tool risk tiers (fail-closed for unknown tools), exact-match policy rules, and single-use, short-TTL human grants for one exact call (`authorizer.py`, `approvals.py`). Install optional server extras via `pip install ".[gateway]"`.
   - **Multi-Server MCP Gateway** ([`mcp_gateway.py`](backend/mellyn/mcp_gateway.py)): One stdio process fronting all downstream MCP servers (`<server>__<tool>`), holding high-risk/tainted calls for loopback human approval (`python -m mellyn.approve`) with container Squid egress isolation (`deploy/`).
5. **B2B Posture, Forensic Audit & Approval Console (`frontend/` + `backend/mellyn/viewer_server.py`)**
   - **Loopback Fail-Closed BFF (`viewer_server.py`)**: Serves the built SPA on `127.0.0.1:8080` with strict `CSP`/`nosniff`/`DENY` headers and refuses any `Host` header outside its allowlist (`421`, against DNS rebinding). Reads (status, reconstructed Airlock reports, gateway audit logs, OWASP/ATLAS assurance reports) need a separate read-only `Role.VIEWER` key (`MELLYN_VIEWER_KEY_DIGEST`); listing, approving, and rejecting held calls need the `Role.APPROVER` key. Both are checked in constant time via `X-Mellyn-API-Key` (`503` if unconfigured, `403` for the wrong role), and approvals are relayed without following redirects. Binding `0.0.0.0` requires `--allow-non-loopback`; extra hostnames are allowed with `--allow-host`.
   - **Offline + Live Security Console (`frontend/` — React + TypeScript + Vite)**: Works with built-in redacted synthetic demos, client-side local file uploads (verifying `audit.jsonl` SHA-256 hash chains via Web Crypto), or live loopback API connections (the viewer key is kept in memory only; the approver key is entered in the Approvals tab and held only while that tab is open). Uploaded pre-built reports are labelled unverified.

---

## Quickstart: Red-Teaming & Containment Workflow

Install the core Airlock package (installs only `pydantic>=2.10.0`):

```bash
pip install -e .
```

1. **Pin a downstream MCP server manifest (`mellyn-pin`)**:

```bash
mellyn-pin --output policy.toml -- python -m my_mcp_server
# Review policy.toml and fill in allowed_tools, workspace_roots, and canary_tokens
```

2. **Run with fail-closed enforcement (`mellyn-airlock`, default `--mode enforce`)**:

```bash
mellyn-airlock --policy policy.toml --audit-log audit.jsonl --opaque-policy-errors -- python -m my_mcp_server
```

3. **Run a multi-turn red-team evaluation (`--mode observe`) inside an isolated sandbox**. Observe mode forwards policy violations (including canary leaks) instead of blocking them, so use a separate policy with `allow_observe_mode = true`, throwaway canaries, and a sandboxed downstream:

```bash
mellyn-airlock --policy policy.observe.toml --audit-log audit.observe.jsonl \
  --mode observe --record-redacted-payloads -- python -m my_mcp_server
```

`--record-redacted-payloads` stores request and response contents (up to 16 KiB each, secrets and canaries redacted) for allowed traffic too, so tool results such as file contents end up in the audit log.

4. **Verify the ledger & reconstruct the incident timeline (`mellyn-ir`)**:

```bash
mellyn-ir audit.jsonl --json
```

5. **Run the deterministic canary/secret scanner benchmark (`mellyn-bench`)**:

```bash
mellyn-bench --json
```

6. **Build & launch the Plane 4 Posture, Audit & Approval Console**:

```bash
npm --prefix frontend install
npm --prefix frontend run build
# Needs MELLYN_API_KEY_PEPPER, MELLYN_VIEWER_KEY_DIGEST (reads) and MELLYN_APPROVER_KEY_DIGEST (approvals).
PYTHONPATH=backend python -m mellyn.viewer_server \
  --airlock-audit-log audit.jsonl \
  --gateway-audit-log gateway-audit.jsonl \
  --approval-port 8765
```

---

## Documentation

- [**Client Onboarding Guide (Reusable CI Gate & Pre-Commit Pack)**](docs/CLIENT_ONBOARDING.md)
- [**Self-Hosted Deployment Guide (Docker + Egress Proxy)**](deploy/README.md)
- [**OWASP AI-Assisted & Agentic Coding Security Synthesis**](docs/OWASP_AI_CODING_SECURITY.md)
- [**System & B2B Reference Architecture**](docs/ARCHITECTURE.md)
- [**Runtime Gateway Threat Model**](docs/THREAT_MODEL.md)

---

## Quick Verification

Run the built-in OWASP AI Dependency & Anti-Slopsquatting Verifier:

```bash
python scripts/verify_dependencies.py --online   # existence, package age, pinning, non-registry sources
python scripts/sync_agent_rules.py --check        # agent rules in sync, no hidden characters
python -m unittest discover -s tests              # tests
pre-commit install && pre-commit run --all-files  # all local gates
```

The HTTP API tests (`tests/test_api.py`) skip locally unless FastAPI and httpx are installed; CI installs
pinned versions in the test job and sets `MELLYN_REQUIRE_API_TESTS=1`, so there they fail rather than skip.
Locally, install them in a separate virtual environment from Semgrep: current FastAPI releases need a newer
`opentelemetry-api` than Semgrep 1.182 allows.
