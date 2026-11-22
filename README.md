# Mellyn Security — AI Security Engineering Architecture & B2B Guardrail Platform

An **OWASP-aligned AI Security Engineering Reference Architecture** and **B2B Security Platform** designed to secure AI-assisted coding workflows and runtime LLM/Agentic applications for small and medium businesses (SMBs).

---

## Status

| Plane | State |
| :--- | :--- |
| 1–2. Secure AI-assisted coding (agent rules, pre-commit, CI gate, CODEOWNERS) | **Implemented & Tested** |
| 3. Self-hosted MCP Tool-Call Authorizer (`backend/aegis_ai/`) | **Core, HTTP API, stdio MCP gateway & container deployment with egress proxy implemented & tested** (stack built and run; see `deploy/README.md`); persistent state and tool-description pinning planned |
| 4. B2B posture & audit viewer (`frontend/`) | Planned (built after telemetry matures) |

Self-hosted deployment (authorizer, gateway, Squid egress proxy): [`deploy/README.md`](deploy/README.md).

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
3. **Self-Hosted MCP Tool-Call Authorizer (`backend/aegis_ai/` — Python / FastAPI)**
   - **Authorization-First Core**: Server-issued sessions with automatic taint tracking, tool risk tiers (fail-closed for unknown tools), exact-match policy rules, and single-use, short-TTL human grants for one exact call.
   - **Separate Agent and Approver Credentials**: The agent's key cannot issue approvals; keys are stored as HMAC-SHA256 digests with a server-side pepper.
   - **MCP Gateway** ([`mcp_gateway.py`](backend/aegis_ai/mcp_gateway.py)): one stdio process in front of all of a client's MCP servers, so taint and approvals are shared across them. Tools are namespaced `<server>__<tool>` and tiered per server; listings from untrusted servers taint the session; downstream replies are matched by ID and server-initiated requests are refused. Held calls are approved by a human through a loopback-only approval server with the approver key (`python -m aegis_ai.approve`). Configure it with [`config/mellyn-gateway.example.toml`](config/mellyn-gateway.example.toml) and [`config/mellyn-policy.example.toml`](config/mellyn-policy.example.toml).
   - **Hard Security Boundaries**: MCP server allowlist, workspace path jail (secret files, `.git/`, and guardrail self-modification denied), argv-only shell execution, and SSRF / HTTPS egress allowlist, attached to any server's tools through **capability bindings** (`tool_capabilities`, or presets for the standard filesystem and fetch servers). Reviewed tool listings can be **pinned** by SHA-256 so they stop tainting the session and any later change is refused.
   - **Supporting Risk Signals & Redacted Audit Logs**: Prompt-injection and DLP signals escalate risk only (never grant access); audit logs hash arguments (`SHA-256`) and redact secrets.
4. **B2B Posture & Evidence Viewer (`frontend/` — TypeScript / Next.js)** — *planned*
   - Redacted audit viewer and structured control evidence mapped to OWASP LLM/Agentic Top 10 and NIST AI RMF.

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
pinned versions in the test job and sets `AEGIS_REQUIRE_API_TESTS=1`, so there they fail rather than skip.
Locally, install them in a separate virtual environment from Semgrep: current FastAPI releases need a newer
`opentelemetry-api` than Semgrep 1.182 allows.
