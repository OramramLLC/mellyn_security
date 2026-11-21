# AegisAI — AI Security Engineering Architecture & B2B Guardrail Platform

An **OWASP-aligned AI Security Engineering Reference Architecture** and **B2B Security Platform** designed to secure AI-assisted coding workflows and runtime LLM/Agentic applications for small and medium businesses (SMBs).

---

## Status

| Layer | State |
| :--- | :--- |
| 1–3. Secure AI-assisted coding (agent rules, pre-commit, CI gate) | **Implemented** |
| 4. Runtime AI & agent security engine (`backend/`) | Planned |
| 5. B2B posture dashboard (`frontend/`) | Planned |

## Core Capabilities

1. **OWASP Secure Coding with AI Guardrails (IDE & Agent Layer)**
   - One canonical ruleset ([`scripts/sync_agent_rules.py`](scripts/sync_agent_rules.py) keeps every agent's file in sync and rejects hidden Unicode):
     - [`.agent/rules/owasp-secure-ai-coding.md`](.agent/rules/owasp-secure-ai-coding.md)
     - [`CLAUDE.md`](CLAUDE.md)
     - [`.cursorrules`](.cursorrules)
     - [`.github/copilot-instructions.md`](.github/copilot-instructions.md)
2. **Deterministic Pre-Commit & CI/CD Security Gateways**
   - **Anti-Slopsquatting & Dependency Verification**: [`scripts/verify_dependencies.py`](scripts/verify_dependencies.py) prevents hallucinated packages and unpinned dependencies.
   - **AI-Targeted Static Analysis (SAST)**: [`.semgrep/owasp-ai-code-rules.yaml`](.semgrep/owasp-ai-code-rules.yaml) blocks unsafe `eval`/`exec`, `shell=True`, insecure deserialization, weak crypto defaults, and XSS sinks.
   - **AI & Cloud Secret Scanning**: [`.gitleaks.toml`](.gitleaks.toml) detects OpenAI, Anthropic, Gemini, HuggingFace, LangSmith, and cloud keys before commit.
3. **Runtime AI & Agent Security Engine (`backend/` — Python / FastAPI)** — *planned*
   - Direct & Indirect Prompt Injection Detection (`OWASP LLM01`)
   - Sensitive Information & Secret Egress DLP Redactor (`OWASP LLM02`)
   - Agent & MCP Tool Execution Policy Engine with SSRF Prevention (`OWASP LLM06` / `Agentic Top 10`)
4. **B2B Posture & Compliance Dashboard (`frontend/` — TypeScript / Next.js)** — *planned*
   - Real-time policy testing, audit logs, and compliance mapping for SMBs.

---

## Documentation

- [**OWASP AI-Assisted & Agentic Coding Security Synthesis**](docs/OWASP_AI_CODING_SECURITY.md)
- [**System & B2B Reference Architecture**](docs/ARCHITECTURE.md)

---

## Quick Verification

Run the built-in OWASP AI Dependency & Anti-Slopsquatting Verifier:

```bash
python scripts/verify_dependencies.py --online   # existence, package age, pinning, non-registry sources
python scripts/sync_agent_rules.py --check        # agent rules in sync, no hidden characters
python -m unittest discover -s tests              # tests
pre-commit install && pre-commit run --all-files  # all local gates
```
