# CLAUDE.md — Project Context & OWASP AI Security Guardrails

## Project Overview
This repository houses **Mellyn Security**, an AI Security Engineering Reference Architecture and B2B SMB Security Platform.

- **Implemented today**: the secure AI-assisted coding layer — agent rules files, the dependency / anti-slopsquatting
  verifier, custom Semgrep rules, Gitleaks config, pre-commit hooks, and the CI security gate — and `backend/aegis_ai/`
  (Python 3.12+, FastAPI, Pydantic v2): the tool-call authorizer, HTTP API, stdio MCP gateway, and `deploy/` stack.
- **Planned (not yet in the repo)**: `frontend/` (TypeScript, Next.js App Router, Tailwind CSS, Zod).

## Essential Commands
On Windows, use `py` instead of `python` if `python` opens the Microsoft Store.

- **Verify dependencies (anti-slopsquatting)**: `python scripts/verify_dependencies.py --online`
- **Run tests**: `python -m unittest discover -s tests` (or `pytest`)
- **Check agent rules are in sync**: `python scripts/sync_agent_rules.py --check`
- **Static analysis**: `semgrep scan --config .semgrep/owasp-ai-code-rules.yaml --exclude .semgrep --error`
- **Test the Semgrep rules**: `cd .semgrep && semgrep --test .` (must run inside the directory)
- **Secrets scan**: `gitleaks git --config .gitleaks.toml`
- **All hooks**: `pre-commit run --all-files`

## Mandatory Security Rules
The full ruleset lives in one canonical file shared by every coding assistant in this repo. Edit that file only, then
run `python scripts/sync_agent_rules.py` to regenerate `.cursorrules` and `.github/copilot-instructions.md`.

@.agent/rules/owasp-secure-ai-coding.md
