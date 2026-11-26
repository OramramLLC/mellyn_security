# CLAUDE.md — Project Context & OWASP AI Security Guardrails

## Project Overview
This repository houses **Mellyn Security**, the core MCP runtime security engine (`src/mellyn/`):

- **MCP Airlock (`src/mellyn/airlock/`, `core/`, `egress/`, `ir_lab/`)**: stdio containment proxy (`mellyn-airlock`), quarantined AgBOM manifest/instructions pinner (`mellyn-pin`), scanner benchmark (`mellyn-bench`), and cryptographic incident reconstructor (`mellyn-ir`).
- **Runtime Authorization Engine & Multi-Server Gateway (`src/mellyn/`)**: server-issued sessions, cross-server taint tracking, capability bindings, exact-arg/`argv` rules, durable SQLite session/grant persistence, Streamable HTTP downstream transport with OAuth 2.1, loopback exact-call approvals, hash-chained audit ledger (`mellyn verify`), and optional Docker + Squid egress stack (`deploy/`).
- **Sibling repositories**: `OramramLLC/mellyn-guardrails` (AI coding rules, SAST/secret configs, supply-chain verifier, pre-commit pack, and reusable CI gate consumed here by commit SHA) and `mellyn-redteam` (adversarial red-team harness and OWASP/ATLAS conformance suite; Plane 4 Console, PR #29, and PR #30 are parked at `archive/v1-monolith-full`).

## Essential Commands
On Windows, use `py` instead of `python` if `python` opens the Microsoft Store.

- **Run unit & regression tests**: `python -m unittest discover -s tests -v` (or `pytest`)
- **Run Ruff lint & format checks**: `ruff check .` and `ruff format --check .`
- **Run all pre-commit & guardrail gates** (via pinned `mellyn-guardrails` hooks: dependency/anti-slopsquatting verification, hidden-Unicode/pack-canonical rules check, Gitleaks, and Semgrep): `pre-commit run --all-files`
- **CI gate**: `.github/workflows/ai-security-gate.yml` runs the pinned `mellyn-guardrails` reusable workflow (`require-pack-rules: true`), baseline Ruff checks, Python 3.12/3.14 tests, and `scripts/verify_container_stack.py`.

## Mandatory Security Rules
The canonical ruleset is maintained in `OramramLLC/mellyn-guardrails`. Keep the local copies (`.agent/rules/owasp-secure-ai-coding.md`, `.cursorrules`, `.github/copilot-instructions.md`) unmodified unless updating from the pinned guardrail pack, verified by `mellyn-check-agent-rules` (`--check --require-pack-canonical`) in pre-commit and CI.

@.agent/rules/owasp-secure-ai-coding.md
