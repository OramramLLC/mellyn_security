# Changelog

All notable changes to **Mellyn Security** are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Hash-chained audit logs.** The authorizer's and gateway's audit logs are now hash-chained JSONL, verified before
  every append. On upgrade, an existing log in the old unchained format is moved aside, unchanged, as
  `<name>.pre-chain-<UTC time>`, and a new chain starts with a `ledger_rotated` record. A log that is partly chained
  or otherwise fails verification still stops the service (fail closed).
- **`mellyn pin --name … --config mellyn.toml`** records a server's tool hash in the unified config. It refuses tool
  definitions containing invisible Unicode, edits only that server's block so comments survive, and writes
  atomically. The gateway also blocks any listing with invisible Unicode, pinned or not.

## [1.0.0] - 2026-11-24

First general release uniting all four security planes for self-hosted MCP tool execution and AI-assisted development.

### Added
- **Plane 1 — Developer & Agent Endpoint Guardrails**:
  - Canonical AI secure coding guidelines in [`.agent/rules/owasp-secure-ai-coding.md`](.agent/rules/owasp-secure-ai-coding.md), synchronized deterministically across `CLAUDE.md`, `.cursorrules`, and `.github/copilot-instructions.md` via `scripts/sync_agent_rules.py` (with hidden-Unicode smuggling detection).
  - Pre-commit configuration (`.pre-commit-config.yaml`) and exportable hook pack (`.pre-commit-hooks.yaml`), Claude Code permission rules (`.claude/settings.json`), and mandatory `CODEOWNERS` governance.
- **Plane 2 — CI/CD & Supply-Chain Security Gate**:
  - Baseline-enforced GitHub Actions security gate (`.github/workflows/ai-security-gate.yml`) and reusable SHA-pinned workflow (`.github/workflows/mellyn-reusable-ai-security-gate.yml`).
  - SHA-256 verified Gitleaks rules (`.gitleaks.toml`), custom OWASP AI Semgrep rules (`.semgrep/owasp-ai-code-rules.yaml`), and fail-closed PyPI/npm package age (90 days), release cooldown (14 days), and lockfile hash verifier (`scripts/verify_dependencies.py`).
  - Automated OWASP/MITRE ATLAS conformance harness (`tests/conformance/`, `scripts/run_conformance_report.py`).
- **Plane 3a — Zero-Dependency Stdio Containment Airlock (`src/mcp_airlock/`)**:
  - Cryptographic AgBOM tool, manifest, and `initialize.instructions` pinning (`mellyn-pin`) with invisible-Unicode pre-poisoning refusal.
  - Fail-closed JSON-RPC 2.0 containment proxy (`mellyn-airlock`) with bounded line/stdin framing, duplicate-key rejection, workspace/resource confinement (including NTFS ADS colon protection), child environment isolation, and AAD process-tree termination (Linux `PR_SET_PDEATHSIG` + process-group `SIGKILL` / Windows Job Object, exit code `78`) with post-reap confirmation receipts.
  - Egress/canary detection (`egress/scanner.py`, `mellyn-bench`) covering raw, casefolded, invisible-Unicode, NFKC, percent-encoded, reversed, separator-interleaved, hex (contiguous, delimited, and `0x`), Base64/Base64url at every offset, `\x`/`\u` escapes, decimal byte lists, one nested encoding layer, and canaries of 16+ characters split across JSON fields in any order. Detection is a tripwire, not a boundary; known gaps are listed in [`examples/adversarial_eval/README.md`](examples/adversarial_eval/README.md#what-this-does-not-cover).
  - Hash-chained, redact-before-disk JSONL flight recorder (`core/audit.py`) and cryptographic timeline verifier (`mellyn-ir`).
  - Quarantined dual-opt-in `--mode observe` red-teaming workflow (`examples/observe_redteam/`), 5-minute interactive demo (`examples/airlock_demo/`), and 28-scenario adversarial scorecard (`examples/adversarial_eval/`).
- **Plane 3b — Self-Hosted MCP Control Plane (`backend/mellyn/`)**:
  - Capability-bound authorization engine (`authorizer.py`, `policy.py`, `egress.py`) enforcing server-issued sessions, automatic cross-server provenance taint tracking, exact-type scoped policy rules, `argv`-only shell validation, secret/guardrail workspace path confinement, and exact-call single-use human grants (`approvals.py`).
  - Fail-closed SQLite persistence (`state_store.py`, `MELLYN_STATE_DB_PATH`) retaining sessions, redacted bounded taint history, and atomic `BEGIN IMMEDIATE` single-use grants across restarts while refusing corrupt, symlinked, or schema-mismatched databases and any trigger, view, or other object it did not create.
  - Multi-server stdio MCP gateway (`mcp_gateway.py`) with `mellyn` (`10001`) / child `mellyn-mcp` (`10002`) privilege separation, loopback approval relay (`approval_relay.py`), FastAPI HTTP adapter (`api.py`), and digest/hash-pinned Docker + policy-synced Squid egress proxy stack (`deploy/`).
- **Plane 4 — Redacted Posture, Forensics & Approvals Console (`frontend/` + `backend/mellyn/viewer_server.py`)**:
  - Hardened container and loopback HTTP BFF (`mellyn-viewer`) separating read-only `Role.VIEWER` evidence endpoints from `Role.APPROVER` pending-call actions, with strict CSP/`DENY`/`nosniff` headers and `Host` allowlist (`421`).
  - React 18 + TypeScript SPA featuring Control Assurance scorecards, browser-side Web Crypto SHA-256 Airlock hash-chain verification, Control Plane taint/audit exploration, and live exact-call approvals.
- **Release & Governance Documentation**:
  - Added [`CHANGELOG.md`](CHANGELOG.md) and [`SECURITY.md`](SECURITY.md); unified runtime package and endpoint versions to `1.0.0`.

### Changed
- **License**: Released under the [Apache License, Version 2.0](LICENSE), with a [`NOTICE`](NOTICE) file. Earlier pre-release snapshots declared `MIT` in `pyproject.toml` only, with no `LICENSE` file.

[1.0.0]: https://github.com/OramramLLC/mellyn_security/releases/tag/v1.0.0
