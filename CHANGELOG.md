# Changelog

All notable changes to **Mellyn Security** are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Unified scanning and redaction core (Phase 2, Pass 2B).** Consolidated the Airlock scanner
  (`mellyn.egress.scanner`), gateway scanner (`mellyn.scanner`), and core ledger regexes into one stdlib-only
  module, `mellyn.core.scan`. `CORE_SECRET_PATTERNS` and `KNOWN_SECRET_RULE_PATTERNS` are removed in favor of
  `KNOWN_SECRET_RULES` and `SECRET_REDACTION_PATTERNS`. `mellyn.core.__init__` now imports Pydantic audit/schema
  submodules lazily so stdlib-only callers can import `mellyn.core.scan`, `mellyn.scanner`, and `mellyn.audit`
  without `pydantic`.
  - **Airlock (`mellyn-airlock`) behaviour changes:** now enforces the 64-level nesting cap (`nesting-too-deep`,
    extending `RedactionKind` with `"structure"`), detects `[^A-Za-z0-9]+` skeleton and iterative tuple containers,
    applies double-NFKC normalization in `normalize_str`, and checks every secret rule and canary without early
    `break` short-circuiting.
  - **Gateway (`mellyn proxy`) & ledger redaction changes:** now catches `url-userinfo-password`, checks
    `[^A-Za-z0-9]+` skeletons, runs all 13 secret rules and obfuscated/encoded layers without early `break`,
    uses `blocked-pattern-<n>` rule IDs, and shares `redact_core_secrets` in `mellyn.audit.redact_text` /
    `AuditLogger`. High-entropy detection stays **off** by default for the gateway (`detect_high_entropy = false`)
    and stays **off** for audit ledger redaction; it is configurable under `[scanner]` in `mellyn.toml`
    (`detect_high_entropy`, `entropy_threshold`, `min_entropy_length`).
  - **Breaking for gateway audit-log consumers:** containment reasons now name the rules the shared core uses. A
    split canary is reported as `canary:canary-<n>` (it was `canary:canary-<n>-split`; the finding's field path is
    still `$[split]`), and policy `blocked_patterns` as `blocked_pattern:blocked-pattern-<n>` (was `blocked-<n>`).
    Update any log search or alert that matches the old IDs.
  - **Benchmark (`mellyn-bench`):** adds `--surface airlock|gateway|both` (default `airlock`), and a
    `large_payload_us_per_kb` figure: the worst µs/KB over two ~256 KiB payloads (non-ASCII prose and MIME
    Base64), each scanned once. The accuracy corpus is small, so p50/p99 alone did not show large-payload cost.
  - **Faster invisible-character stripping:** `strip_invisible` (and so every scan of non-ASCII or decoded text)
    uses one compiled character class instead of a per-character check, with exactly the same characters. A
    1 MiB Base64 payload scans in about 1.1 s on the gateway, down from about 2.1 s before this pass; the
    Airlock's 1 MiB scans drop from about 6.5 s to about 1.3 s.
- **Breaking: one `mellyn` package (Phase 2, Pass 2A).** The Airlock package (`src/mcp_airlock/`) and the runtime
  (`backend/mellyn/`) are now one package under `src/mellyn/`. `backend/` and `src/mcp_airlock/` are gone.
  - **Imports:** `mcp_airlock.core`, `.egress`, `.airlock` and `.ir_lab` are now `mellyn.core`, `mellyn.egress`,
    `mellyn.airlock` and `mellyn.ir_lab`; the runtime modules keep their `mellyn.*` names. `import mcp_airlock` and
    `mcp_airlock.__version__` no longer work (use `mellyn version` or
    `importlib.metadata.version("mellyn-security")`). The console scripts keep their names.
  - **One path and URL guard:** the Airlock now uses the authorizer's `WorkspacePathGuard` and `EgressValidator`
    (`mellyn.egress.guards`). The protected paths are unchanged, but non-string paths and URLs are now refused, and
    the refusal messages changed.
  - **Dependencies are unchanged:** the Airlock commands need only `pydantic`, and the gateway and `import mellyn`
    need nothing beyond the standard library (`mellyn.egress` loads the scanner, and so `pydantic`, only on first
    use).
  - **Deployments:** the image now copies `src/` and sets `PYTHONPATH=/app/src`, so it also contains the Airlock
    code. Local checkouts installed with `pip install -e .` must reinstall, because the old editable install points
    at the deleted folders.
- **Hash-chained audit logs.** The authorizer's and gateway's audit logs are now hash-chained JSONL, verified before
  every append. On upgrade, an existing log in the old unchained format is moved aside, unchanged, as
  `<name>.pre-chain-<UTC time>`, and a new chain starts with a `ledger_rotated` record. A log that is partly chained
  or otherwise fails verification still stops the service (fail closed).
- **`mellyn pin --name … --config mellyn.toml`** records a server's tool hash in the unified config. It refuses tool
  definitions containing invisible Unicode, edits only that server's block so comments survive, and writes
  atomically. The gateway also blocks any listing with invisible Unicode, pinned or not.
- **Gateway-only egress hosts.** Remote `streamable-http` server URLs and their OAuth authorization servers and token
  endpoints are no longer added to the tool egress allowlist (`policy.allowed_egress_domains`). The gateway's own
  clients still reach them, and Squid still allows them. A tool that relied on reaching one of these hosts now needs
  it listed in `[egress].allowed_domains`.
- **Breaking: `--profile viewer` is now `--profile relay`.** The approval relay (`mellyn-approval-relay`) runs in the
  `gateway` and `relay` profiles. Compose still accepts `--profile viewer`, but it now starts neither the relay nor a
  console, so update scripts and `mellyn up --profile …` calls.
- **`mellyn init` no longer creates a viewer key.** It writes only the agent and approver digests. `Role.VIEWER` and
  `MELLYN_VIEWER_KEY_DIGEST` still work for integrations that set one themselves.
- **`examples/airlock_demo/run_demo.py`** prints the verified `mellyn-ir` timeline instead of starting the console;
  its `--no-viewer` and `--port` options are gone.
- **Contributors:** the pre-commit secret scan (`mellyn-gitleaks` from `mellyn-guardrails`) uses a locally installed
  `gitleaks` binary and fails the commit if none is found.

### Security
- **Unified scanning & full-rule coverage across Airlock, gateway, and ledgers (Pass 2B).** Airlock now
  blocks payloads nested deeper than 64 levels (`nesting-too-deep`), both scanners run all 13 secret rules
  and all canaries without early short-circuiting, and the gateway + audit redactor (`mellyn.audit.redact_text`)
  now catch `url-userinfo-password`, `[^A-Za-z0-9]+` canary skeletons, and obfuscated/encoded secrets.
- **Hidden-text check covers every invisible format character (Pass 2B).** The gateway's block on `tools/list` and
  `resources/list` entries with hidden text, and `mellyn pin`'s refusal, now use the same check as the Airlock: every
  Unicode `Cf` character, the tag block, variation selectors and blank fillers. Before, 46 of the 170 `Cf`
  characters got through, including the interlinear annotation characters (U+FFF9–U+FFFB), which can hide text.
  This also newly blocks a soft hyphen (U+00AD) in a tool description, so `mellyn pin` may refuse a server it
  accepted before, and a listing that passed before may now be blocked.
- **OAuth secrets stay out of downstream servers.** Variables named by `client_secret_env` and `bearer_token_env` are
  now withheld from the MCP servers the gateway launches, like every `MELLYN_*` variable.

### Removed
Focused `mellyn_security` on the core runtime (MCP Airlock, Runtime Authorization Engine, Forensic Flight Recorder, and optional container/Squid egress stack):
- **Guardrail authoring pack** (`.semgrep/`, `.gitleaks.toml`, `.pre-commit-hooks.yaml`, `.mellyn-allowlist.toml`, `scripts/sync_agent_rules.py`, `scripts/verify_dependencies.py`, `scripts/ci_guardrails.py`, `.github/workflows/mellyn-reusable-ai-security-gate.yml`, `deploy/requirements-ci-scanners.lock`, `docs/OWASP_AI_CODING_SECURITY.md`, `docs/CLIENT_ONBOARDING.md`, and guardrail tests) -> extracted to the standalone `OramramLLC/mellyn-guardrails` repository (consumed here by commit SHA in `.pre-commit-config.yaml` and `.github/workflows/ai-security-gate.yml`, with `deploy/requirements-ci-lint.lock` holding the Ruff lock block).
- **Plane 4 Posture, Audit & Approval Console** (`frontend/`, `backend/mellyn/viewer_server.py`, `deploy/viewer/`, `mellyn-viewer` Compose service and `--profile viewer`, `mellyn viewer` subcommand, viewer credential generation in `mellyn init`, viewer tests) -> parked at tag `archive/v1-monolith-full` alongside PR #29 and PR #30 (`Role.VIEWER` remains in `credentials.py`; `mellyn-approval-relay` moved to `profiles: ["gateway", "relay"]` with `--profile relay`; `examples/airlock_demo/run_demo.py` prints the `mellyn-ir` timeline to stdout).
- **Red-team harness & conformance suite** (`examples/adversarial_eval/`, `examples/observe_redteam/`, `tests/conformance/`, `scripts/run_conformance_report.py`, and their tests) -> split out to the standalone `mellyn-redteam` repository (`mellyn-bench` stays in core until Phase 2 consolidation).

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
