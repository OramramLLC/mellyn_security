# Mellyn Security: Controls Matrix, Test Procedures & Evidence Samples

**Document ID:** `GRC-CTL-2026-001`\
**Verified Snapshot:** Commit `2ef9ccd` (`main` — Merge PR #37 `OramramLLC/mellyn_security#37`)\
**Mapped Frameworks:** NIST AI RMF 1.0 | ISO/IEC 42001 | SOC 2 (TSC) | ISO/IEC 27001:2022 | [docs/THREAT_MODEL.md](../THREAT_MODEL.md) (`TM-01`–`TM-16`, `AL-01`–`AL-06`)

*Note: Mellyn enforces technical controls and generates cryptographic/JSONL evidence. Organizational, HR, physical, and vendor-contract controls required for full SOC 2 or ISO/IEC 27001/42001 certification live outside the proxy (see [GOVERNANCE.md](../../GOVERNANCE.md)).*

---

## 1. Controls Matrix & Reproducible Test Procedures

| Control ID & Objective | NIST AI RMF / ISO 42001 | SOC 2 / ISO 27001:2022 | Threat IDs | Implementation (`file:symbol`) | Reproducible Test Procedure | Pass Criteria & Evidence Ref |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CTL-01: Fail-Closed Policy Tiers & Stateful Taint Escalation**<br>Enforce `low`/`medium`/`high` tool tiers, capability bindings, exact `[[scoped_rules]]`, and stateful session taint. | `MAP 3.5`<br>`MANAGE 1.3`<br>—<br>`A.6.2.5`, `A.9.2` | `CC6.1`, `CC6.3`<br>—<br>`A.5.15`, `A.8.2` | `TM-01`<br>`TM-04`<br>`TM-11`<br>`TM-15`<br>`TM-16` | `src/mellyn/authorizer.py:Authorizer`<br>`src/mellyn/policy.py:PolicyEngine`<br>`src/mellyn/policy_loader.py:load_policy_file` | `python -m unittest tests/test_authorizer.py tests/test_pr1_capability_and_taint.py -v` | Unknown sessions/tools fail closed (`DENY`/`high`); untrusted server results taint session across servers; `medium` escalates to `REQUIRE_APPROVAL`; unguarded `low`/`medium` policy fails to load. |
| **CTL-02: Single-Use Exact-Call Human Grants & Role Separation**<br>Bind `ApprovalGrant` to session, server, tool, method, expiry, and canonical RFC 8259 JSON args; isolate `Role.APPROVER` from `Role.AGENT`. | `GOVERN 3.2`<br>`MAP 3.5`<br>—<br>`A.6.2.5`, `A.9.2` | `CC6.1`, `CC6.3`<br>—<br>`A.5.3`, `A.5.15`, `A.8.2`, `A.8.3` | `TM-08`<br>`TM-09`<br>`TM-14` | `src/mellyn/authorizer.py:Authorizer.issue_grant`<br>`src/mellyn/credentials.py`<br>`src/mellyn/state_store.py:SqliteStateStore` | `python -m unittest tests/test_credentials.py tests/test_state_store.py tests/test_pr5_trust_boundaries.py -v` | Agent key cannot mint grants; identical digests return `503`; modified args fail grant match; grants persist/consume atomically in `0600` SQLite. |
| **CTL-03: Cryptographic AgBOM / Manifest Pinning & Hidden-Unicode Refusal**<br>Verify exact-byte SHA-256 digests (`agbom_pins`, `manifest_sha256`, `instructions_sha256`, `tools_sha256`, `pinned_tool_hashes`) and reject invisible/non-NFKC smuggling. | `GOVERN 1.6`<br>`MAP 4.2`, `MANAGE 3.1`<br>—<br>`A.4.4`, `A.6.2.6`, `A.10.3` | `CC8.1`, `CC9.2`<br>—<br>`A.5.19`, `A.8.32` | `TM-04`<br>`TM-12`<br>`AL-01` | `src/mellyn/airlock/engine.py:verify_tools_list`<br>`src/mellyn/airlock/pin_cli.py`<br>`src/mellyn/pin_gateway.py` | `python -m unittest tests/test_gateway_pin.py tests/test_gateway_pin_review_fixes.py tests/unit/test_airlock_models_and_engine.py -v` | Missing pins block fail-closed; mismatched tool/manifest/instructions digest or invisible Unicode triggers `AAD_FIRE` / dispatch refusal. *(Sample D; live TPRM: [`TPRM-MCP-2026-001`](evidence/TPRM-MCP-2026-001/TPRM-MCP-2026-001-filesystem.md))* |
| **CTL-04: Workspace Path Jail & Guardrail / Owned-File Self-Protection**<br>Confine file paths/URIs to workspace roots; deny `.git/`, `.env`, `.agent/`, `protected_paths`, subtree moves, and Mellyn's own config/ledger/state DB. | `MANAGE 1.3`<br>—<br>`A.6.2.5`, `A.6.2.6` | `CC6.1`, `CC6.3`<br>—<br>`A.8.2`, `A.8.3`, `A.8.12` | `TM-03`<br>`TM-05`<br>`TM-15` | `src/mellyn/egress/guards.py:WorkspacePathGuard`<br>`config/mellyn-self-policy.toml` | `python -m unittest tests/test_owned_files.py tests/test_core_egress_and_secret_env.py -v` | Traversal (`..`), symlinks, `file://` escapes, secret files, and writes/moves targeting `GUARDRAIL_PATHS` or `owned_files` (`<ledger>.*`, `-wal`) are denied even with grants. |
| **CTL-05: Egress Allowlisting, SSRF Defense & Container Squid ACLs**<br>Enforce HTTPS-only domain allowlists, separate `gateway_egress_domains` from tool egress, block private/IPv6/NAT64/Teredo CIDRs, and route container egress via Squid. | `MANAGE 1.3`<br>—<br>`A.6.2.6` | `CC6.6`, `CC6.7`<br>—<br>`A.8.20`, `A.8.22` | `TM-02`<br>`TM-14` | `src/mellyn/egress/guards.py:EgressValidator`<br>`src/mellyn/egress_proxy.py`<br>`deploy/egress/squid.conf` | `python -m unittest tests/test_deployment_and_egress_proxy.py tests/test_pr7_ci_gate_and_egress_probe.py -v` | Plaintext HTTP, IP literals, userinfo URLs, `3xx` redirects, and unlisted/special-use CIDRs (`64:ff9b::/96`, Teredo, `169.254.169.254`) are blocked. |
| **CTL-06: Strict HTTP/JSON Input & Approval-Channel DoS Hardening (PR #37)**<br>Reject duplicate JSON keys, `NaN`/`Inf`, depth `> 128`, non-ASCII `Content-Length`, `Transfer-Encoding`, and slow-loris trickles across API, relay, and HTTP downstreams. | `MEASURE 2.7`<br>`MANAGE 2.3`<br>—<br>`A.6.2.6` | `CC6.1`, `CC6.6`, `CC8.1`<br>—<br>`A.8.25`, `A.8.28` | `TM-13`<br>`TM-14`<br>`AL-05` | `src/mellyn/core/strict_input.py`<br>`src/mellyn/api.py`<br>`src/mellyn/approvals.py:BoundedApprovalServer`<br>`src/mellyn/http_downstream.py` | `python -m unittest tests/test_pre_audit_hardening.py tests/test_pre_audit_review_fixes.py -v` | Pre-auth body cap (`128 KiB`), exact depth `128`, `10 s` socket timeout / `30 s` request deadline (`DeadlineRequestHandler`), and strict bool-ID rejection verified. *(Sample B)* |
| **CTL-07: Downstream Subprocess Env Isolation & OAuth Secret Withholding**<br>Spawn MCP children with minimal allowlist (`DEFAULT_DOWNSTREAM_ENV_ALLOWLIST` + validated `pass_env`); strip `MELLYN_*`, OAuth secrets, and 24 `CODE_INJECTION_ENV_NAMES`. | `MANAGE 1.3`<br>`MANAGE 2.3`<br>—<br>`A.6.2.6` | `CC6.1`, `CC6.7`<br>—<br>`A.8.3`, `A.8.12`, `A.8.28` | `TM-07`<br>`TM-10` | `src/mellyn/mcp_gateway.py:downstream_environment`<br>`src/mellyn/airlock/proxy.py`<br>`src/mellyn/unified_config.py` | `python -m unittest tests/test_pre_audit_hardening.py tests/test_pre_audit_review_fixes.py tests/test_http_downstream_and_oauth.py -v` | `LD_PRELOAD`, `PYTHONPATH`, `NODE_OPTIONS`, `MELLYN_*`, and OAuth secret env vars are refused in `pass_env` and withheld at spawn. *(Sample B)* |
| **CTL-08: Canary/Secret Scanning & AAD Kill Switch**<br>Scan exact/decoded/obfuscated payloads via `mellyn.core.scan`; fire `AAD_FIRE`, `fsync` telemetry, kill downstream process tree, log confirmation, emit `-32099`, exit `78`. | `MEASURE 2.4`<br>`MANAGE 2.4`, `4.1`<br>—<br>`A.6.2.6`, `A.8.4` | `CC6.7`, `CC7.2`, `CC7.3`, `CC7.4`<br>—<br>`A.5.24`, `A.5.26`, `A.8.12`, `A.8.16` | `AL-02`<br>`AL-03` | `src/mellyn/core/scan.py`<br>`src/mellyn/egress/scanner.py`<br>`src/mellyn/airlock/proxy.py:_trigger_aad` | `python -m mellyn.egress.bench --surface both --json`<br>`python -m unittest tests/e2e/test_proxy_aad.py tests/test_scan_review_fixes.py -v` | `mellyn-bench` passes `26/26` samples (`100%` canary recall, `0` FP, `0` FN; benign samples: `5` Airlock / `7` Gateway); `AAD_FIRE` kills child tree and records `airlock.aad_containment_confirmed`. *(Sample C)* |
| **CTL-09: Redact-Before-Disk `schema_version = 2` Ledger & Forensics**<br>Hash `artifact_sha256` first, redact secrets/canaries, assert zero canary pre-flush, write `0o600` locked `fsync` JSONL, and verify via `mellyn verify` / `mellyn-ir`. | `MEASURE 2.4`<br>`MANAGE 4.1`<br>—<br>`A.6.2.8` | `CC7.2`, `CC7.3`<br>—<br>`A.8.15` | `TM-06`<br>`AL-04` | `src/mellyn/core/audit.py:CoreAuditLedger`<br>`src/mellyn/ir_lab/reconstruct.py`<br>`src/mellyn/ir_lab/verify_chain.py` | `python examples/airlock_demo/run_demo.py`<br>`python -m unittest tests/unit/test_core_audit.py tests/test_ledger_v2.py tests/test_ledger_review_fixes.py -v` | Chain verifies `VALID` (`chain_valid=true`); zero plaintext secrets/canaries on disk; tampered/symlinked ledgers fail closed. *(Sample A)* |
| **CTL-10: Secure SDLC, Threat Traceability & CI Guardrails**<br>Enforce threat-to-test traceability (`TM-01`–`TM-16`), DAG layering, Gitleaks/Semgrep/OWASP parity via pinned `mellyn-guardrails`, and mandatory security review callouts. | `GOVERN 4.3`<br>`MEASURE 2.6`, `2.7`<br>—<br>`A.6.2.4` | `CC3.2`, `CC4.1`, `CC8.1`<br>—<br>`A.8.25`, `A.8.28`, `A.8.29` | `TM-01`–`TM-16` | `.github/workflows/ai-security-gate.yml`<br>`.pre-commit-config.yaml`<br>`tests/test_pr4_traceability_and_identity.py`<br>`tests/test_pre_audit_remediation.py` | `python -m unittest tests/test_pr4_traceability_and_identity.py -v` | All 7 traceability/identity tests pass (`OK`); `git log` captures review fixes and `SECURITY REVIEW:` gates; [`SEC-AUDIT-2026-001`](evidence/SEC-AUDIT-2026-001/PRE_AUDIT_SECURITY_REVIEW.md) (`PRE_AUDIT_SECURITY_REVIEW.md`, `30/30` findings remediated, `0` open). *(Sample B)* |

---

## 2. Evidence Sample A — Redacted `schema_version = 2` Audit Ledger Excerpt & `mellyn-ir` Timeline

Generated directly via `mellyn.core.audit.AuditLedger`, `mellyn.airlock.engine.{verify_tools_list,evaluate_tool_call}`, and `mellyn.ir_lab.reconstruct.reconstruct_incident` against [examples/airlock_demo/reviewed_policy.toml](../../examples/airlock_demo/reviewed_policy.toml) and [examples/airlock_demo/sample_mcp_server.py](../../examples/airlock_demo/sample_mcp_server.py) (`TOOLS`):

### Raw Hash-Chained JSONL Excerpt (`schema_version = 2`)
```json
{"entry_hash":"00bfc725bed866dc23af8027a1b1bdd7bc6fcf82faabf96af1aca519c6f8705a","event":{"action":"session.start","artifact_sha256":"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","event_id":"evt_demo_00","metadata":{"enforcement_mode":"enforce","session_id":"demo-session-01"},"reason":"Airlock session started in enforce mode.","redactions":[],"request_id":null,"rule_id":"airlock.session_started","severity":"INFO","timestamp_utc":"2026-11-27T19:38:00Z","tool_name":null,"verdict_allow":true,"zone":"airlock"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","schema_version":2,"seq":0,"source":"airlock"}
{"entry_hash":"d05b5e7b0c1aad6cb9bda3f84603f2c5e5f175a1bac55e681014ec6b770a0e05","event":{"action":"tools/list","artifact_sha256":"4953dd98bc22d12acb49e47e504f820e03559fdbd9c92fc7fc46f2621bbc3407","event_id":"evt_demo_01","metadata":{"session_id":"demo-session-01","tool_count":2},"reason":"Downstream tool manifest matches pinned AgBOM SHA-256 digests.","redactions":[],"request_id":2,"rule_id":"airlock.agbom_verified","severity":"ALLOW","timestamp_utc":"2026-11-27T19:38:00Z","tool_name":null,"verdict_allow":true,"zone":"airlock"},"prev_hash":"00bfc725bed866dc23af8027a1b1bdd7bc6fcf82faabf96af1aca519c6f8705a","schema_version":2,"seq":1,"source":"airlock"}
{"entry_hash":"4bdba7efd6b944c7132ea7c3baf92b593586468a9f84de76807c24d063e78ab9","event":{"action":"tools/call","artifact_sha256":"6bf93349232b943b9dead25d0856d5b2c7baea217124a6dea108bfade3a6b1f9","event_id":"evt_demo_02","metadata":{"session_id":"demo-session-01"},"reason":"Tool call 'read_status_note' satisfied all airlock and egress checks.","redactions":[],"request_id":3,"rule_id":"airlock.tool_call_allowed","severity":"ALLOW","timestamp_utc":"2026-11-27T19:38:00Z","tool_name":"read_status_note","verdict_allow":true,"zone":"airlock"},"prev_hash":"d05b5e7b0c1aad6cb9bda3f84603f2c5e5f175a1bac55e681014ec6b770a0e05","schema_version":2,"seq":2,"source":"airlock"}
{"entry_hash":"6773e0b3790154556f7502beb6749597ad1ad6f5be0ced52dad4f16d6928703c","event":{"action":"tools/call","artifact_sha256":"cfcf6396def346986b50c7110bc85ad6ffbd64249ecec3b531508c8d01146297","event_id":"evt_demo_03","metadata":{"session_id":"demo-session-01"},"reason":"Tool 'export_diagnostics' is not allowlisted by AirlockPolicy.","redactions":[],"request_id":4,"rule_id":"airlock.tool_not_allowed","severity":"BLOCK","timestamp_utc":"2026-11-27T19:38:00Z","tool_name":"export_diagnostics","verdict_allow":false,"zone":"airlock"},"prev_hash":"4bdba7efd6b944c7132ea7c3baf92b593586468a9f84de76807c24d063e78ab9","schema_version":2,"seq":3,"source":"airlock"}
```

### `mellyn-ir` Verified Reconstruction Output
```markdown
# Mellyn Incident Reconstruction (BLOCKED_ACTIVITY)

- **Chain Integrity**: VALID (`4` entries, tail `seq=3`, `hash=6773e0b3790154556f7502beb6749597ad1ad6f5be0ced52dad4f16d6928703c`)
- **Tail truncation**: NOT checked (no anchor supplied: entries deleted from the end would not be detected)
- **Sessions**: `1`

## Session `demo-session-01` (4 events)
- **Zones Traversed**: airlock
- **Zone Transitions**: none
- **Mode**: enforce
- **BLOCK Precursors**: 1

| Seq | Time (UTC) | Zone | Action | Severity | Reason Code | RPC ID | Tool |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | 2026-11-27T19:38:00Z | airlock | session.start | INFO | SESSION_STARTED | - | - |
| 1 | 2026-11-27T19:38:00Z | airlock | tools/list | ALLOW | AGBOM_VERIFIED | 2 | - |
| 2 | 2026-11-27T19:38:00Z | airlock | tools/call | ALLOW | TOOL_CALL_ALLOWED | 3 | read_status_note |
| 3 | 2026-11-27T19:38:00Z | airlock | tools/call | BLOCK | TOOL_NOT_ALLOWED | 4 | export_diagnostics |
```

*(Note: `seq=1` `artifact_sha256` `4953dd98...` matches `manifest_sha256` in `examples/airlock_demo/reviewed_policy.toml`, and `seq=2`/`seq=3` record SHA-256 digests without persisting raw tool arguments.)*

**Re-verified 2026-11-27:**
*   Saving the four lines above and running `mellyn verify` gives `Chain Integrity: VALID` (exit `0`).
*   Changing one field in `seq=3` (`"verdict_allow":false` → `true`, which turns a logged BLOCK into an apparent allow) gives `INTEGRITY_COMPROMISED`, `First Invalid Seq: 3` (exit `2`).

The tamper test shows that a hidden edit to this evidence would be caught. It does not detect deletion of entries from the end of the ledger unless an external anchor is supplied (see `Tail truncation` above).

---

## 3. Evidence Sample B — PR #37 Change-Control & Security-Review Trail

*   **Pull Request:** `OramramLLC/mellyn_security#37` (`Merge pull request #37 from OramramLLC/pre-audit-hardening`)
*   **Merge Commit:** `2ef9ccd` (parent hardening + review-fix commit: `ef55a89eacfbe3c96c717ab2a5a5ae7ce94f6bd1`, authored `2026-11-27 13:29:40 -0500`)
*   **Change Footprint:** `15` files changed (`+1156 / -51` lines) across:
    *   `src/mellyn/core/strict_input.py` (new stdlib-only parser enforcing RFC 9110 `Content-Length`, `MAX_JSON_DEPTH = 128`, duplicate-key rejection, `NaN`/`Infinity` rejection)
    *   `src/mellyn/api.py`, `src/mellyn/approvals.py`, `src/mellyn/approval_relay.py`, `src/mellyn/http_downstream.py` (`128 KiB` pre-auth body cap, `Transfer-Encoding` rejection, `10 s` socket read timeout, `30 s` `DeadlineRequestHandler`, `32`-slot concurrency cap, exact-type JSON-RPC `id` check)
    *   `src/mellyn/gateway_config.py`, `src/mellyn/unified_config.py`, `src/mellyn/mcp_gateway.py` (`DEFAULT_DOWNSTREAM_ENV_ALLOWLIST`, `pass_env` opt-in, withholding `MELLYN_*`, OAuth secrets, and 24 `CODE_INJECTION_ENV_NAMES`)
    *   `src/mellyn/egress_proxy.py`, `deploy/egress/squid.conf` (IPv4-mapped, NAT64 `64:ff9b::/96` & `64:ff9b:1::/48`, Teredo, and 6to4 CIDR blocks)
    *   `CHANGELOG.md`, `config/mellyn.example.toml`, `tests/test_gateway_pin.py`, `tests/test_pre_audit_hardening.py` (`334` lines), `tests/test_pre_audit_review_fixes.py` (`284` lines)
*   **Explicit Human Security-Review Gate (from commit `ef55a89`):**
    > `SECURITY REVIEW: this changes authentication-adjacent request parsing, the approval (authorization) channel, and downstream tool-execution environments; please review it yourself.`
    > `Tests: test_pre_audit_hardening.py (12) and test_pre_audit_review_fixes.py (16, mutation-checked 9/9).`
*   **Signatures:** GitHub verifies `ef55a89` and the merge `2ef9ccd` as signed (`verification.verified = true`). The `Protect main` ruleset enforces signed commits, PR-only merges, and strict required checks.
*   **Independent CI verification:** all 7 required checks passed on the PR head, [run 46052241195](https://github.com/OramramLLC/mellyn_security/actions/runs/46052241195), 2026-11-27 18:49–18:50 UTC:
    *   Tests on Python 3.12 and 3.14 (Linux);
    *   Container build & Squid egress integration;
    *   Gitleaks (twice);
    *   the Mellyn Guardrails supply-chain & OWASP AI SAST gate;
    *   SAST/lint/agent-rules/dependency verification.

    The `main` push run after the merge also passed: [run 46052597269](https://github.com/OramramLLC/mellyn_security/actions/runs/46052597269).
*   **Local re-run for this matrix (2026-11-27, Windows, Python 3.14 with the CI test lock, commit `2ef9ccd`):**
    *   All 21 test modules cited in §1 ran **250 tests: OK** (5 skipped). The skips are POSIX `0600` checks and symlink creation, which needs Windows privileges; CI covers them on Linux.
    *   The full suite (`python -m unittest discover -s tests`) ran 485 tests: OK.
*   **Incident record:** this change is the subject of [IR-DRILL-2026-001](../../INCIDENT_DRILL_001.md). An adversarial review found approval-channel slot exhaustion inside the change before it was committed. The fix was verified by a pre-patch vs. post-patch replay ([evidence](evidence/IR-DRILL-2026-001/)).

---

## 4. Evidence Sample C — Deterministic Scanner Benchmark (`mellyn-bench`)

Observed output from `.\.venv\Scripts\python.exe -m mellyn.egress.bench --surface both --json` on commit `2ef9ccd`:

```json
{
  "airlock": {
    "canary_detected": 13,
    "canary_recall": 1.0,
    "canary_total": 13,
    "false_negatives": 0,
    "false_positives": 0,
    "iterations": 10,
    "large_payload_us_per_kb": 1138.347,
    "p50_us_per_kb": 1420.373,
    "p99_us_per_kb": 2761.956,
    "passed": true,
    "precision": 1.0,
    "recall": 1.0,
    "surface": "airlock",
    "total_samples": 26,
    "total_scans": 260,
    "true_negatives": 5,
    "true_positives": 21
  },
  "gateway": {
    "canary_detected": 13,
    "canary_recall": 1.0,
    "canary_total": 13,
    "false_negatives": 0,
    "false_positives": 0,
    "iterations": 10,
    "large_payload_us_per_kb": 917.544,
    "p50_us_per_kb": 1172.945,
    "p99_us_per_kb": 11084.8,
    "passed": true,
    "precision": 1.0,
    "recall": 1.0,
    "surface": "gateway",
    "total_samples": 26,
    "total_scans": 260,
    "true_negatives": 7,
    "true_positives": 19
  },
  "passed": true,
  "surface": "both"
}
```

---

## 5. Evidence Sample D — Cryptographic AgBOM Pinning (`examples/airlock_demo/reviewed_policy.toml`)

```toml
policy_id = "mellyn-5min-demo"
allowed_tools = ["read_status_note"]
max_payload_bytes = 65536
workspace_roots = []
manifest_sha256 = "4953dd98bc22d12acb49e47e504f820e03559fdbd9c92fc7fc46f2621bbc3407"

[agbom_pins]
read_status_note = "397a273375dc43c3e70c4049c9471cd63929e16ae592c310a80fe7689780cf14"
export_diagnostics = "61b837c3ae79132a6888ea7654f5bf991303f8ec6b86f43e6498134a6f7a5330"

[tool_rules.read_status_note]
name = "read_status_note"
allowed = true
allowed_arg_names = ["note_id"]
arg_regex_rules = { note_id = "^[a-z0-9-]+$" }

[tool_rules.export_diagnostics]
name = "export_diagnostics"
allowed = false
allowed_arg_names = []
arg_regex_rules = {}
```
