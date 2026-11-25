# Mellyn Airlock — 5-Minute Runnable Demo

This directory ships a harmless, self-contained MCP demo server, a reviewed fail-closed AgBOM policy, and a single-command runner that demonstrates an **allowed** tool call, a **blocked** tool call, and cryptographic hash-chain verification + timeline reconstruction with `mellyn-ir`.

## Contents

- [`sample_mcp_server.py`](sample_mcp_server.py) — Standard-library-only MCP stdio server with zero disk/network side effects and two tools:
  - `read_status_note` (safe in-memory lookup)
  - `export_diagnostics` (sensitive stub tool intentionally blocked by policy)
- [`reviewed_policy.toml`](reviewed_policy.toml) — Reviewed AgBOM policy pinned via `mellyn-pin` (`allowed_tools = ["read_status_note"]`, strict slug regex `^[a-z0-9-]+$` on `note_id`, and `export_diagnostics` set to `allowed = false`).
- [`run_demo.py`](run_demo.py) — End-to-end driver that runs `mellyn-airlock`, executes both calls, verifies `audit.jsonl` via `mellyn-ir`, and prints the reconstructed incident timeline to stdout.

---

## Quickstart (One Command)

```bash
python examples/airlock_demo/run_demo.py
```

Optional flag:

- `--output-dir <path>` — Save `audit.jsonl` and `incident_report.json` in a chosen directory instead of a temporary folder.

---

## What Happens During the Demo

1. **AgBOM Verification (`tools/list`)**: `mellyn-airlock` verifies the SHA-256 digests of `read_status_note` and `export_diagnostics` plus `manifest_sha256` against [`reviewed_policy.toml`](reviewed_policy.toml) before any tool call runs.
2. **Allowed Call (`read_status_note`)**: Calling `read_status_note(note_id="release-readiness")` passes the allowlist and argument regex, forwards to [`sample_mcp_server.py`](sample_mcp_server.py), and returns the status note while recording an `ALLOW` event in `audit.jsonl`.
3. **Blocked Call (`export_diagnostics`)**: Calling `export_diagnostics(destination="https://example.invalid/drop")` is denied fail-closed before reaching the downstream server, returns JSON-RPC `-32000`, and appends a `BLOCK` event to the SHA-256 hash chain.
4. **Forensic Verification (`mellyn-ir`)**: `reconstruct_incident(audit.jsonl)` walks every entry from `seq=0`, confirms `chain_valid=True`, sets `status="BLOCKED_ACTIVITY"`, saves `incident_report.json`, and prints the reconstructed Markdown timeline to stdout.

---

## Equivalent Individual CLI Commands

If you want to run each stage manually using the installed entrypoints:

```bash
# 1. Inspect and generate a starter policy from the sample server
mellyn-pin --policy-id mellyn-5min-demo -o starter_policy.toml -- python examples/airlock_demo/sample_mcp_server.py

# 2. Front the sample server with the reviewed policy
mellyn-airlock --policy examples/airlock_demo/reviewed_policy.toml --audit-log audit.jsonl --session-id demo-session-01 -- python examples/airlock_demo/sample_mcp_server.py

# 3. Verify and reconstruct the tamper-evident ledger
mellyn-ir audit.jsonl
```
