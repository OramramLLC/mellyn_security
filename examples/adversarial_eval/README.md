# Mellyn Security — 28-Scenario Adversarial Red-Team Evaluation

This suite exercises live attacks across every plane of the Mellyn Security architecture and reports a deterministic pass/fail scorecard. `tests/e2e/test_adversarial_eval.py` runs it on every test run.

Read the score as a regression result: every case is a technique the controls are known to handle. It is not a measure of how well they hold up against techniques nobody has written a case for. See [What this does not cover](#what-this-does-not-cover).

## Quickstart

```bash
python examples/adversarial_eval/run_redteam.py
```

Options:

- `--json` — Emit machine-readable JSON results (`passed`, `failed`, `total`, `cases`).
- `--audit-out <path>` — Save the verified `audit.jsonl` from the real `AirlockProxy` rug-pull containment run so you can inspect it directly in the **Plane 4 Viewer** or verify it with `mellyn-ir`.

---

## Attack Families Covered (28 Cases)

1. **Supply Chain & AgBOM Tampering (4 cases, real `AirlockProxy` subprocesses)**
   - Post-pin tool description rug pull (`AAD_FIRE`, exit `78`, `-32099`, `AAD_CONTAINED`)
   - Unpinned tool injection (`AAD_FIRE`, exit `78`)
   - Invisible Unicode Tag (`U+E0000`) smuggling inside tool definitions (`AAD_FIRE`)
   - Unpinned `initialize.instructions` & extra `tools/list` keys stripped cleanly
2. **Protocol & Framing Attacks (4 cases)**
   - Duplicate JSON object keys rejected fail-closed (`parse_jsonrpc_bytes`)
   - Unsolicited/spoofed JSON-RPC response ID triggers `AAD_FIRE` (`exit=78`)
   - Non-finite JSON `NaN` constant rejected fail-closed
   - Oversized client single-line frame bomb blocked before `json.loads()` (`-32000`)
3. **Workspace & Path Confinement (5 cases, across `mcp_airlock`, `mellyn`, and `engine`)**
   - `../.env` traversal
   - Trailing dot `.env.` obfuscation
   - Windows NTFS Alternate Data Streams (`.env::$DATA`, `secret.key::$DATA`, `.env:stream`)
   - Trailing dot/space writes that would create a protected file on Windows (`.gitleaks.toml.`, `.claude./settings.json`)
4. **Egress & Canary Exfiltration (10 cases)**
   - Plain & ZWSP-interleaved canary tokens
   - Split-list & split-dict canary fragments (`$values`, `$keys`, `$keys+values`)
   - Split fragments interleaved with other data, reordered, or after 128 KiB of padding
   - `\x`/`\u` escapes, decimal byte lists, double Base64, and Base64-of-hex canaries
   - Newline-wrapped & space-chunked Base64 canary payloads
   - Partially percent-encoded hex & Base64 canary payloads
   - `0x`-prefixed hex, reversed hex, reversed Base64, and Base32 canary payloads
   - Percent-encoded & lowercase-hex known API credentials
   - Base64, delimited-hex, `0x`-hex, and `\u`-escaped known API credentials
5. **Forensic Ledger Tampering (2 cases)**
   - Mid-chain 1-byte tamper detected as `INTEGRITY_COMPROMISED` by `mellyn-ir`
   - Zero raw, encoded, chunked, or split canary leakage written to `audit.jsonl`
6. **Plane 4 Viewer BFF Security (3 cases)**
   - DNS-rebinding `Host` header rejected with `421 Misdirected Request`
   - Strict `Role.VIEWER` / `Role.APPROVER` separation (`403`), and four traversal encodings that must not return a real file planted outside the static root (with a positive control proving files are served)
   - Upstream `302` approval relay redirect refused with `502 Bad Gateway`

---

## What this does not cover

Canary and secret detection compare text against known encodings, so it is a tripwire, not a boundary. These
still get through, by design or because no case exists yet:

- **Encodings outside the list:** ROT13 and other ciphers, ascii85, compression, homoglyphs (for example
  Cyrillic letters that look Latin), reversed secrets, and more than one extra layer of nested encoding.
- **Small scattered pieces:** a canary of 16+ characters is found when cut into pieces of at least 5 characters
  (7 for an all-hex canary) in any order, anywhere in one payload. Smaller pieces mixed in with other data are not.
  Canaries shorter than 16 characters are only found split when their pieces sit next to each other.
- **Splits across calls:** pieces sent in separate requests or responses are never joined.
- **Predictable canaries:** the split check assumes a random canary. A canary made of common words can be
  assembled from unrelated text, so generate canaries with `secrets.token_urlsafe(16)` or similar.

Keeping data in is the job of network egress isolation (the Squid egress proxy in `deploy/`) and least-privilege
tool policies. Canaries tell you an exfiltration attempt happened; they do not stop every one.
