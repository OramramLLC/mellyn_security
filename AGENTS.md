# AGENTS.md — Mellyn Security Architectural Invariants

The repository-wide secure-coding rules live in `.agent/rules/owasp-secure-ai-coding.md` and apply to every change.
This file adds the architectural invariants for the unified `mellyn` package in `src/mellyn/` (including the
strictly layered `core`, `egress`, `airlock`, and `ir_lab` subpackages).

## 1. Dependency DAG (Strict One-Way Imports)
- `mellyn.core` imports NOTHING from `airlock`, `egress`, `ir_lab`, or top-level `mellyn` modules (`core/scan.py` is stdlib-only and houses the shared scanning and redaction core; `core/__init__.py` loads Pydantic submodules lazily).
- `mellyn.egress` imports ONLY from `mellyn.core` (plus stdlib / lazy `pydantic` on scanner access).
- `mellyn.airlock` imports ONLY from `mellyn.core` and `mellyn.egress`.
- `mellyn.ir_lab` imports ONLY from `mellyn.core`.
- Use absolute imports only. Circular imports, relative imports, and cross-package monkeypatching are forbidden.

## 2. Non-Negotiable Security Invariants
1. **Fail-Closed Everywhere:** Any malformed JSON-RPC frame, missing policy pin, unhandled exception, or schema validation failure MUST default to `DENY` (`verdict_allow=False`). Never `try/except: pass` around a security gate.
2. **Strict Wire Typing:** All Pydantic models in `core` and `airlock` MUST set `ConfigDict(extra="forbid", strict=True, frozen=True)`. Never use `Any` on untrusted wire fields (`id`, `method`, `params`, `tool_name`). Reject duplicate JSON object keys.
3. **Stdio Wire Purity:** `airlock/proxy.py` MUST NEVER write logs, tracebacks, or debug prints to `stdout`. `stdout` is exclusively the client-facing JSON-RPC wire. All diagnostics go to `stderr` or `core/audit.py`.
4. **Subprocess Environment Isolation:** Downstream MCP servers spawned via `asyncio.create_subprocess_exec` MUST receive an explicit minimal `env` dict—never inherit ambient `os.environ`.
5. **Redact Before Disk:** `core/audit.py` MUST NEVER write raw unredacted secrets or canary values to JSONL. Compute `artifact_sha256` first, redact the string, then hash-chain and flush.
6. **Check and Hash What Is Forwarded:** AgBOM tool pins, request/response `artifact_sha256`, and payload size caps MUST be computed over the exact bytes forwarded (`exact_json_bytes`: `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` with no normalization). Unicode NFKC normalization and invisible-character stripping may only make a check *stricter* (deny rules, canary and secret matching); they must never make a value pass. Allow-rules reject input that is not already in normal form, and invisible tag/zero-width characters in tool definitions or tool-call arguments are denied. The audit ledger's own hash chain (`sha256_canonical`) covers data Mellyn writes itself and may stay normalized.

## 3. Privileged Artifacts (Anti-Reward-Hacking Rule)
- Once a test file in `tests/` or policy file in `policies/` *(planned)* is locked for a pass, you MAY NOT weaken assertions, delete test cases, or alter pinned SHA-256 digests to make failing tests pass. Fix the implementation in `src/mellyn/`.
