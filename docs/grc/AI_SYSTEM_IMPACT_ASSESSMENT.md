# Mellyn Security: AI System Impact Assessment (AIIA)

**Document ID:** `GRC-AIIA-2026-001`\
**System Under Assessment:** Mellyn Security Core Runtime (`mellyn proxy`, `mellyn-airlock`, `Authorizer`, `mellyn-pin` / `mellyn pin`, `mellyn.core.scan`, `mellyn.core.audit`, optional `deploy/` Squid stack)\
**Assessment Owner:** `[Name / Role — e.g., Security Engineering Lead]`\
**Review Cadence:** Annual, and prior to any material change in deployment topology, downstream MCP server trust tier, or `mellyn.toml` / `mellyn-policy.toml` authority boundaries\
**Mapped Controls:** NIST AI RMF 1.0 (`MAP 1.1`, `MAP 1.5`, `MAP 3.5`, `MAP 5.1`, `MANAGE 1.4`) | ISO/IEC 42001 (`A.5.2`, `A.5.3`, `A.5.4`, `A.5.5`) & ISO/IEC 42005 | SOC 2 (`CC3.2`, `CC6.1`, `CC6.6`) | ISO/IEC 27001:2022 (`A.5.15`, `A.8.12`, `A.8.20`)

---

## 1. System Profile & Intended Use
Mellyn Security is a deterministic, fail-closed runtime authorization and containment layer mediating tool calls, resource reads, and outbound network egress between an untrusted AI agent/LLM loop and external Model Context Protocol (MCP) servers.

*   **Deployment Topologies (`docs/THREAT_MODEL.md` §1–2):**
    1.  **Single-Tenant Container Stack (`deploy/docker-compose.yml`):** `mellyn-gateway` and downstream MCP servers isolated on an internal bridge network (`mellyn-internal`), with all outbound HTTPS routed exclusively through the hardened Squid egress proxy (`deploy/egress/squid.conf`, `CONNECT :443`), plus optional `--profile relay` for human approval routing.
    2.  **Local Developer Workstation (`mellyn proxy` / `mellyn-airlock`):** Stdio JSON-RPC mediation on a developer workstation with application-layer path/URL confinement and subprocess environment isolation.
    3.  **HTTP Authorizer API (`src/mellyn/api.py`):** Custom agent harnesses submitting tool-call requests under a strict two-role credential split (`Role.AGENT` vs. `Role.APPROVER`).
*   **Core Security Assumption:** The connected LLM and agent loop reside **inside the blast radius of indirect prompt injection** (`OWASP LLM01`). Mellyn does not rely on model alignment or prompt compliance; it enforces hard boundaries deterministically outside the model.
*   **Explicit Out-of-Scope / Non-Intended Uses (`SECURITY.md`, `docs/THREAT_MODEL.md` §5):**
    *   Not a multi-tenant SaaS prompt-storage platform (deployed single-tenant per VPC or workstation so customers retain zero third-party prompt custody).
    *   Not a replacement for OS kernel sandboxing (cgroups/containers remain complementary Layer-1 infrastructure controls).
    *   Not a 100% probabilistic prompt-injection classifier (`injection_escalate_threshold = 0.70` and `injection_deny_threshold = 0.90` act strictly as escalate-only signals, never allow gates).

---

## 2. Data Flows, Privacy & Custody Boundaries

| Data Element | Flow & Storage Path | Protection & Redaction Rule | Retention / Custody Boundary |
| :--- | :--- | :--- | :--- |
| **Tool-Call Arguments & Tool Responses** | Agent ↔ `mellyn proxy` / `mellyn-airlock` ↔ Downstream MCP Server (`stdio` or `streamable-http`) | Scanned in memory by `mellyn.core.scan`; exact forwarded bytes digested (`artifact_sha256` / `args_sha256`); raw payloads, secrets, and canaries **never** written plaintext to `mellyn-audit.jsonl`. | Zero multi-tenant SaaS storage; customer-controlled local/container retention. |
| **Audit Telemetry (`mellyn-audit.jsonl`)** | `src/mellyn/core/audit.py` (`schema_version = 2` SHA-256 hash-chained JSONL) | Digests computed before redaction; zero-canary pre-flush check; `0o600` locked `fsync` writes; symlink refusal (`O_NOFOLLOW`); unrecognized caller IDs hashed (`unknown_ses:`, `untrusted_srv:`, `untrusted_tool:`). | Customer-controlled retention; tamper-verified via `mellyn verify` / `mellyn-ir` with optional external `(seq, entry_hash)` anchors. |
| **Session State & Human Grants (`mellyn-state.sqlite3`)** | `src/mellyn/state_store.py` (`SqliteStateStore`) | Created `0o600` inside `0o700` directory; verifies SQLite schema objects on open (refuses planted triggers/views). **Documented Exception (`SECURITY.md`):** Live `ApprovalGrant`s retain exact approved arguments and `approved_by` unredacted so exact-call verification works. | Single-use grants deleted upon consumption or expiry (`max 24 h`, default `15 min`). |
| **API & OAuth 2.1 Credentials** | `src/mellyn/credentials.py`, `src/mellyn/oauth_client.py` | Agent/Approver/Viewer keys stored solely as `HMAC-SHA256(pepper, key)` digests; OAuth `client_secret_env` / `bearer_token_env` and `MELLYN_*` stripped from child MCP environments; OAuth `token_cache_path` kept outside `/workspace` (one per server). | Never written to audit logs or exposed to downstream MCP servers. |

---

## 3. Stakeholder & Harm Impact Analysis

| Affected Stakeholder | Potential Adverse Impact (Without / With Failure) | Severity | Likelihood (With Mellyn) | Enforced Technical Mitigations |
| :--- | :--- | :--- | :--- | :--- |
| **Enterprise / Data Owners** | Exfiltration of source code, API credentials, or PII via indirect prompt injection or rogue MCP server (`TM-01`, `TM-02`, `TM-03`). | **High / Critical** | **Low** | `WorkspacePathGuard` (`GUARDRAIL_PATHS`, `protected_paths`), `EgressValidator` + Squid (`deploy/egress/squid.conf`), stateful taint escalation, `mellyn.core.scan` + **AAD Kill Switch** (`[scanner].aad_kill_on_leak = true`). |
| **Engineering & Operations Teams** | Unauthorized state mutation, destructive shell execution, or repository guardrail tampering (`TM-05`, `TM-10`). | **High** | **Low** | `[tool_risk_tiers]` (`high` default for unlisted tools), `validate_argv` (no shell interpreters/inline eval), `[[scoped_rules]]` `effect = "deny"` (`deny-destructive-programs`), `owned_files` self-protection, single-use `ApprovalGrant`s. |
| **Downstream Service / API Tenants** | Runaway loops, SSRF against internal/cloud metadata (`169.254.169.254`), or OAuth token misuse (`TM-02`, `TM-13`). | **High** | **Low** | `gateway_egress_domains` separation, HTTPS-only no-redirect OAuth 2.1 pinning, `max_sessions` refusal (no eviction), bounded framing (`65,536` B read-ahead), RFC 9110 `Content-Length` & `MAX_JSON_DEPTH = 128` limits. |
| **Operators & Approvers** | Approval fatigue ("taint explosion") causing rubber-stamping of dangerous calls (`TM-04`), or workflow disruption from false positives. | **Medium** | **Low** | `pinned_tool_hashes` / `tools_sha256` preventing turn-0 taint on reviewed listings; exact-arg `[[scoped_rules]]` (`allow_when_tainted = true`); `mellyn-bench` 0-false-positive regression gate (5 Airlock / 7 Gateway benign samples; a regression check, not a measured rate; see `RSK-05`). |

---

## 4. Autonomy, Taint & Human-Oversight Impact
Mellyn prevents silent privilege escalation across autonomous workflows through three coupled mechanisms:
1. **Explicit Authority Tiers (`[tool_risk_tiers]`):** Only capability-bound `low` tools execute autonomously regardless of taint; `medium` tools run autonomously only while the session is clean and automatically require human approval once tainted; `high` tools (and all unlisted `<server>/<tool>` names) fail closed to `REQUIRE_APPROVAL` unless matched by an exact-argument `[[scoped_rules]]` rule.
2. **Cryptographic Role Separation (`Role.AGENT` vs. `Role.APPROVER`):** An agent or harness holding the agent credential can create sessions and request decisions, never mint grants (`approvals.py`, `api.py` returns `503` if digests match).
3. **Deterministic Disengagement (`AAD_FIRE`):** On canary detection, AgBOM tool-definition drift, or invisible-Unicode smuggling, Airlock `fsync`s telemetry, kills the downstream process tree, logs `airlock.aad_containment_confirmed`, emits JSON-RPC `-32099`, and exits `78` without relying on LLM cooperation.

---

## 5. Documented Residual Risks & Compensating Organizational Controls
Per `SECURITY.md` and `docs/THREAT_MODEL.md` (§4), the following accepted technical boundaries require organizational compensating controls:

*   **Workstation Deployments Without Squid:** Local developer runs receive application-layer URL/domain validation only (no kernel network namespace or post-DNS private-IP rejection). *Compensating Control:* Mandate the `deploy/docker-compose.yml` Squid stack for sensitive repositories or production-adjacent data.
*   **Downstream Check-Then-Use File TOCTOU:** Paths are validated before a separate downstream MCP tool opens them. *Compensating Control:* Run untrusted servers in isolated containers/sandboxes with least-privilege filesystem mounts (`MELLYN_REQUIRE_WORKSPACE_MOUNT=1`).
*   **Approved Test/Build Execution:** Taint-safe rules permitting `pytest` or approved `HIGH`-risk commands (`make`, `npm run`) execute workspace code. *Compensating Control:* Approvers must review workspace writes before authorizing execution ([docs/grc/AI_AGENT_ACCEPTABLE_USE_POLICY.md](AI_AGENT_ACCEPTABLE_USE_POLICY.md)).
*   **Detection Is a Tripwire, Not a Boundary (`SECURITY.md`):** Canary/secret matching covers known encodings; ciphers, compression, arbitrary non-NFKC homoglyphs, and cross-call splitting remain out of scope for tripwire matching. *Compensating Control:* Enforce least-privilege tool tiers, network egress allowlists, and ongoing adversarial evaluation in `mellyn-redteam`.
*   **Self-Declared `approved_by` Label:** Possession of the `Role.APPROVER` key is cryptographically verified, while the `approved_by` label is self-reported until per-user SSO is integrated. *Compensating Control:* Issue per-approver credentials and restrict host/TTY access to the approval surface.

---

## 6. Impact Determination & Sign-Off

*   **Overall Inherent Risk Rating:** **High / Critical** *(unmediated agent with shell/file/network MCP tools)*
*   **Overall Residual Risk Rating (With Enforced Controls):** **Low–Medium** *(subject to compensating organizational controls in §5)*
*   **Mandatory Re-Assessment Triggers:** Enabling `streamable-http` OAuth servers handling regulated PII/PHI, introducing a new `trusted = true` MCP server, relaxing `protected_paths` or `[egress].allowed_domains`, or any `SEV-1` / `SEV-2` incident ([INCIDENT_DRILL_001.md](../../INCIDENT_DRILL_001.md)).

| Role | Name | Decision (`Approve` / `Conditions` / `Reject`) | Date |
| :--- | :--- | :--- | :--- |
| **System Owner** | `[Name / Role]` | `[Approve / Conditions]` | `[YYYY-MM-DD]` |
| **Security Engineering Lead** | `[Name / Role]` | `[Approve / Conditions]` | `[YYYY-MM-DD]` |
| **Privacy / Compliance Lead** | `[Name / Role]` | `[Approve / Conditions]` | `[YYYY-MM-DD]` |
