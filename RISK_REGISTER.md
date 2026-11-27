# Mellyn Security: Agent Authority Statement & AI Risk Register

**Document ID:** `GRC-AUTH-2026-001`\
**System Scope:** AI Agent + `mellyn proxy` / `mellyn-airlock` Runtime (`config/mellyn.example.toml` `schema_version = 2`, `config/mellyn-policy.example.toml` `schema_version = 1`, `src/mellyn/authorizer.py`, `src/mellyn/policy.py`, `src/mellyn/airlock/engine.py`, `mellyn pin` / `mellyn-pin`, AAD Kill Switch)\
**System Owner / Risk Owner:** Project maintainer (OramramLLC). In this single-maintainer project every owner role below is held by the same person (see `RSK-08`). An adopting organization should replace each role with a named individual.\
**Last Reviewed:** 2026-11-27 (after [IR-DRILL-2026-001](INCIDENT_DRILL_001.md)) | **Next Review:** 2027-02-27\
**Review Cadence:** Quarterly, after any SEV-1 to SEV-3 incident, or on any `mellyn.toml` / `mellyn-policy.toml` / MCP tool-schema change\
**Mapped Controls:** NIST AI RMF (`GOVERN 1.3`, `MAP 3.5`, `MAP 5.1`, `MANAGE 1.2`, `MANAGE 1.3`, `MANAGE 1.4`) | ISO/IEC 42001 (clauses `6.1.2`, `6.1.3`; `A.6.2.5`, `A.9.2`) | SOC 2 (`CC3.2`, `CC6.1`, `CC6.3`, `CC6.6`, `CC8.1`) | ISO/IEC 27001:2022 (`A.5.15`, `A.8.2`, `A.8.12`, `A.8.32`)

> **In plain terms:** An AI agent connected to tools can be tricked by text it reads into doing things its user never asked for. This register lists the eight ways that matters most for Mellyn. For each one, it scores how likely and how harmful the risk is before and after Mellyn's controls, says what is done about it, and names who accepts what is left over. Section 1 states what the agent may do on its own and what needs a human.

---

## 1. Agent Authority Statement
This statement defines the deterministic boundaries of what the AI agent is authorized to execute unattended versus where execution is gated or prohibited, enforced at runtime by `Authorizer` (`src/mellyn/authorizer.py`) and `Airlock` (`src/mellyn/airlock/engine.py`) via strict TOML policy files (`config/mellyn-policy.example.toml`, `config/mellyn.example.toml`, `examples/airlock_demo/reviewed_policy.toml`).

| Policy Tier | Authority Level | Permitted Actions | Oversight & Logging |
| :--- | :--- | :--- | :--- |
| **Tier 1 (`[tool_risk_tiers] = "low"`)** | **Autonomous (`ALLOW`)** | Bounded, low-impact tool calls within pinned schemas and declared `ToolCapability` guards (e.g., `"local-workspace/workspace_read"`, `"local-workspace/resources/read"`, `"github-readonly/get_issue"`, and read-only `mcp-filesystem` / `github` preset tools; or `allowed_tools` in Airlock). | `WorkspacePathGuard` / `pure = true` boundary checks; redacted `schema_version = 2` hash-chained JSONL (`mellyn-audit.jsonl`). |
| **Tier 2 (`[tool_risk_tiers] = "medium"`)** | **Autonomous when Clean / Gated when Tainted (`ALLOW` → `REQUIRE_APPROVAL`)** | Bounded workspace writes or allowlisted read-only network/SQL calls (e.g., `"local-workspace/workspace_write"`, `http_get`, `postgres/query`, `mcp-fetch/fetch`) inside `WorkspacePathGuard` and `allowed_egress_domains`. | Full payload egress/canary scan (`mellyn.core.scan`) + SHA-256 `args_sha256` / `artifact_sha256` in JSONL; escalates automatically to human approval once the session is tainted. |
| **Tier 3 (`[tool_risk_tiers] = "high"` — *fail-closed default for unlisted tools*)** | **Human-in-the-Loop Gated (`REQUIRE_APPROVAL`)** | State-mutating operations, shell execution (`"local-workspace/shell_exec"` with validated `argv`), outbound mutations (`http_post`, `send_email`, `git_push`), and any unlisted `<server>/<tool>`. | Execution held pending a single-use, exact-call `ApprovalGrant` (`Role.APPROVER` via `mellyn approve` or approval relay), unless matched by an exact-argument `[[scoped_rules]]` `effect = "allow"` (e.g., `allow-unit-tests-when-tainted`). |
| **Tier 4 (Hard Boundaries / `[[scoped_rules]]` `effect = "deny"` / `AAD_FIRE`)** | **Hard-Blocked (`DENY` / `AAD_FIRE`)** | Destructive/network binaries (`deny-destructive-programs`: `rm`, `curl`, `wget`, `nc`, `ncat`), shell interpreters/inline eval flags, `protected_paths` & `GUARDRAIL_PATHS` (including Mellyn's own config/ledger/state DB), unlisted `allowed_mcp_servers` / `allowed_egress_domains`, `deny_on_dlp_secret = true`, `injection_deny_threshold = 0.90`, unpinned/mismatched `agbom_pins` / `tools_sha256`, and `[scanner].aad_kill_on_leak = true` canary triggers. | Deterministically denied regardless of taint or grants; `AAD_FIRE` triggers **AAD Kill Switch** (downstream halt, `-32099` / exit `78` in Airlock, full session sever in Gateway) and writes redacted `AAD_FIRE` record to `mellyn-audit.jsonl`. |

### Dynamic Taint-Escalation Rule (`src/mellyn/authorizer.py` & `src/mellyn/policy.py`)
Authority is **stateful, not static**. When an agent session ingests untrusted external content—such as a tool in `untrusted_content_tools` (`http_get`, `http_fetch`, `web_fetch`, `web_search`) or any MCP server not in `trusted_mcp_servers` (`[[servers]].trusted = false`)—`Authorizer` marks the session as **tainted** (persisted across restarts when `[runtime].state_db = "mellyn-state.sqlite3"` is configured):
*   **Automatic Escalation:** `medium`-tier tools escalate from `ALLOW` to `REQUIRE_APPROVAL`, and `[[scoped_rules]]` with `effect = "allow"` fall back to `REQUIRE_APPROVAL` unless explicitly marked `allow_when_tainted = true` with exact `arg_equals` matches. Supporting signals (`injection_escalate_threshold = 0.70`, `injection_deny_threshold = 0.90`, `deny_on_dlp_secret = true`) can only escalate decisions, never relax them.
*   **Governance Purpose:** Prevents indirect prompt injection (`TM-01`, `TM-11`, `TM-16`) from hijacking the agent's ambient authority to exfiltrate data or mutate state.

---


## 2. Risk Scoring Method
Each risk is scored twice: **inherent** (with no Mellyn controls) and **residual** (with the controls in the register, as verified in [docs/grc/CONTROLS_MATRIX_AND_EVIDENCE.md](docs/grc/CONTROLS_MATRIX_AND_EVIDENCE.md)). **Score = Likelihood × Impact.**

| Score | Likelihood (over 12 months, per deployment) | Impact (worst credible outcome) |
| :---: | :--- | :--- |
| 1 | Rare: needs a novel technique and insider position | Minimal: no data or integrity loss |
| 2 | Unlikely: needs a targeted attacker and specific conditions | Minor: brief workflow disruption, no data loss |
| 3 | Possible: demonstrated by public research or our own red team | Moderate: loss of a control's availability, or limited non-sensitive data |
| 4 | Likely: expected for any agent reading untrusted content | Major: credential or source-code exposure, or unauthorized change to one system |
| 5 | Almost certain: occurs in normal use | Severe: regulated-data breach or unauthorized changes across systems |

**Bands:** 1–4 **Low** (accept; review annually) · 5–9 **Medium** (treat or formally accept; review quarterly) · 10–16 **High** (treat before production use) · 20–25 **Critical** (do not deploy without treatment).

**Rules:**
*   A control may lower **likelihood** when it blocks the attack path.
*   A control may lower **impact** only when it limits blast radius, for example the workspace jail, egress allowlist or AAD halt.
*   Residual ratings must cite evidence. A rating with no test or drill behind it stays at its inherent score.

---

## 3. AI Risk Register

| Risk ID | Risk Scenario | Inherent (L×I) | Mellyn Technical Control & Evidence | Residual (L×I) | Treatment & Acceptance |
| :--- | :--- | :---: | :--- | :---: | :--- |
| **RSK-01** | **Indirect Prompt Injection → Data Egress (`TM-01`, `TM-02`, `TM-11`):** Untrusted input tricks the agent into exfiltrating sensitive data via an MCP tool. | 4×5 = **20 Critical** | Stateful taint escalation (`trusted_mcp_servers`, `untrusted_content_tools`), the `EgressValidator` domain allowlist plus Squid, `mellyn.core.scan` canary/secret detection, and the **AAD Kill Switch**. *Evidence:* `CTL-01`, `CTL-05`, `CTL-08`. | 2×4 = **8 Medium** | **Mitigate.** Accepted by the Maintainer, 2026-11-27. Not Low: detection is a tripwire, not a boundary (`SECURITY.md`), and workstation deployments without Squid only get application-layer URL checks. |
| **RSK-02** | **MCP Tool Schema Drift / "Rug-Pull" (`TM-12`, `AL-01`):** A downstream tool silently alters its schema or embeds hidden Unicode instructions. | 3×4 = **12 High** | Exact-byte SHA-256 pinning (`mellyn pin` / `mellyn-pin`) plus invisible-Unicode rejection (`AAD_FIRE`). *Evidence:* `CTL-03`, Sample D. | 1×4 = **4 Low** | **Mitigate.** Accepted by the Maintainer. Schema updates require a diff review and re-pinning through the [MCP third-party questionnaire](docs/grc/MCP_THIRD_PARTY_RISK_QUESTIONNAIRE.md). |
| **RSK-03** | **Payload Obfuscation / Filter Bypass (`AL-02`):** Encoded, fragmented, or Unicode-obfuscated payloads evade string inspection. | 4×4 = **16 High** | `mellyn.core.normalize` and `mellyn.core.scan`: NFKC and invisible-character stripping; percent, Base64/Base64url (3 offsets), hex, reversed and separator-interleaved matching. *Evidence:* `CTL-08`, `mellyn-bench`, `mellyn-redteam`. | 3×3 = **9 Medium** | **Mitigate + accept the remainder.** Ciphers, compression and splitting across calls are out of scope for matching (`SECURITY.md`). Egress allowlisting (RSK-01) is the backstop. |
| **RSK-04** | **Unauthorized State Mutation / Runaway Execution (`TM-08`, `TM-09`, `TM-10`, `TM-13`):** The agent executes destructive writes, shell escapes, or unbounded or spoofed calls. | 3×5 = **15 High** | `high`-tier `REQUIRE_APPROVAL` with single-use exact-call `ApprovalGrant`s (`Role.APPROVER`), `validate_argv`, `effect = "deny"` rules, the workspace jail, and bounded framing. *Evidence:* `CTL-01`, `CTL-02`, `CTL-04`. | 1×4 = **4 Low** | **Mitigate.** Accepted by the Maintainer. All grants and decisions are recorded in the hash-chained ledger (`CTL-09`). |
| **RSK-05** | **Alert Fatigue / Over-Blocking (`TM-04`):** Over-aggressive rules or taint explosion block legitimate work, so operators bypass the proxy. | 3×3 = **9 Medium** | Risk tiers, taint-safe exact-argument `[[scoped_rules]]`, and `pinned_tool_hashes` (no turn-0 taint). The `mellyn-bench` regression gate requires 0 false positives. | 2×3 = **6 Medium** | **Mitigate (open action).** The 0-false-positive gate rests on only **5 benign samples (Airlock) and 7 (Gateway)**. That catches regressions but does not estimate a real false-positive rate. *Action:* build a benign corpus from real tool traffic before claiming a rate. |
| **RSK-06** | **Unapproved Policy Modification / Guardrail Tampering (`TM-05`):** Unauthorized edits weaken `mellyn.toml` / `mellyn-policy.toml` or prematurely lift an AAD Kill Switch. | 3×4 = **12 High** | *In proxy:* `GUARDRAIL_PATHS`, `protected_paths` and `owned_files` block agent writes to configs, ledgers and the state DB (`CTL-04`). *Outside proxy:* the `Protect main` ruleset (signed commits, PRs only, strict required CI) and pre-commit guardrails (`CTL-10`). | 2×4 = **8 Medium** | **Mitigate + accept.** The ruleset requires a PR but **0 approving reviews**, because there is only one maintainer. A compromised maintainer account could therefore change policy. See RSK-08. |
| **RSK-07** | **Loss of Human-Oversight Availability:** A local process exhausts the approval server's or relay's connection slots, so approvers cannot reach held calls. | 3×4 = **12 High** | `DeadlineRequestHandler` (30 s total deadline) and `BoundedApprovalServer` (32-slot cap) fail closed: no call is approved while the channel is down. *Evidence:* [IR-DRILL-2026-001](INCIDENT_DRILL_001.md), `CTL-06`. | 2×3 = **6 Medium** | **Mitigate + accept the remainder.** An attacker who reconnects every 30 s can still compete for slots (drill §6). *Open actions:* a per-peer limit or a slot reserved for authenticated approvers. |
| **RSK-08** | **Single-Maintainer Segregation-of-Duties Gap (organizational):** The same person writes policy and code, reviews it, and approves high-risk tool calls. | 3×3 = **9 Medium** | *Compensating:* signed commits, strict required CI, mutation-checked regression tests, independent adversarial review by an AI reviewer with written findings, and a public repository. | 3×3 = **9 Medium** | **Accept (documented).** Inherent to a solo project. An adopting organization must assign separate System Owner, Policy Maintainer and Approver roles (see the [Acceptable-Use Policy](docs/grc/AI_AGENT_ACCEPTABLE_USE_POLICY.md)) and require at least one approving review on `main`. |

---

## 4. Residual Risk Acceptance & Change Control
*   **Zero Silent Changes:** Any change to `[tool_risk_tiers]`, `[[scoped_rules]]`, `protected_paths`, taint-escalation triggers, or pinned MCP digests (`tools_sha256` / `agbom_pins`) needs all of the following:
    *   a pull request;
    *   passing `python -m unittest discover -s tests -v` and `mellyn bench --surface both --json`;
    *   `mellyn-redteam` conformance runs;
    *   explicit sign-off from the System Owner.
*   **Acceptance Rule:** Medium residual risks (RSK-01, 03, 05, 06, 07, 08) are accepted for the current single-tenant, maintainer-operated scope only. Each is re-scored at the next quarterly review, or sooner if a related incident occurs. No residual risk is High or Critical.
*   **Change Log:**
    *   **2026-11-27, Maintainer:**
        *   Added the scoring method and recorded each risk's L×I.
        *   Added RSK-07 (from IR-DRILL-2026-001) and RSK-08.
        *   Re-scored RSK-01, RSK-05 and RSK-06 from Low to Medium, because the evidence did not support Low.
