# Mellyn Security: Acceptable-Use Policy (AUP) for AI Agents

**Document ID:** `GRC-AUP-2026-001`\
**Scope:** All developers, operators, human approvers, and maintainers interacting with AI agents connected to MCP tools or workspace resources via Mellyn Security (`mellyn proxy`, `mellyn-airlock`, `mellyn.api`)\
**Policy Owner:** `[Security Engineering Lead / CISO Delegate]`\
**Review Cadence:** Annual, or upon major runtime/policy changes\
**Mapped Controls:** NIST AI RMF 1.0 (`GOVERN 2.1`, `GOVERN 3.2`, `MAP 3.5`) | ISO/IEC 42001 (`A.2.2`, `A.9.2`, `A.9.3`) | SOC 2 (`CC6.1`, `CC6.3`) | ISO/IEC 27001:2022 (`A.5.10`, `A.5.15`, `A.8.2`)

---

## 1. Purpose & Covered Roles
This policy establishes binding rules for safe human-and-agent operation across the Mellyn runtime boundary. Because the AI agent/LLM is assumed prompt-injectable (`docs/THREAT_MODEL.md`), **human operators and approvers are active security controls** and must uphold the boundaries enforced by the proxy.

*   **Operators / Developers:** Engineers invoking AI coding or operational agents mediated by Mellyn.
*   **Human Approvers (`Role.APPROVER`):** Authorized personnel holding the approver credential (`mellyn approve` / approval relay) who review held `REQUIRE_APPROVAL` calls.
*   **Policy Maintainers & System Owners:** Individuals authorized to modify `mellyn.toml` / `mellyn-policy.toml` / `AirlockPolicy` files and approve risk-tier changes via pull request.

---

## 2. Mandatory Runtime Mediation & No-Bypass Rules
1.  **Single Shared Gateway Boundary:** All MCP servers accessible to an agent session MUST be routed through one shared `mellyn proxy` (or `mellyn-airlock` for single-server stdio containment) so session taint propagates across servers (`TM-11`). Users MUST NOT leave direct, unmediated server entries in their client's native MCP configuration.
2.  **Production Enforcement Mode Only:** `--mode observe` (requiring both the CLI flag and `[runtime].allow_observe_mode = true` / `AirlockPolicy.allow_observe_mode = true`) is restricted strictly to isolated red-team or policy-calibration labs. `allow_observe_mode` MUST remain `false` in production and staging deployments handling real credentials or data.
3.  **Container Egress Stack for Sensitive Workloads:** Workloads handling sensitive repositories or regulated data MUST run inside the containerized `deploy/docker-compose.yml` stack so `mellyn-internal` routes outbound traffic exclusively through Squid (`deploy/egress/squid.conf`).

---

## 3. Permitted & Prohibited Actions by Authority Tier

| Tier / Control | Permitted Use | Strictly Prohibited Behavior |
| :--- | :--- | :--- |
| **`low` Tier** | Autonomous read-only workspace/metadata operations bound by `ToolCapability` and pinned schemas. | Naming or re-tiering an arbitrary mutating or recursive search tool as `low` without an explicit capability guard (`PolicyConfig` rejects this fail-closed). |
| **`medium` Tier** | Autonomous workspace writes or allowlisted read-only queries in **clean** sessions; escalated to human review when **tainted**. | Attempting to launder or reset session taint (restarting ephemeral stores, forging session IDs, or splitting sessions across multiple gateways). |
| **`high` Tier (`ApprovalGrant`)** | Executing sensitive operations **only after** a `Role.APPROVER` inspects the exact canonical JSON arguments (`tool_name`, `mcp_server`, `arguments`) and issues a single-use grant. | Rubber-stamping pending approvals without inspecting arguments; reviewing/approving code-execution (`pytest`, `make`, `npm run`) after an untrusted session wrote workspace files without reading the diff (`TM-04`); sharing `Role.APPROVER` keys with any agent runtime or CI bot (`TM-08`). |
| **Hard-Denied / AAD** | Deterministic blocking of `deny-destructive-programs`, `GUARDRAIL_PATHS`, `protected_paths`, `owned_files`, unlisted domains/servers, and `AAD_FIRE` containment. | Disabling `[scanner].block_known_secrets`, `[scanner].aad_kill_on_leak`, `deny_on_dlp_secret`, or `protected_paths`; using `pass_env` to forward `MELLYN_*`, OAuth secrets, or `CODE_INJECTION_ENV_NAMES`; using `--opaque-policy-errors=false` exemptions to extract secret shapes. |

---

## 4. Data Classification, Secrets & Canary Hygiene
1.  **No Raw Secrets in Config or Prompts:** Operators MUST NOT paste raw API keys, passwords, or OAuth `client_secret` / `bearer_token` values into `mellyn.toml`, `mellyn-policy.toml`, or prompts. Remote MCP authentication MUST reference environment variable names (`client_secret_env`, `bearer_token_env`) with token caches stored outside `/workspace`.
2.  **Restricted Data in Untrusted Sessions:** Regulated PII/PHI, production customer secrets, or cryptographic private keys MUST NOT be placed inside workspaces exposed to `trusted = false` MCP servers or `untrusted_content_tools`.
3.  **Canary Token Stewardship:** Planted `[scanner].canary_tokens` / `AirlockPolicy.canary_tokens` MUST be treated as high-sensitivity tripwires—never committed in plaintext to public repositories, shared outside the deployment's secret store, or suppressed after an `AAD_FIRE` event.

---

## 5. Exceptions, Incident Reporting & Enforcement
*   **Time-Boxed Policy Exceptions:** Any request to add a new `[[scoped_rules]]` `allow_when_tainted = true` rule, relax `protected_paths`, or expand `[egress].allowed_domains` requires a pull request detailing business justification, a documented expiry/review date, passing `unittest` and `mellyn bench --surface both --json` checks, and approval from `[Policy Maintainer / Security Lead]`.
*   **Mandatory Escalation (`AAD_FIRE` / Bypass Discovery):** Upon any `AAD_FIRE` termination (`exit 78` / `-32099`), unapproved `mellyn pin` mismatch, or suspected control bypass, operators MUST **not** restart the session or re-enable the tool. Preserve `mellyn-audit.jsonl`, verify its integrity with `mellyn verify` / `mellyn-ir`, and escalate immediately per [INCIDENT_DRILL_001.md](../../INCIDENT_DRILL_001.md) and [SECURITY.md](../../SECURITY.md).
*   **Non-Compliance:** Deliberately bypassing Mellyn runtime mediation, tampering with `mellyn-audit.jsonl` or `mellyn-state.sqlite3`, or sharing `Role.APPROVER` credentials constitutes a security policy violation subject to access revocation and incident investigation.

---

## 6. Operator & Approver Attestation
> *"I have read and understood the Mellyn Security Acceptable-Use Policy for AI Agents (`GRC-AUP-2026-001`). I will route all managed MCP tool use through the approved Mellyn runtime boundary, inspect exact canonical arguments before issuing any `Role.APPROVER` grant, and report any `AAD_FIRE` or schema-drift event before resuming execution."*

| Role | Name | Attestation Date |
| :--- | :--- | :--- |
| **Operator / Developer** | `[Name]` | `[YYYY-MM-DD]` |
| **Designated Human Approver (`Role.APPROVER`)** | `[Name]` | `[YYYY-MM-DD]` |
| **System Owner** | `[Name]` | `[YYYY-MM-DD]` |
