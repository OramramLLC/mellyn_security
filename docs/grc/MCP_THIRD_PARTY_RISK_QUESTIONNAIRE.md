# Mellyn Security: Third-Party Risk Questionnaire (MCP Servers)

**Document ID:** `GRC-TPRM-MCP-2026-001`\
**Applies To:** Every external or third-party Model Context Protocol (MCP) server onboarded to `mellyn proxy` (`[[servers]]` in `mellyn.toml` / `mellyn-gateway.toml`) or `mellyn-airlock`\
**Owner:** `[Security Engineering / TPRM Lead]`\
**Mapped Controls:** NIST AI RMF 1.0 (`GOVERN 6.1`, `GOVERN 6.2`, `MAP 4.1`, `MANAGE 3.1`) | ISO/IEC 42001 (`A.10.2`, `A.10.3`) | SOC 2 (`CC8.1`, `CC9.2`) | ISO/IEC 27001:2022 (`A.5.19`, `A.5.20`, `A.8.32`)

---

## 1. Onboarding & Pinning-as-Evidence Gate
No third-party MCP server may be added to `allowed_mcp_servers` or `[[servers]]` until it completes this questionnaire **and** passes quarantined cryptographic pinning (`mellyn pin` for Gateway `mellyn.toml`, or `mellyn-pin` for standalone `AirlockPolicy`). **The pinned SHA-256 manifest digest and zero-warning Unicode inspection output serve as the binding technical evidence for vendor schema acceptance.**

```text
[1. Intake & Provenance] ─► [2. Quarantined Inspection (mellyn pin / mellyn-pin)]
         │                                       │ (Fail if invisible/non-NFKC Unicode)
         ▼                                       ▼
[3. Capability & Tier Binding] ◄──── [4. Cryptographic Pin Recorded in GitOps TOML]
         │                                       │
         ▼                                       ▼
[5. Approved Production Use] ──────► [6. Any Drift / Rug-Pull -> AAD_FIRE & Re-Review]
```

---

## 2. Questionnaire

### Part A — Server Provenance & Supply Chain
| # | Assessment Question | Required Answer / Evidence | Response |
| :--- | :--- | :--- | :--- |
| **A1** | **Server Name & Vendor/Maintainer:** Exact `[[servers]].name`, package/repo URL, and accountable publisher. | Lowercase `[a-z0-9-]`, verified upstream source. | `[e.g., github-readonly / org/repo]` |
| **A2** | **Pinned Version / Artifact Digest:** Exact tag, PyPI/npm version with lockfile hash, or OCI image digest. | Immutable version/digest (never `latest`). | `[Version + SHA-256 / Commit]` |
| **A3** | **Transport Mode:** `stdio` (local subprocess) or `streamable-http` (remote endpoint). | Matches `[[servers]].transport`. | `[stdio / streamable-http]` |
| **A4** | **Maintenance & Vulnerability Disclosure:** Active security contact and CVE remediation SLA? | Vendor security policy / GitHub Advisory SLA. | `[Link / SLA]` |

### Part B — Tool Surface, Least Privilege & Capability Binding
| # | Assessment Question | Required Answer / Evidence | Response |
| :--- | :--- | :--- | :--- |
| **B1** | **Complete `tools/list` Inventory:** List all exposed tools and classify each into `[tool_risk_tiers]` (`low`, `medium`, `high`). | Unlisted tools default fail-closed to `high` (`REQUIRE_APPROVAL`). | `[Tool list + tiers]` |
| **B2** | **Deterministic `ToolCapability` Binding:** Which `preset` (`mcp-filesystem`, `mcp-fetch`, `github`, `linear`, `slack`, `postgres`) or `[tool_capabilities]` (`path_read_args`, `path_write_args`, `url_args`, `shell_argv_arg`, `pure = true`) binds every `low`/`medium` tool? | Policy loader refuses `low`/`medium` tools without a capability binding (`src/mellyn/policy.py`). | `[Preset or explicit bindings]` |
| **B3** | **Trust Posture (`trusted` / `trusted_mcp_servers`):** Does this server ingest external or user-authored content? | Must default to `trusted = false` (taints session on call/list) unless strictly local/static. | `[false (Recommended) / justification if true]` |
| **B4** | **High-Risk Exclusions:** Are unguarded recursive search tools (`search_files`, `directory_tree`) and shell interpreters excluded or held at `high`? | Confirmed excluded from `low`/`medium` tiers (`TM-03`, `TM-10`). | `[Yes / Exception ref]` |

### Part C — Authentication, OAuth 2.1 & Subprocess Environment Isolation
| # | Assessment Question | Required Answer / Evidence | Response |
| :--- | :--- | :--- | :--- |
| **C1** | **OAuth 2.1 Configuration (if `streamable-http`):** Specify `flow` (`pkce` or M2M), `allowed_authorization_servers`, `resource`, and least-privilege `scopes`. | Exact `resource` & `issuer` match enforced (`src/mellyn/oauth_client.py`). | `[N/A or OAuth fields]` |
| **C2** | **Secret Custody & `token_cache_path`:** Are `client_secret_env` / `bearer_token_env` passed solely via env-var names (never raw secrets in TOML) and `token_cache_path` placed outside `/workspace`? | Confirmed out-of-workspace, one cache file per server; raw secret keys forbidden (`unified_config.py`). | `[Confirmed / Path]` |
| **C3** | **Subprocess `pass_env` Justification (if `stdio`):** List any env vars requested beyond `DEFAULT_DOWNSTREAM_ENV_ALLOWLIST`. | Zero `MELLYN_*`, OAuth secrets, or `CODE_INJECTION_ENV_NAMES` (`LD_PRELOAD`, `PYTHONPATH`, `NODE_OPTIONS`, etc. per PR #37). | `[None or exact list]` |

### Part D — Network Egress & Data Handling
| # | Assessment Question | Required Answer / Evidence | Response |
| :--- | :--- | :--- | :--- |
| **D1** | **Required Outbound Domains:** Which hostnames does the server or its tools legitimately contact? | Gateway/OAuth hosts stay in `gateway_egress_domains` only; tool destinations require `[egress].allowed_domains` + Squid (`deploy/egress/squid.conf`). | `[Exact HTTPS hostnames]` |
| **D2** | **Protocol & SSRF Posture:** Does the server require HTTP redirects, plaintext HTTP, or internal/RFC1918 IPs? | Mellyn refuses redirects (`3xx`), non-HTTPS, IP literals, and private/metadata CIDRs (`TM-02`, `TM-14`). | `[No — HTTPS strict]` |
| **D3** | **Vendor Data Retention & Model Training (Remote MCP):** Does the vendor retain tool arguments/outputs or use them for model training? | Contractual zero-retention / training opt-out confirmation for non-public data. | `[Retention terms / Link]` |

---

## 3. Part E — Pinning-as-Evidence Verification Record

Attach the exact `mellyn pin` (Gateway `mellyn.toml`) or `mellyn-pin` (Airlock `AirlockPolicy`) output generated inside Mellyn's quarantined subprocess sandbox (`src/mellyn/pin_gateway.py` / `src/mellyn/airlock/pin_cli.py`).

### Blank Verification Template
```toml
# Executed command:
#   mellyn pin --name <server-name> --preset <preset> --config config/mellyn.toml -- <server-cmd...>
#   (or) mellyn-pin --output <policy.toml> -- <server-cmd...>
# Inspection timestamp (UTC): [YYYY-MM-DDTHH:MM:SSZ]
# Reviewer: [Name / Role]
# Unicode smuggling check (invisible / non-NFKC warnings): [0 warnings]

schema_version = 2

[[servers]]
name = "<server-name>"
transport = "stdio"
preset = "<preset>"
trusted = false
tools_sha256 = "<64-char lowercase hex SHA-256 from mellyn pin>"
```

### Worked Example from Repository (`examples/airlock_demo/reviewed_policy.toml`)
The repository's reference Airlock demo policy demonstrates pinning-as-evidence against `examples/airlock_demo/sample_mcp_server.py`:
*   **Verification Tool:** `mellyn-pin` (`src/mellyn/airlock/pin_cli.py`)
*   **Pinned Manifest Digest (`manifest_sha256`):** `4953dd98bc22d12acb49e47e504f820e03559fdbd9c92fc7fc46f2621bbc3407`
*   **Per-Tool AgBOM Pins (`[agbom_pins]`):**
    *   `read_status_note`: `397a273375dc43c3e70c4049c9471cd63929e16ae592c310a80fe7689780cf14` *(Reviewed & allowed: `allowed_arg_names = ["note_id"]`, `arg_regex_rules = { note_id = "^[a-z0-9-]+$" }`)*
    *   `export_diagnostics`: `61b837c3ae79132a6888ea7654f5bf991303f8ec6b86f43e6498134a6f7a5330` *(Pinned for inventory visibility, explicitly denied at runtime: `allowed = false`)*
*   **Assurance Effect:** Any unapproved change to a tool's name, description, `inputSchema`, or hidden Unicode characters breaks the SHA-256 pin and triggers immediate fail-closed containment (`AAD_FIRE` / exit `78` in Airlock; refused `tools/call` in Gateway).

---

## 4. Risk Determination & Re-Pinning Triggers

| Determination | Criteria | Approval Authority |
| :--- | :--- | :--- |
| **Approved (Pinned)** | Parts A–D complete, `0` invisible-Unicode warnings, all `low`/`medium` tools capability-bound, `tools_sha256` / `agbom_pins` committed via PR. | `[Security Engineering Lead]` |
| **Approved with Conditions** | Approved for non-production or `trusted = false` + `high`-tier `REQUIRE_APPROVAL` only until vendor gap resolved. | `[Security Lead + System Owner]` |
| **Rejected** | Unbounded shell/arbitrary code execution, invisible-Unicode smuggling detected, plaintext/redirect egress requirement, or unacceptable data retention. | `[Security Engineering Lead]` |

**Mandatory Re-Assessment / Re-Pinning Triggers:** Any `tools_sha256` or `agbom_pins` mismatch (`SEV-2` alert per [INCIDENT_DRILL_001.md](../../INCIDENT_DRILL_001.md)), upstream server version bump, new OAuth scope request, or annual review.
