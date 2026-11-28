# Mellyn Security: Completed Third-Party Risk Assessment — `@modelcontextprotocol/server-filesystem`

**Assessment ID:** `TPRM-MCP-2026-001`\
**Server Under Review:** `@modelcontextprotocol/server-filesystem@2.4.1` (`io.github.modelcontextprotocol/server-filesystem`)\
**Assessed Date:** 2026-11-27 | **Mellyn Snapshot:** Commit `bedbe50` (`main`)\
**Assessor / Owner:** Project maintainer (OramramLLC) — single-maintainer project (see `RSK-08` in [RISK_REGISTER.md](../../../RISK_REGISTER.md))\
**Mapped Controls:** NIST AI RMF 1.0 (`GOVERN 6.1`, `GOVERN 6.2`, `MAP 4.1`, `MAP 4.2`, `MANAGE 3.1`) | ISO/IEC 42001 (`A.4.4`, `A.10.2`, `A.10.3`) | SOC 2 (`CC8.1`, `CC9.2`) | ISO/IEC 27001:2022 (`A.5.19`, `A.5.20`, `A.8.32`)

> **In plain terms:** Before Mellyn allows an AI agent to call an external MCP server, the server is launched inside a stripped-down quarantine, its live `tools/list` output is hashed and checked for hidden Unicode instructions, and every tool is mapped to Mellyn's risk tiers and path guards. Inspecting `@modelcontextprotocol/server-filesystem@2.4.1` live uncovered **4 tools** (`append_file`, `copy_file`, `directory_tree`, `search_files`) beyond the 12 tools in Mellyn's `mcp-filesystem` preset—demonstrating how Mellyn's fail-closed default automatically holds unmapped tools at `high` (`REQUIRE_APPROVAL`).

---

## 1. Part A — Server Provenance & Supply Chain

| # | Assessment Question | Observed Evidence / Answer |
| :--- | :--- | :--- |
| **A1** | **Server Name & Vendor/Maintainer** | Gateway server name: `local-workspace`. Package: `@modelcontextprotocol/server-filesystem` (`mcpName`: `io.github.modelcontextprotocol/server-filesystem`), published by `Model Context Protocol a Series of LF Projects, LLC.` Upstream repo: `https://github.com/modelcontextprotocol/servers.git` (homepage `https://modelcontextprotocol.io`). |
| **A2** | **Pinned Version & Artifact Integrity** | Exact npm version `2.4.1` (`package-lock.json` lockfileVersion `3`). Resolved tarball: `https://registry.npmjs.org/@modelcontextprotocol/server-filesystem/-/server-filesystem-2.4.1.tgz`. **SHA-512 integrity:** `sha512-77Az42zbdj97BPS+3d0gGc74BoYxhR/tY1SodV7VjhZRbJt8PTeQtZfPOZncXXOVuUc8rY+BdFgIeaFwo8IzZg==`. Entrypoint: `dist/index.js` (requires `node >= 24`, verified on Node `v24.19.0`). Package `license` field: `SEE LICENSE IN LICENSE`. |
| **A3** | **Dependency Footprint & Transport** | `stdio` transport (`[[servers]].transport = "stdio"`). Lockfile installs `12` total npm packages (`@modelcontextprotocol/server-filesystem` plus `11` dependencies/peers: `@modelcontextprotocol/node@2.1.2`, `@modelcontextprotocol/server@2.4.0`, `@modelcontextprotocol/core@2.4.0`, `@hono/node-server@2.1.11`, `hono@4.13.23`, `diff@8.0.4`, `minimatch@11.0.9`, `zod@4.6.7`, `brace-expansion@5.1.0`, `balanced-match@4.0.4`, `@isaacs/nonrecursive-glob-match@1.1.0`). |
| **A4** | **Maintenance & Vulnerability Disclosure** | Active upstream issue tracker (`https://github.com/modelcontextprotocol/servers/issues`). **Finding:** Never invoke via unpinned `npx -y @modelcontextprotocol/server-filesystem` in production; require an exact version + `package-lock.json` integrity check or pre-built container image digest. |

---

## 2. Part B — Live Tool Surface, Capability Binding & Gap Analysis (`16` Tools)

Live `tools/list` inspection returned **`16` tools**, whereas `MCP_CAPABILITY_PRESETS["mcp-filesystem"]` (`src/mellyn/policy.py`) explicitly maps **`12` tools**:

| Tool Name | Live Required Args | `mcp-filesystem` Preset Tier | Bound `ToolCapability` (`src/mellyn/policy.py`) | Runtime Enforcement & Assessment Finding |
| :--- | :--- | :---: | :--- | :--- |
| `read_file` | `path` | `low` | `path_read_args=("path",)` | Autonomous `ALLOW`; confined by `WorkspacePathGuard` (note: marked `DEPRECATED` upstream in favor of `read_text_file`). |
| `read_text_file` | `path` | `low` | `path_read_args=("path",)` | Autonomous `ALLOW`; confined by `WorkspacePathGuard`. |
| `read_media_file` | `path` | `low` | `path_read_args=("path",)` | Autonomous `ALLOW`; confined by `WorkspacePathGuard`; response scanned by `mellyn.core.scan`. |
| `read_multiple_files` | `paths` | `low` | `path_read_list_args=("paths",)` | Autonomous `ALLOW`; every path element checked by `WorkspacePathGuard`. |
| `list_directory` | `path` | `low` | `path_read_args=("path",)` | Autonomous `ALLOW`; confined by `WorkspacePathGuard`. |
| `list_directory_with_sizes` | `path` | `low` | `path_read_args=("path",)` | Autonomous `ALLOW`; confined by `WorkspacePathGuard`. |
| `get_file_info` | `path` | `low` | `path_read_args=("path",)` | Autonomous `ALLOW`; confined by `WorkspacePathGuard`. |
| `list_allowed_directories` | *(none)* | `low` | `pure=True` | Autonomous `ALLOW`; no path args accepted. |
| `write_file` | `path`, `content` | `medium` | `path_write_args=("path",)` | `ALLOW` when clean; escalates to `REQUIRE_APPROVAL` once session is tainted; `GUARDRAIL_PATHS`/`protected_paths`/`owned_files` denied even with grant. |
| `edit_file` | `path`, `edits` | `medium` | `path_write_args=("path",)` | `ALLOW` when clean; escalates to `REQUIRE_APPROVAL` once tainted; `protected_paths` denied. |
| `create_directory` | `path` | `medium` | `path_write_args=("path",)` | `ALLOW` when clean; escalates to `REQUIRE_APPROVAL` once tainted; `protected_paths` denied. |
| `move_file` | `source`, `destination` | `medium` | `path_write_args=("source", "destination")` | `ALLOW` when clean; escalates to `REQUIRE_APPROVAL` once tainted; ancestor subtree moves of `protected_paths` denied (`TM-05`). |
| `append_file` | `path`, `content` | **`high` (unmapped)** | *None (`UNBOUND_PATH_ARG_NAMES`)* | **Preset gap found:** Added in upstream server; unmapped by preset so Mellyn fails closed to `high` (`REQUIRE_APPROVAL`) and checks `path` as a write. Leave at `high`, or bind `path_write_args=("path",)` if `medium` is needed. |
| `copy_file` | `source`, `destination` | **`high` (unmapped)** | *None (`UNBOUND_PATH_ARG_NAMES`)* | **Preset gap found:** Unmapped by preset so Mellyn fails closed to `high` (`REQUIRE_APPROVAL`) and checks `source`/`destination` as writes. Leave at `high`, or bind explicitly if needed. |
| `directory_tree` | `path` | **`high` (unmapped)** | *Intentionally omitted* | **Intentional exclusion (`TM-03`):** Recursive tree traversal is omitted from `MCP_CAPABILITY_PRESETS` and held at `high` (`REQUIRE_APPROVAL`). Keep at `high`. |
| `search_files` | `path`, `pattern` | **`high` (unmapped)** | *Intentionally omitted* | **Intentional exclusion (`TM-03`):** Recursive glob walk is omitted from `MCP_CAPABILITY_PRESETS` and held at `high` (`REQUIRE_APPROVAL`). Keep at `high`. |

*   **B3 Trust Posture Finding:** `SMB_SERVER_PRESETS["mcp-filesystem"]` sets `trusted = true` by default (assuming a clean local repo). **Condition:** If the mounted workspace contains untrusted third-party files (cloned external repos, downloaded issues, external docs), operators MUST override with `--untrusted` (`trusted = false`) so reads taint the session.
*   **B4 High-Risk Exclusions:** No shell execution tools are exposed; `directory_tree` and `search_files` remain held at `high`.

---

## 3. Part C — Authentication, OAuth 2.1 & Environment Isolation

| # | Control Check | Assessment Result |
| :--- | :--- | :--- |
| **C1** | **OAuth 2.1 / Remote Auth** | Not applicable (`transport = "stdio"`, local child process only). |
| **C2** | **Secret Custody** | Zero credentials, API keys, or OAuth `token_cache_path` required. |
| **C3** | **Subprocess `pass_env`** | `pass_env = []` (empty). Live inspection succeeded with `DEFAULT_DOWNSTREAM_ENV_ALLOWLIST` alone—no `MELLYN_*`, OAuth secrets, or `CODE_INJECTION_ENV_NAMES` (`LD_PRELOAD`, `PYTHONPATH`, `NODE_OPTIONS`, etc.) are needed or permitted. |

---

## 4. Part D — Network Egress & Data Handling

| # | Control Check | Assessment Result |
| :--- | :--- | :--- |
| **D1** | **Required Outbound Domains** | None (`egress_domains = ()`). Although `@hono/node-server` and `hono` appear in `node_modules` via `@modelcontextprotocol/node`, `server-filesystem` runs purely over `stdio`. Container deployments (`deploy/docker-compose.yml` + `deploy/egress/squid.conf`) block any unexpected outbound connections at the network layer. |
| **D2** | **Protocol & SSRF Posture** | No outbound HTTP requests or URL tool arguments. |
| **D3** | **Data Handling & Known Boundary** | All file data remains local within the configured workspace root(s). **Accepted Residual Boundary (`docs/THREAT_MODEL.md` §4):** Mellyn validates paths prior to downstream `open()` (check-then-use TOCTOU); mitigate in sensitive environments by mounting only the target repository inside the container stack (`MELLYN_REQUIRE_WORKSPACE_MOUNT=1`). |

---

## 5. Part E — Pinning-as-Evidence Verification Record

*   **Inspection Timestamp (UTC):** `2026-11-27T23:33–23:34 UTC`
*   **Unicode Smuggling Check (`mellyn pin` & `mellyn-pin`):** **`0` warnings** (zero invisible format/tag/bidi/zero-width or non-NFKC characters across all `16` tool definitions).
*   **Gateway Pin Command (`mellyn.pin_gateway`):**
    ```bash
    python -m mellyn.pin_gateway --name local-workspace --preset mcp-filesystem \
      --json -- node ./node_modules/@modelcontextprotocol/server-filesystem/dist/index.js ./sandbox_root
    ```
    *   **Pinned `tools_sha256`:** `789b5d1ed5f1bcd6cd91a8bd0dab3693062d5ffed2c26544e7720b0a9cb9c4d1`
    *   **Raw Evidence:** [`pin-gateway-output.json`](pin-gateway-output.json)
*   **Airlock Pin Command (`mellyn-pin`):**
    ```bash
    mellyn-pin --policy-id tprm-mcp-2026-001 --output pin-airlock-starter.toml \
      -- node ./node_modules/@modelcontextprotocol/server-filesystem/dist/index.js ./sandbox_root
    ```
    *   **Pinned `manifest_sha256`:** `f4bcf214f2ea8b71178bbd6408df901dce11502483b98c7e9feed592b0b022cd`
    *   **Raw Evidence:** [`pin-airlock-starter.toml`](pin-airlock-starter.toml) (fail-closed starter policy: `allowed_tools = []`, all 16 per-tool `[agbom_pins]` populated, all 16 `[tool_rules.*]` `allowed = false`).

### Approved Gateway Configuration Block (`mellyn.toml`, `schema_version = 2`)
```toml
[[servers]]
name = "local-workspace"
transport = "stdio"
preset = "mcp-filesystem"
trusted = false  # Set to true only when workspace contains exclusively trusted local files
command = ["node", "/opt/mcp/server-filesystem/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js", "/workspace"]
tools_sha256 = "789b5d1ed5f1bcd6cd91a8bd0dab3693062d5ffed2c26544e7720b0a9cb9c4d1"
```

---

## 6. Risk Determination, Conditions & Re-Pinning Triggers

*   **Determination:** **Approved with Conditions**
*   **Mandatory Conditions:**
    1.  **Immutable Packaging:** Pin `@modelcontextprotocol/server-filesystem@2.4.1` with lockfile SHA-512 verification (never run `npx @modelcontextprotocol/server-filesystem` floating `latest`).
    2.  **Preserve `high` Tier on Unmapped/Recursive Tools:** Keep `directory_tree`, `search_files`, `append_file`, and `copy_file` at `high` (`REQUIRE_APPROVAL`) unless explicitly reviewed and bound under `[tool_capabilities]`.
    3.  **Taint Posture:** Use `trusted = false` whenever the mounted workspace holds external/untrusted repositories or documents.
    4.  **Container Isolation for Sensitive Repos:** Run inside `deploy/docker-compose.yml` (`mellyn-mcp` UID `10002`, internal bridge + Squid egress proxy) to mitigate downstream check-then-use path TOCTOU and block unexpected egress.
*   **Mandatory Re-Pinning Triggers:** Any `tools_sha256` or `manifest_sha256` mismatch (`SEV-2` alert per [INCIDENT_DRILL_001.md](../../../INCIDENT_DRILL_001.md)), any npm version bump above `2.4.1`, or quarterly review (`Next Review: 2027-02-27`).
