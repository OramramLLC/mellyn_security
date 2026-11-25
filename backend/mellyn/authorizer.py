"""Core Mellyn Security Authorizer orchestrating sessions, taint, capabilities, policy, grants, egress, and audit."""

from __future__ import annotations

import secrets
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import url2pathname

from mellyn.audit import MAX_TAINT_ENTRY_CHARS, AuditLogger, format_taint_entry, hash_untrusted_identifier, redact_text
from mellyn.egress import _CONTROL_CHARACTERS, EgressValidator, WorkspacePathGuard
from mellyn.models import (
    ApprovalGrant,
    AuthorizationResult,
    Decision,
    RiskTier,
    TaintSource,
    ToolCallRequest,
    canonical_json,
    effective_mcp_method,
    utc_now,
    validate_json_value,
)
from mellyn.policy import (
    UNBOUND_PATH_ARG_NAMES,
    PolicyConfig,
    PolicyEngine,
    ScopedRule,
    ToolCapability,
    validate_argv,
)
from mellyn.state_store import AuthorizerStateStore, InMemoryStateStore, SessionSnapshot
from mellyn.state_store import SessionLimitError as SessionLimitError

# MCP resources/read is authorized as a pseudo-tool of this name, with arguments {"uri": ...}.
RESOURCE_READ_TOOL = "resources/read"

MAX_GRANT_TTL_SECONDS = 86400
MAX_GRANT_USES = 100
DEFAULT_SESSION_TTL_SECONDS = 86400
DEFAULT_MAX_SESSIONS = 10_000
DEFAULT_MAX_TAINT_SAMPLE = 16


class Authorizer:
    """
    Deterministic, authorization-first tool-call gatekeeper.

    Decision invariant:
    1. Hard security boundaries (known session, strict RFC 8259 JSON arguments, MCP allowlist,
       capability-bound workspace secret/guardrail jail, argv-only shell execution, SSRF/egress
       allowlist, explicit DENY rules) ALWAYS deny regardless of taint state, approval grants, or
       risk scores.
    2. High-risk tools in a tainted session are NEVER auto-allowed without an explicit taint-safe
       scoped policy rule or a valid human grant for that exact call.
    3. Supporting signals (prompt-injection score, DLP secret hit) can only escalate a decision
       (ALLOW -> REQUIRE_APPROVAL -> DENY), never relax it.

    Session model: session IDs are issued by the authorizer (`create_session`) and unknown IDs are
    denied, so a caller cannot shed taint by inventing a fresh ID. Ephemeral in-memory restarts fail
    closed rather than resetting sessions to clean; configuring `SqliteStateStore` persists session
    taint and exact-call grants durably across restarts while still failing closed on corruption or
    expiry. Taint is recorded automatically whenever an allowed call's result brings outside content
    into the session (by `authorize`, or by `record_tool_result_taint` once the gateway has the server's
    reply); `mark_tainted` is for other sources the harness knows about (an issue body, a PR comment).
    """

    def __init__(
        self,
        *,
        workspace_root: Path,
        policy_config: PolicyConfig | None = None,
        audit_logger: AuditLogger | None = None,
        session_ttl_seconds: int | None = DEFAULT_SESSION_TTL_SECONDS,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        max_taint_sample: int = DEFAULT_MAX_TAINT_SAMPLE,
        state_store: AuthorizerStateStore | None = None,
    ) -> None:
        # session_ttl_seconds=None: sessions never expire (the stdio gateway's single session lives as long
        # as the process, so an idle client is not locked out after a day).
        if session_ttl_seconds is not None and session_ttl_seconds <= 0:
            raise ValueError("session_ttl_seconds must be positive or None.")
        if max_sessions <= 0:
            raise ValueError("max_sessions must be positive.")
        if max_taint_sample <= 0:
            raise ValueError("max_taint_sample must be positive.")
        self.policy = PolicyEngine(policy_config)
        self.egress = EgressValidator(self.policy.config.allowed_egress_domains)
        self.path_guard = WorkspacePathGuard(workspace_root, self.policy.config.protected_paths)
        self.audit = audit_logger or AuditLogger()
        self.session_ttl_seconds = session_ttl_seconds
        self.max_sessions = max_sessions
        self.max_taint_sample = max_taint_sample
        # FastAPI runs sync handlers in a thread pool; one lock keeps taint and grant use atomic.
        self._lock = threading.Lock()
        self._state: AuthorizerStateStore = state_store if state_store is not None else InMemoryStateStore()

    @property
    def _grants(self) -> dict[str, ApprovalGrant]:
        return self._state.active_grants_snapshot()

    def close(self) -> None:
        """Close the backing state store (idempotent)."""
        self._state.close()

    def __enter__(self) -> Authorizer:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ---- Sessions & taint -------------------------------------------------------------------------

    def create_session(self, *, now: datetime | None = None, owner_subject: str | None = None) -> str:
        """Issue a new, clean session ID. Only IDs issued here are accepted by authorize()."""
        created = now or utc_now()
        session_id = f"ses_{secrets.token_urlsafe(18)}"
        with self._lock:
            self._state.create_session(
                session_id,
                now=created,
                session_ttl_seconds=self.session_ttl_seconds,
                max_sessions=self.max_sessions,
                owner_subject=owner_subject,
            )
        return session_id

    def has_session(self, session_id: str, *, now: datetime | None = None) -> bool:
        with self._lock:
            return self._state.has_session(
                session_id,
                now=now or utc_now(),
                session_ttl_seconds=self.session_ttl_seconds,
            )

    def get_session_snapshot(self, session_id: str, *, now: datetime | None = None) -> SessionSnapshot | None:
        """Return the immutable session snapshot if active and unexpired, else `None`."""
        check_time = now or utc_now()
        with self._lock:
            if not self._state.has_session(
                session_id,
                now=check_time,
                session_ttl_seconds=self.session_ttl_seconds,
            ):
                return None
            return self._state.get_session_snapshot(session_id)

    def delete_session(self, session_id: str) -> bool:
        """Delete a session and any associated taints/grants."""
        with self._lock:
            return self._state.delete_session(session_id)

    def _safe_origin_for_request(self, request: ToolCallRequest) -> str:
        if request.mcp_server is None:
            srv_part = "local"
        elif self.policy.is_known_mcp_server(request.mcp_server):
            srv_part = redact_text(request.mcp_server)[:64]
        else:
            srv_part = hash_untrusted_identifier("untrusted_srv", request.mcp_server)

        if self.policy.is_known_tool(request.tool_name, request.mcp_server):
            tool_part = redact_text(request.tool_name)[:64]
        else:
            tool_part = hash_untrusted_identifier("untrusted_tool", request.tool_name)
        return f"{srv_part}:{tool_part}"

    @staticmethod
    def _sanitize_taint_source(source: TaintSource) -> tuple[TaintSource, str]:
        sanitized = TaintSource(
            source_type=redact_text(source.source_type)[:64],
            origin=redact_text(source.origin)[:MAX_TAINT_ENTRY_CHARS],
            recorded_at=source.recorded_at,
        )
        return sanitized, format_taint_entry(sanitized)

    def mark_tainted(self, session_id: str, source: TaintSource, *, now: datetime | None = None) -> None:
        """Record that untrusted external content has entered the session and emit a durable audit event."""
        check_time = now or utc_now()
        sanitized, formatted = self._sanitize_taint_source(source)
        with self._lock:
            updated = self._state.record_taint(
                session_id,
                sanitized,
                formatted,
                now=check_time,
                session_ttl_seconds=self.session_ttl_seconds,
                max_taint_sample=self.max_taint_sample,
                missing_ok=False,
            )
        if updated is None:
            raise KeyError(f"Unknown session '{session_id}'.")
        taint_count, taint_entries = updated
        self.audit.record_taint(
            session_id=session_id,
            taint_count=taint_count,
            taint_sources=taint_entries,
            reason=f"Session tainted by '{taint_entries[-1]}'.",
        )

    def record_tool_result_taint(self, request: ToolCallRequest, *, now: datetime | None = None) -> bool:
        """
        Record taint from an allowed tool call's result AFTER downstream execution succeeds.

        Used by `MCPGateway` (which calls `authorize(..., record_taint_on_allow=False)`) so failed
        or timed-out downstream requests do not taint the session with content that never arrived.
        Emits a durable taint audit event so a session ending immediately still leaves JSONL evidence.
        """
        if not self.policy.brings_untrusted_content(request):
            return False
        check_time = now or utc_now()
        origin = self._safe_origin_for_request(request)
        sanitized, formatted = self._sanitize_taint_source(
            TaintSource(source_type="tool_result", origin=origin, recorded_at=check_time)
        )
        with self._lock:
            updated = self._state.record_taint(
                request.session_id,
                sanitized,
                formatted,
                now=check_time,
                session_ttl_seconds=self.session_ttl_seconds,
                max_taint_sample=self.max_taint_sample,
                missing_ok=True,
            )
        if updated is None:
            return False
        taint_count, taint_entries = updated
        self.audit.record_taint(
            session_id=request.session_id,
            taint_count=taint_count,
            taint_sources=taint_entries,
            reason=f"Session tainted by the result of '{origin}'.",
        )
        return True

    def is_tainted(self, session_id: str) -> bool:
        with self._lock:
            state = self._state.get_session_snapshot(session_id)
            return bool(state and state.tainted)

    def get_taint_count(self, session_id: str) -> int:
        with self._lock:
            state = self._state.get_session_snapshot(session_id)
            return state.taint_count if state else 0

    def get_taint_sources(self, session_id: str) -> tuple[TaintSource, ...]:
        with self._lock:
            state = self._state.get_session_snapshot(session_id)
            return state.taint_sample if state else ()

    # ---- Human approval grants ------------------------------------------------------------------

    def issue_grant(
        self,
        *,
        session_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        approved_by: str,
        mcp_server: str | None = None,
        mcp_method: str | None = None,
        ttl_seconds: int = 900,
        max_uses: int = 1,
        now: datetime | None = None,
    ) -> ApprovalGrant:
        """
        Approve one exact tool call (session, operation, tool, MCP server, and full argument set) for a short time.

        Callers must restrict this to human approvers: the API exposes it only to the approver credential,
        never to the agent credential.
        """
        if not 0 < ttl_seconds <= MAX_GRANT_TTL_SECONDS:
            raise ValueError(f"ttl_seconds must be between 1 and {MAX_GRANT_TTL_SECONDS} seconds.")
        if not 0 < max_uses <= MAX_GRANT_USES:
            raise ValueError(f"max_uses must be between 1 and {MAX_GRANT_USES}.")
        issued_at = now or utc_now()
        grant = ApprovalGrant(
            grant_id=f"grt_{secrets.token_hex(10)}",
            session_id=session_id,
            tool_name=tool_name,
            mcp_server=mcp_server,
            arguments_json=canonical_json(arguments),
            approved_by=approved_by,
            expires_at=issued_at + timedelta(seconds=ttl_seconds),
            max_uses=max_uses,
            mcp_method=mcp_method,
        )
        with self._lock:
            self._state.issue_grant(
                grant,
                now=issued_at,
                session_ttl_seconds=self.session_ttl_seconds,
            )
        return grant

    # ---- Authorization ---------------------------------------------------------------------------

    def authorize(
        self,
        request: ToolCallRequest,
        *,
        now: datetime | None = None,
        record_taint_on_allow: bool = True,
        denial_reason: str | None = None,
    ) -> AuthorizationResult:
        """Evaluate a tool call and record a redacted audit event."""
        with self._lock:
            return self._authorize_locked(
                request,
                now or utc_now(),
                record_taint_on_allow=record_taint_on_allow,
                denial_reason=denial_reason,
            )

    def _authorize_locked(
        self,
        request: ToolCallRequest,
        check_time: datetime,
        *,
        record_taint_on_allow: bool,
        denial_reason: str | None = None,
    ) -> AuthorizationResult:
        risk_tier = self.policy.classify_risk(request.tool_name, request.mcp_server)
        state = self._state.touch_session(
            request.session_id,
            now=check_time,
            session_ttl_seconds=self.session_ttl_seconds,
        )

        # 0. Hard boundary: the session must have been issued by this authorizer
        if state is None:
            reason = "Unknown session ID; sessions must be created by the authorizer (fails closed after restart)."
            return self._finalize(
                request,
                Decision.DENY,
                risk_tier,
                False,
                (),
                [reason],
                taint_count=0,
                session_known=False,
            )

        tainted = state.tainted
        taint_entries = state.taint_entries
        taint_count = state.taint_count
        reasons: list[str] = []
        policy_id: str | None = None
        grant_id: str | None = None

        def deny(reason: str) -> AuthorizationResult:
            return self._finalize(
                request,
                Decision.DENY,
                risk_tier,
                tainted,
                taint_entries,
                [*reasons, reason],
                taint_count=taint_count,
            )

        # 0b. Hard boundary: arguments must be a valid RFC 8259 JSON mapping
        if not isinstance(request.arguments, dict):
            return deny("Tool arguments must be a dictionary.")
        try:
            validate_json_value(request.arguments)
        except (TypeError, ValueError) as exc:
            return deny(f"Invalid tool arguments: {exc}")

        # 1. Hard boundary: MCP server allowlist
        mcp_ok, mcp_reason = self.policy.check_mcp_server(request.mcp_server)
        if not mcp_ok:
            return deny(mcp_reason)

        # 1b. Hard boundary: MCP operation identity separation (tools/call vs resources/read)
        op_method = effective_mcp_method(request.tool_name, request.mcp_method)
        if request.mcp_method == "tools/call" and (request.tool_name == RESOURCE_READ_TOOL or "/" in request.tool_name):
            return deny("Reserved MCP operation name cannot be invoked via tools/call.")
        if op_method == "resources/read" and request.tool_name != RESOURCE_READ_TOOL:
            return deny("resources/read requests must use the reserved resource-read operation identity.")

        # 1c. Hard boundary: caller-detected protocol/pinning denial (e.g. failed pinned_tool_hashes check)
        if denial_reason is not None:
            return deny(denial_reason)

        # 2. Hard boundary: MCP resource reads of file:// URIs
        if op_method == "resources/read":
            uri_ok, uri_reason = self._check_resource_uri(request.arguments.get("uri"))
            if not uri_ok:
                return deny(uri_reason)
            reasons.append(uri_reason)

        # 3. Hard boundary: Capability-bound path, shell, and URL guards
        capability = self.policy.capability_for(request.tool_name, request.mcp_server)
        argv_key = (
            capability.shell_argv_arg if capability is not None and capability.shell_argv_arg is not None else "argv"
        )
        if capability is not None:
            cap_ok, cap_reasons = self._enforce_capability(capability, request.arguments)
            if not cap_ok:
                return deny(cap_reasons[0])
            reasons.extend(cap_reasons)
        else:
            # No binding: guess path arguments by name and hold them to the write rules (see UNBOUND_PATH_ARG_NAMES).
            path_ok, path_reasons = self._guard_unbound_paths(request.arguments)
            if not path_ok:
                return deny(path_reasons[0])
            reasons.extend(path_reasons)
        # Defense in depth: a "url" argument is checked against the egress allowlist on EVERY tool, whatever its
        # capability says, unless that capability already checked it. A pure or path-only tool must not become
        # a way to hand a server an internal or metadata URL.
        if "url" in request.arguments and (capability is None or "url" not in capability.url_args):
            url_ok, url_reason = self.egress.validate_url(request.arguments.get("url", ""))
            if not url_ok:
                return deny(url_reason)
            reasons.append(url_reason)

        # 4. Evaluate scoped policy rules (explicit DENY always wins)
        matched_rule = self.policy.match_scoped_rule(request, argv_key=argv_key)
        if matched_rule and matched_rule.effect == Decision.DENY:
            reasons.append(f"Denied by scoped policy '{matched_rule.rule_id}': {matched_rule.description}")
            return self._finalize(
                request,
                Decision.DENY,
                risk_tier,
                tainted,
                taint_entries,
                reasons,
                policy_id=matched_rule.rule_id,
                taint_count=taint_count,
            )

        # 5. Base decision from risk tier + taint state + scoped allow
        decision = self._evaluate_base_decision(risk_tier, tainted, matched_rule, reasons)
        if matched_rule and decision == Decision.ALLOW:
            policy_id = matched_rule.rule_id

        # 6. A human grant for this exact call can turn REQUIRE_APPROVAL into ALLOW
        matching_grants: list[ApprovalGrant] = []
        if decision == Decision.REQUIRE_APPROVAL:
            matching_grants = [
                grant
                for grant in self._state.list_usable_grants(request.session_id, now=check_time)
                if grant.matches(request, now=check_time)
            ]
            if matching_grants:
                decision = Decision.ALLOW

        # 7. Apply supporting risk signals (escalate ONLY; never downgrade)
        decision = self._apply_risk_signals(request, decision, reasons)

        if decision == Decision.ALLOW and matching_grants:
            # A grant is spent only after risk signals leave ALLOW, and atomically so concurrent callers fail closed.
            consumed_grant = None
            for candidate in matching_grants:
                if self._state.consume_grant(candidate.grant_id, now=check_time):
                    consumed_grant = candidate
                    grant_id = candidate.grant_id
                    reasons.append(
                        f"Approved by human grant '{candidate.grant_id}' (approved_by={candidate.approved_by})."
                    )
                    break
            if consumed_grant is None:
                decision = Decision.REQUIRE_APPROVAL
                grant_id = None
                reasons.append("Approval grant was already consumed or expired; requiring approval.")

        if decision == Decision.ALLOW:
            # The result of this call will enter the agent's context: taint the session (the gateway defers
            # this to record_tool_result_taint, once it knows whether the server actually replied).
            if record_taint_on_allow and self.policy.brings_untrusted_content(request):
                origin = self._safe_origin_for_request(request)
                sanitized, formatted = self._sanitize_taint_source(
                    TaintSource(source_type="tool_result", origin=origin, recorded_at=check_time)
                )
                updated = self._state.record_taint(
                    request.session_id,
                    sanitized,
                    formatted,
                    now=check_time,
                    session_ttl_seconds=self.session_ttl_seconds,
                    max_taint_sample=self.max_taint_sample,
                    missing_ok=True,
                )
                if updated is not None:
                    taint_count, taint_entries = updated
                reasons.append(f"Session tainted by the result of '{origin}'.")
        elif grant_id is not None:
            grant_id = None

        return self._finalize(
            request,
            decision,
            risk_tier,
            tainted,
            taint_entries,
            reasons,
            policy_id=policy_id,
            grant_id=grant_id,
            taint_count=taint_count,
        )

    def _enforce_capability(self, capability: ToolCapability, arguments: dict[str, Any]) -> tuple[bool, list[str]]:
        """Run every hard-boundary guard declared by `capability`. Fails closed on missing or invalid args."""
        notes: list[str] = []

        for arg_name in capability.path_read_args:
            ok, reason = self.path_guard.validate_path(arguments.get(arg_name, ""), is_write=False)
            if not ok:
                return False, [reason]
            notes.append(reason)

        for arg_name in capability.optional_path_read_args:
            raw_val = arguments.get(arg_name)
            target = "." if raw_val is None else raw_val
            ok, reason = self.path_guard.validate_path(target, is_write=False)
            if not ok:
                return False, [reason]
            notes.append(reason)

        for arg_name in capability.path_read_list_args:
            paths = arguments.get(arg_name)
            if not isinstance(paths, list | tuple) or not paths:
                return False, [f"Argument '{arg_name}' must be a non-empty list of paths."]
            for item in paths:
                ok, reason = self.path_guard.validate_path(item, is_write=False)
                if not ok:
                    return False, [reason]
                notes.append(reason)

        for arg_name in capability.path_write_args:
            ok, reason = self.path_guard.validate_path(arguments.get(arg_name, ""), is_write=True)
            if not ok:
                return False, [reason]
            notes.append(reason)

        if capability.shell_argv_arg is not None:
            ok, reason = validate_argv(arguments, argv_key=capability.shell_argv_arg)
            if not ok:
                return False, [reason]
            notes.append(reason)

        for arg_name in capability.url_args:
            ok, reason = self.egress.validate_url(arguments.get(arg_name, ""))
            if not ok:
                return False, [reason]
            notes.append(reason)

        return True, notes

    def _guard_unbound_paths(self, arguments: dict[str, Any]) -> tuple[bool, list[str]]:
        """Path-like arguments of a tool with no capability binding, checked as writes (strictest)."""
        notes: list[str] = []
        for name, value in arguments.items():
            canonical_arg = name.lower()
            if canonical_arg not in UNBOUND_PATH_ARG_NAMES:
                continue
            values = value if isinstance(value, list | tuple) else [value]
            for item in values:
                if not isinstance(item, str):
                    continue  # not a path string; a bound capability would reject it, a guess should not
                ok, reason = self.path_guard.validate_path(item, is_write=True)
                if not ok:
                    return False, [f"Unbound tool argument '{canonical_arg}': {reason}"]
                notes.append(f"Unbound tool argument '{canonical_arg}': {reason}")
        return True, notes

    def _check_resource_uri(self, uri: object) -> tuple[bool, str]:
        if not isinstance(uri, str) or not uri.strip():
            return False, "resources/read requires a non-empty string 'uri'."
        if _CONTROL_CHARACTERS.search(uri):
            return False, "Resource URI contains control characters."
        try:
            parsed = urlparse(uri.strip())
            port = parsed.port
        except ValueError:
            return False, "Malformed resource URI authority or port."
        if not parsed.scheme:
            return False, "Resource URI is missing a scheme."
        if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
            return False, "Resource URIs with embedded credentials/userinfo are forbidden."
        hostport = parsed.netloc
        if "]" in hostport:
            _, _, after_bracket = hostport.rpartition("]")
            has_colon_port = ":" in after_bracket
        else:
            has_colon_port = ":" in hostport
        if has_colon_port and (port is None or port <= 0):
            return False, "Resource URI specifies an empty or invalid port."
        if parsed.scheme.lower() != "file":
            return True, "Non-file resource URI scheme; risk tier decides."
        if port is not None or parsed.netloc.lower() not in ("", "localhost"):
            return False, "file:// URI on remote host or with port is denied."
        try:
            local_path = url2pathname(parsed.path)
        except (OSError, ValueError):
            return False, "Malformed file:// resource URI path."
        return self.path_guard.validate_path(local_path, is_write=False)

    @staticmethod
    def _evaluate_base_decision(
        risk_tier: RiskTier,
        tainted: bool,
        matched_rule: ScopedRule | None,
        reasons: list[str],
    ) -> Decision:
        if matched_rule and matched_rule.effect == Decision.ALLOW:
            if not tainted or matched_rule.allow_when_tainted:
                reasons.append(f"Allowed by scoped policy '{matched_rule.rule_id}'.")
                return Decision.ALLOW
            reasons.append(
                f"Scoped policy '{matched_rule.rule_id}' does not permit execution in a tainted session; "
                "requiring approval."
            )
            return Decision.REQUIRE_APPROVAL

        if matched_rule and matched_rule.effect == Decision.REQUIRE_APPROVAL:
            reasons.append(f"Approval required by scoped policy '{matched_rule.rule_id}'.")
            return Decision.REQUIRE_APPROVAL

        if risk_tier == RiskTier.LOW:
            reasons.append("Low-risk tool call permitted.")
            return Decision.ALLOW

        if risk_tier == RiskTier.MEDIUM:
            if tainted:
                reasons.append("Medium-risk tool call in a tainted session requires human approval.")
                return Decision.REQUIRE_APPROVAL
            reasons.append("Medium-risk tool call in a clean session permitted.")
            return Decision.ALLOW

        # HIGH risk (including unknown tools)
        if tainted:
            reasons.append("High-risk tool call in a tainted session requires explicit policy allow or human approval.")
            return Decision.REQUIRE_APPROVAL

        reasons.append("High-risk tool call requires explicit policy allow or human approval.")
        return Decision.REQUIRE_APPROVAL

    def _apply_risk_signals(self, request: ToolCallRequest, current: Decision, reasons: list[str]) -> Decision:
        """Signals can escalate ALLOW -> REQUIRE_APPROVAL -> DENY, never relax."""
        signals = request.signals
        config = self.policy.config
        decision = current

        if signals.dlp_secret_detected:
            if config.deny_on_dlp_secret:
                reasons.append("DLP signal: potential secret detected in tool payload; escalating to DENY.")
                decision = Decision.DENY
            elif decision == Decision.ALLOW:
                reasons.append("DLP signal: potential secret detected; escalating to REQUIRE_APPROVAL.")
                decision = Decision.REQUIRE_APPROVAL

        score = signals.injection_score
        if score >= config.injection_deny_threshold:
            reasons.append(
                f"Injection signal ({score:.2f} >= {config.injection_deny_threshold:.2f}); escalating to DENY."
            )
            decision = Decision.DENY
        elif score >= config.injection_escalate_threshold and decision == Decision.ALLOW:
            reasons.append(
                f"Injection signal ({score:.2f} >= {config.injection_escalate_threshold:.2f}); "
                "escalating to REQUIRE_APPROVAL."
            )
            decision = Decision.REQUIRE_APPROVAL

        return decision

    def _finalize(
        self,
        request: ToolCallRequest,
        decision: Decision,
        risk_tier: RiskTier,
        tainted: bool,
        taint_sources: tuple[TaintSource | str, ...],
        reasons: list[str],
        *,
        policy_id: str | None = None,
        grant_id: str | None = None,
        taint_count: int = 0,
        session_known: bool = True,
    ) -> AuthorizationResult:
        server_known = self.policy.is_known_mcp_server(request.mcp_server)
        tool_known = server_known and self.policy.is_known_tool(request.tool_name, request.mcp_server)
        event = self.audit.record(
            session_id=request.session_id,
            tool_name=request.tool_name,
            mcp_server=request.mcp_server,
            arguments=request.arguments,
            decision=decision,
            risk_tier=risk_tier,
            tainted=tainted,
            taint_sources=taint_sources,
            reasons=tuple(reasons),
            policy_id=policy_id,
            grant_id=grant_id,
            taint_count=taint_count,
            session_known=session_known,
            tool_known=tool_known,
            server_known=server_known,
        )
        return AuthorizationResult(
            decision=decision,
            risk_tier=risk_tier,
            tainted=tainted,
            reasons=tuple(reasons),
            audit_id=event.audit_id,
            policy_id=policy_id,
            grant_id=grant_id,
        )
