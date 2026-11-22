"""Core Mellyn Security Authorizer orchestrating sessions, taint, capabilities, policy, grants, egress, and audit."""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import url2pathname

from mellyn.audit import AuditLogger
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

# MCP resources/read is authorized as a pseudo-tool of this name, with arguments {"uri": ...}.
RESOURCE_READ_TOOL = "resources/read"

MAX_GRANT_TTL_SECONDS = 86400
MAX_GRANT_USES = 100
DEFAULT_SESSION_TTL_SECONDS = 86400
DEFAULT_MAX_SESSIONS = 10_000


class SessionLimitError(RuntimeError):
    """The authorizer already holds max_sessions active sessions. Existing sessions are not evicted."""


@dataclass
class _SessionState:
    created_at: datetime
    last_seen_at: datetime
    taints: list[TaintSource] = field(default_factory=list)


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
    denied, so a caller cannot shed taint by inventing a fresh ID, and a restart (which clears this
    in-memory state) fails closed rather than resetting every session to clean. Taint is recorded
    automatically whenever an allowed call's result brings outside content into the session (by
    `authorize`, or by `record_tool_result_taint` once the gateway has the server's reply);
    `mark_tainted` is for other sources the harness knows about (an issue body, a PR comment).
    """

    def __init__(
        self,
        *,
        workspace_root: Path,
        policy_config: PolicyConfig | None = None,
        audit_logger: AuditLogger | None = None,
        session_ttl_seconds: int | None = DEFAULT_SESSION_TTL_SECONDS,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
    ) -> None:
        # session_ttl_seconds=None: sessions never expire (the stdio gateway's single session lives as long
        # as the process, so an idle client is not locked out after a day).
        if session_ttl_seconds is not None and session_ttl_seconds <= 0:
            raise ValueError("session_ttl_seconds must be positive or None.")
        if max_sessions <= 0:
            raise ValueError("max_sessions must be positive.")
        self.policy = PolicyEngine(policy_config)
        self.egress = EgressValidator(self.policy.config.allowed_egress_domains)
        self.path_guard = WorkspacePathGuard(workspace_root, self.policy.config.protected_paths)
        self.audit = audit_logger or AuditLogger()
        self.session_ttl_seconds = session_ttl_seconds
        self.max_sessions = max_sessions
        # FastAPI runs sync handlers in a thread pool; one lock keeps taint and grant use atomic.
        self._lock = threading.Lock()
        self._sessions: dict[str, _SessionState] = {}
        self._grants: dict[str, ApprovalGrant] = {}
        self._grant_uses: dict[str, int] = {}

    # ---- Sessions & taint -------------------------------------------------------------------------

    def _evict_session_locked(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
        stale_grants = [gid for gid, grant in self._grants.items() if grant.session_id == session_id]
        for gid in stale_grants:
            del self._grants[gid]
            self._grant_uses.pop(gid, None)

    def _prune_sessions_locked(self, now: datetime) -> None:
        if self.session_ttl_seconds is None:
            return
        cutoff = now - timedelta(seconds=self.session_ttl_seconds)
        expired = [sid for sid, state in self._sessions.items() if state.last_seen_at < cutoff]
        for sid in expired:
            self._evict_session_locked(sid)

    def create_session(self, *, now: datetime | None = None) -> str:
        """Issue a new, clean session ID. Only IDs issued here are accepted by authorize()."""
        created = now or utc_now()
        session_id = f"ses_{secrets.token_urlsafe(18)}"
        with self._lock:
            self._prune_sessions_locked(created)
            # Refuse rather than evict: evicting the oldest session would let anyone holding the agent key
            # end other agents' active sessions just by opening new ones.
            if len(self._sessions) >= self.max_sessions:
                raise SessionLimitError(f"Session limit ({self.max_sessions}) reached; try again later.")
            self._sessions[session_id] = _SessionState(created_at=created, last_seen_at=created)
        return session_id

    def has_session(self, session_id: str, *, now: datetime | None = None) -> bool:
        with self._lock:
            self._prune_sessions_locked(now or utc_now())
            return session_id in self._sessions

    def mark_tainted(self, session_id: str, source: TaintSource, *, now: datetime | None = None) -> None:
        """Record that untrusted external content has entered the session. Unknown sessions raise KeyError."""
        check_time = now or utc_now()
        with self._lock:
            self._prune_sessions_locked(check_time)
            state = self._session(session_id)
            state.last_seen_at = check_time
            state.taints.append(source)

    def record_tool_result_taint(self, request: ToolCallRequest, *, now: datetime | None = None) -> bool:
        """
        Record taint from an allowed tool call's result AFTER downstream execution succeeds.

        Used by `MCPGateway` (which calls `authorize(..., record_taint_on_allow=False)`) so failed
        or timed-out downstream requests do not taint the session with content that never arrived.
        """
        if not self.policy.brings_untrusted_content(request):
            return False
        check_time = now or utc_now()
        origin = f"{request.mcp_server or 'local'}:{request.tool_name}"
        with self._lock:
            self._prune_sessions_locked(check_time)
            state = self._sessions.get(request.session_id)
            if state is None:
                return False
            state.last_seen_at = check_time
            state.taints.append(TaintSource(source_type="tool_result", origin=origin, recorded_at=check_time))
        return True

    def is_tainted(self, session_id: str) -> bool:
        with self._lock:
            state = self._sessions.get(session_id)
            return bool(state and state.taints)

    def get_taint_sources(self, session_id: str) -> tuple[TaintSource, ...]:
        with self._lock:
            state = self._sessions.get(session_id)
            return tuple(state.taints) if state else ()

    def _session(self, session_id: str) -> _SessionState:
        state = self._sessions.get(session_id)
        if state is None:
            raise KeyError(f"Unknown session '{session_id}'.")
        return state

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
            self._prune_sessions_locked(issued_at)
            state = self._session(session_id)
            state.last_seen_at = issued_at
            self._prune_grants(issued_at)
            self._grants[grant.grant_id] = grant
            self._grant_uses[grant.grant_id] = 0
        return grant

    def _prune_grants(self, now: datetime) -> None:
        for grant_id in [g.grant_id for g in self._grants.values() if not g.is_valid(now)]:
            del self._grants[grant_id]
            del self._grant_uses[grant_id]

    def _find_matching_grant(self, request: ToolCallRequest, now: datetime) -> ApprovalGrant | None:
        for grant in self._grants.values():
            if self._grant_uses[grant.grant_id] < grant.max_uses and grant.matches(request, now=now):
                return grant
        return None

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
        self._prune_sessions_locked(check_time)
        risk_tier = self.policy.classify_risk(request.tool_name, request.mcp_server)
        state = self._sessions.get(request.session_id)

        # 0. Hard boundary: the session must have been issued by this authorizer
        if state is None:
            reason = "Unknown session ID; sessions must be created by the authorizer (fails closed after restart)."
            return self._finalize(request, Decision.DENY, risk_tier, False, (), [reason])

        state.last_seen_at = check_time
        tainted = bool(state.taints)
        taint_sources = tuple(state.taints)
        reasons: list[str] = []
        policy_id: str | None = None
        grant_id: str | None = None

        def deny(reason: str) -> AuthorizationResult:
            return self._finalize(request, Decision.DENY, risk_tier, tainted, taint_sources, [*reasons, reason])

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
            return deny(f"Tool name '{request.tool_name}' is reserved and cannot be invoked via tools/call.")
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
                request, Decision.DENY, risk_tier, tainted, taint_sources, reasons, policy_id=matched_rule.rule_id
            )

        # 5. Base decision from risk tier + taint state + scoped allow
        decision = self._evaluate_base_decision(risk_tier, tainted, matched_rule, reasons)
        if matched_rule and decision == Decision.ALLOW:
            policy_id = matched_rule.rule_id

        # 6. A human grant for this exact call can turn REQUIRE_APPROVAL into ALLOW
        matching_grant = None
        if decision == Decision.REQUIRE_APPROVAL:
            matching_grant = self._find_matching_grant(request, check_time)
            if matching_grant is not None:
                decision = Decision.ALLOW
                grant_id = matching_grant.grant_id
                reasons.append(
                    f"Approved by human grant '{matching_grant.grant_id}' (approved_by={matching_grant.approved_by})."
                )

        # 7. Apply supporting risk signals (escalate ONLY; never downgrade)
        decision = self._apply_risk_signals(request, decision, reasons)

        if decision == Decision.ALLOW:
            # A grant is spent only by a call it actually let through.
            if matching_grant is not None:
                self._grant_uses[matching_grant.grant_id] += 1
            # The result of this call will enter the agent's context: taint the session (the gateway defers
            # this to record_tool_result_taint, once it knows whether the server actually replied).
            if record_taint_on_allow and self.policy.brings_untrusted_content(request):
                origin = f"{request.mcp_server or 'local'}:{request.tool_name}"
                state.taints.append(TaintSource(source_type="tool_result", origin=origin, recorded_at=check_time))
                reasons.append(f"Session tainted by the result of '{origin}'.")
        elif grant_id is not None:
            grant_id = None

        return self._finalize(
            request,
            decision,
            risk_tier,
            tainted,
            taint_sources,
            reasons,
            policy_id=policy_id,
            grant_id=grant_id,
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
            if name.lower() not in UNBOUND_PATH_ARG_NAMES:
                continue
            values = value if isinstance(value, list | tuple) else [value]
            for item in values:
                if not isinstance(item, str):
                    continue  # not a path string; a bound capability would reject it, a guess should not
                ok, reason = self.path_guard.validate_path(item, is_write=True)
                if not ok:
                    return False, [f"Unbound tool argument '{name}': {reason}"]
                notes.append(f"Unbound tool argument '{name}': {reason}")
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
            return True, f"Resource URI scheme '{parsed.scheme}' (non-file); risk tier decides."
        if port is not None or parsed.netloc.lower() not in ("", "localhost"):
            return False, f"file:// URI on remote host '{parsed.netloc}' is denied."
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
        taint_sources: tuple[TaintSource, ...],
        reasons: list[str],
        *,
        policy_id: str | None = None,
        grant_id: str | None = None,
    ) -> AuthorizationResult:
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
