"""
Mellyn Security enforcement gate for AgentDojo benchmarks (`workspace`, `banking`, `slack`, `travel`).

Implements a pure-Python `MellynToolGate` backed by `mellyn.authorizer.Authorizer`,
`mellyn.core.scan.scan_value`, and hash-chained `mellyn.audit.AuditLogger`, plus a lazy
`build_mellyn_tools_executor()` adapter so local tests do not require `agentdojo` installed.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mellyn.audit import AuditLogger, verify_gateway_audit_file
from mellyn.authorizer import Authorizer
from mellyn.core.normalize import has_invisible_unicode
from mellyn.core.scan import ScannerConfig, scan_value
from mellyn.models import Decision, RiskSignals, RiskTier, TaintSource, ToolCallRequest
from mellyn.policy import PolicyConfig, ToolCapability

# Tools that only inspect state cleanly (non-tainting low-risk metadata queries)
SAFE_LOW_TOOLS: frozenset[str] = frozenset(
    {
        "get_current_day",
        "get_day_calendar_events",
        "search_calendar_events",
        "search_contacts_by_name",
        "search_contacts_by_email",
        "list_files",
        "get_channels",
        "get_users_in_channel",
        "get_balance",
        "get_all_hotels_in_city",
        "get_hotels_prices",
        "get_hotels_address",
        "get_all_restaurants_in_city",
        "get_restaurants_address",
        "get_cuisine_type_for_restaurants",
        "get_dietary_restrictions_for_restaurants",
        "get_contact_information_for_restaurants",
        "get_price_for_restaurants",
        "check_restaurant_opening_hours",
        "get_all_car_rental_companies_in_city",
        "get_car_types_available",
        "get_car_rental_address",
        "get_car_fuel_options",
        "get_car_price_per_day",
        "get_flight_information",
        "get_user_information",
    }
)

# Read tools whose output frequently carries untrusted external content / indirect prompt injections.
# Risk tier is LOW (so benign read chains still function), but execution automatically taints the session.
UNTRUSTED_READ_TOOLS: frozenset[str] = frozenset(
    {
        "get_unread_emails",
        "search_emails",
        "get_received_emails",
        "get_sent_emails",
        "search_files",
        "search_files_by_filename",
        "get_file_by_id",
        "read_file",
        "read_channel_messages",
        "read_inbox",
        "get_webpage",
        "get_most_recent_transactions",
        "get_scheduled_transactions",
        "get_rating_reviews_for_hotels",
        "get_rating_reviews_for_restaurants",
        "get_rating_reviews_for_car_rental",
    }
)

# Side-effecting task tools: allowed on clean (untainted) user intent, blocked once tainted unless granted.
TAINT_GATED_MEDIUM_TOOLS: frozenset[str] = frozenset(
    {
        "send_email",
        "share_file",
        "create_file",
        "append_to_file",
        "create_calendar_event",
        "cancel_calendar_event",
        "add_calendar_event_participants",
        "send_direct_message",
        "send_channel_message",
        "add_user_to_channel",
        "invite_user_to_slack",
        "post_webpage",
        "send_money",
        "schedule_transaction",
        "update_scheduled_transaction",
        "reserve_hotel",
        "reserve_restaurant",
        "reserve_car_rental",
    }
)

# Destructive or security-sensitive admin tools: always HIGH risk (require explicit human grant).
HIGH_RISK_TOOLS: frozenset[str] = frozenset(
    {
        "delete_file",
        "delete_email",
        "remove_user_from_slack",
        "update_password",
        "update_user_info",
    }
)


@dataclass(frozen=True)
class GateEvaluation:
    """Deterministic authorization decision returned by `MellynToolGate`."""

    tool_name: str
    allowed: bool
    decision: str
    risk_tier: str
    tainted: bool
    reasons: tuple[str, ...]
    scanner_clean: bool


def build_agentdojo_policy(
    *,
    allowed_egress_domains: frozenset[str] = frozenset(),
) -> PolicyConfig:
    """Construct a fail-closed `PolicyConfig` covering AgentDojo suites."""
    risk_tiers: dict[str, RiskTier] = {}
    capabilities: dict[str, ToolCapability] = {}

    for tool_name in (*SAFE_LOW_TOOLS, *UNTRUSTED_READ_TOOLS):
        risk_tiers[tool_name] = RiskTier.LOW
        capabilities[tool_name] = ToolCapability(pure=True)

    for tool_name in TAINT_GATED_MEDIUM_TOOLS:
        risk_tiers[tool_name] = RiskTier.MEDIUM
        capabilities[tool_name] = ToolCapability(pure=True)

    for tool_name in HIGH_RISK_TOOLS:
        risk_tiers[tool_name] = RiskTier.HIGH
        capabilities[tool_name] = ToolCapability(pure=True)

    # Tool holding explicit `url` parameter binds URL egress allowlist
    capabilities["get_webpage"] = ToolCapability(url_args=("url",))
    capabilities["post_webpage"] = ToolCapability(url_args=("url",))

    return PolicyConfig(
        tool_risk_tiers=risk_tiers,
        tool_capabilities=capabilities,
        untrusted_content_tools=UNTRUSTED_READ_TOOLS,
        allowed_egress_domains=allowed_egress_domains,
        deny_on_dlp_secret=True,
    )


class MellynToolGate:
    """Stateful security gate wrapping `Authorizer`, `ScannerConfig`, and hash-chained `AuditLogger`."""

    def __init__(
        self,
        *,
        workspace_root: Path,
        audit_log_path: Path | None = None,
        canary_tokens: Sequence[str] = (),
        allowed_egress_domains: frozenset[str] = frozenset(
            {"www.our-company.com", "our-company.com", "docs.example.com"}
        ),
    ) -> None:
        self.workspace_root = workspace_root.resolve()
        self.audit_log_path = audit_log_path
        self.canary_tokens = tuple(canary_tokens)
        self.scanner_config = ScannerConfig(
            canary_tokens=self.canary_tokens,
            block_known_secrets=True,
            aad_kill_on_leak=True,
        )
        if audit_log_path is not None:
            audit_log_path.parent.mkdir(parents=True, exist_ok=True)
            self._audit_logger, self._ledger_handle = AuditLogger.open_chained(
                audit_log_path,
                canary_tokens=self.canary_tokens,
            )
        else:
            self._audit_logger = AuditLogger(canary_tokens=self.canary_tokens)
            self._ledger_handle = None

        policy = build_agentdojo_policy(allowed_egress_domains=allowed_egress_domains)
        self.authorizer = Authorizer(
            workspace_root=self.workspace_root,
            policy_config=policy,
            audit_logger=self._audit_logger,
            session_ttl_seconds=None,
        )
        self.session_id = self.authorizer.create_session()
        self.allowed_count = 0
        self.blocked_count = 0

    def reset_task_session(self) -> str:
        """Issue a fresh session ID for a new benchmark task (each task starts untainted)."""
        self.session_id = self.authorizer.create_session()
        return self.session_id

    def evaluate_tool_call(self, tool_name: str, arguments: dict[str, Any]) -> GateEvaluation:
        """Scan arguments for canaries/secrets/invisible chars and authorize via Mellyn PolicyEngine."""
        scan_result = scan_value(arguments, self.scanner_config)
        invisible_hit = has_invisible_unicode(arguments)
        dlp_hit = not scan_result.clean
        notes = tuple(f.rule_id for f in scan_result.findings) + (("invisible_unicode",) if invisible_hit else ())
        signals = RiskSignals(
            injection_score=1.0 if invisible_hit else 0.0,
            dlp_secret_detected=dlp_hit,
            notes=notes,
        )
        request = ToolCallRequest(
            session_id=self.session_id,
            tool_name=tool_name,
            arguments=arguments,
            signals=signals,
        )
        auth = self.authorizer.authorize(request, record_taint_on_allow=False)
        allowed = auth.decision == Decision.ALLOW and not invisible_hit
        if allowed:
            self.allowed_count += 1
        else:
            self.blocked_count += 1
        return GateEvaluation(
            tool_name=tool_name,
            allowed=allowed,
            decision=auth.decision.value,
            risk_tier=auth.risk_tier.value,
            tainted=auth.tainted,
            reasons=auth.reasons,
            scanner_clean=scan_result.clean and not invisible_hit,
        )

    def record_tool_result(self, tool_name: str, arguments: dict[str, Any], result_payload: Any) -> bool:
        """Propagate session taint after an allowed untrusted read and check output scan cleanliness."""
        req = ToolCallRequest(session_id=self.session_id, tool_name=tool_name, arguments=arguments)
        tainted_now = self.authorizer.record_tool_result_taint(req)
        scan_out = scan_value(result_payload, self.scanner_config)
        if not scan_out.clean and not self.authorizer.is_tainted(self.session_id):
            self.authorizer.mark_tainted(
                self.session_id,
                TaintSource(source_type="scanner_output_flag", origin=tool_name),
            )
            return True
        return tainted_now

    def verify_audit_ledger(self) -> bool:
        """Verify cryptographic hash-chain integrity of the gateway audit log, if configured."""
        if self.audit_log_path is None:
            return True
        report = verify_gateway_audit_file(self.audit_log_path)
        return report.valid

    def close(self) -> None:
        """Flush and close the authorizer state store and chained audit ledger."""
        try:
            self.authorizer.close()
        finally:
            if self._ledger_handle is not None and not self._ledger_handle.closed:
                self._ledger_handle.close()

    def __enter__(self) -> MellynToolGate:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _tool_result_text(message: Any) -> str:
    """Join the text blocks of an AgentDojo `ChatToolResultMessage` (content is a list of blocks)."""
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    return "\n".join(str(block.get("content") or "") for block in content if isinstance(block, dict))


def build_mellyn_tools_executor(gate: MellynToolGate) -> Any:
    """
    Lazily construct an AgentDojo `BasePipelineElement` wrapping `ToolsExecutor` with `gate`.

    Raises `ImportError` only when `agentdojo` is not installed. Written against agentdojo 0.1.35, where chat
    messages are TypedDicts, tool calls are `FunctionCall` models, and tool-result `content` is a list of text
    blocks.
    """
    from agentdojo.agent_pipeline import BasePipelineElement, ToolsExecutor
    from agentdojo.types import ChatToolResultMessage, text_content_block_from_string

    class MellynGuardedToolsExecutor(BasePipelineElement):
        """Enforces Mellyn policy & taint gates around every AgentDojo tool call."""

        name = "mellyn_guarded_tools_executor"

        def __init__(self, tool_gate: MellynToolGate) -> None:
            self.gate = tool_gate
            self._inner = ToolsExecutor()

        def query(self, query: str, runtime: Any, env: Any, messages: Any, extra_args: dict[str, Any]) -> Any:
            if not messages:
                return query, runtime, env, messages, extra_args
            last = messages[-1]
            tool_calls = list(last.get("tool_calls") or []) if last.get("role") == "assistant" else []
            if not tool_calls:
                return query, runtime, env, messages, extra_args
            # A task's first tool batch has no earlier tool results: start that task untainted.
            if not any(m.get("role") == "tool" for m in messages[:-1]):
                self.gate.reset_task_session()

            allowed_calls = []
            blocked_by_index: dict[int, Any] = {}
            for index, tc in enumerate(tool_calls):
                ev = self.gate.evaluate_tool_call(str(tc.function), dict(tc.args))
                if ev.allowed:
                    allowed_calls.append((index, tc))
                    continue
                reason_text = "; ".join(ev.reasons) or "Denied by Mellyn policy gate."
                blocked_by_index[index] = ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(f"[MELLYN BLOCKED] {reason_text}")],
                    tool_call=tc,
                    tool_call_id=tc.id,
                    error=f"[MELLYN BLOCKED] {reason_text}",
                )

            results_by_index: dict[int, Any] = dict(blocked_by_index)
            if allowed_calls:
                # Run only the allowed calls, but leave the assistant message itself unchanged so every
                # tool result still matches a tool_call_id the model actually issued.
                filtered_last = {**last, "tool_calls": [tc for _, tc in allowed_calls]}
                query, runtime, env, executed, extra_args = self._inner.query(
                    query, runtime, env, [*messages[:-1], filtered_last], extra_args
                )
                inner_results = list(executed[len(messages) :])
                for (index, tc), result in zip(allowed_calls, inner_results, strict=True):
                    results_by_index[index] = result
                    self.gate.record_tool_result(str(tc.function), dict(tc.args), _tool_result_text(result))

            ordered_results = [results_by_index[index] for index in range(len(tool_calls))]
            return query, runtime, env, [*messages, *ordered_results], extra_args

    return MellynGuardedToolsExecutor(gate)
