"""
Post-incident forensic timeline reconstructor (`mellyn-ir`).

Strict DAG invariant: imports ONLY from `mellyn.core` and `mellyn.ir_lab` (+ stdlib / pydantic).
Always verifies the `audit.jsonl` cryptographic hash chain BEFORE reconstructing any incident timeline.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mellyn.core.audit import EMPTY_JSON_OBJECT_SHA256, LedgerAnchor, redact_core_secrets
from mellyn.core.normalize import is_invisible_codepoint
from mellyn.core.schemas import (
    AAD_CONTAINMENT_CONFIRMED_RULE_ID,
    SESSION_STARTED_RULE_ID,
    LedgerSource,
    Severity,
    Zone,
    ZoneEvent,
)
from mellyn.ir_lab.verify_chain import ChainVerificationReport, read_and_verify_chain

_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

_MD_UNSAFE_CHAR_RE = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")
_MD_ESCAPES = str.maketrans(
    {
        "\\": "\\\\",
        "`": "\\`",
        "[": "\\[",
        "]": "\\]",
        "|": "\\|",
        "<": "&lt;",
        ">": "&gt;",
    }
)


def _md(value: object) -> str:
    """
    Render a ledger value as inert Markdown text. Ids, tool names, actions and reasons can carry attacker-chosen
    text; unescaped, a `|` or newline would forge table rows and markup could hide or restyle findings. Control and
    invisible characters are shown as `\\uXXXX` escapes instead.
    """
    text = "-" if value is None else str(value)
    text = "".join(f"\\u{ord(ch):04x}" if is_invisible_codepoint(ch) else ch for ch in text)
    text = _MD_UNSAFE_CHAR_RE.sub(lambda m: f"\\u{ord(m.group()):04x}", text)
    return text.translate(_MD_ESCAPES)


def _code(value: object) -> str:
    """
    Render a value as an inline code span when it cannot break out of one (no backtick, control or invisible
    characters); otherwise fall back to escaped plain text. Only for values outside the table, where `|` is harmless.
    """
    text = "-" if value is None else str(value)
    if "`" in text or _MD_UNSAFE_CHAR_RE.search(text) or any(is_invisible_codepoint(ch) for ch in text):
        return _md(text)
    return f"`{text}`"


REASON_CODE_MAP: dict[str, str] = {
    "airlock.agbom_pin_mismatch": "AGBOM_HASH_MISMATCH",
    "airlock.agbom_manifest_mismatch": "AGBOM_HASH_MISMATCH",
    "airlock.agbom_unpinned_tool": "AGBOM_UNPINNED_TOOL",
    "airlock.invisible_unicode_injection": "INVISIBLE_UNICODE_INJECTION",
    "airlock.instructions_pin_mismatch": "INSTRUCTIONS_PIN_MISMATCH",
    "airlock.unsolicited_response_id": "UNSOLICITED_RPC_ID",
    "airlock.invalid_tools_list_manifest": "INVALID_TOOLS_LIST_MANIFEST",
    "egress.canary_exfiltration": "CANARY_EXFILTRATION",
    "egress.response_canary_detected": "CANARY_EXFILTRATION",
}


def map_reason_code(rule_id: str) -> str:
    """Map an internal `rule_id` to a stable incident-response `reason_code`."""
    mapped = REASON_CODE_MAP.get(rule_id)
    if mapped is not None:
        return mapped
    return rule_id.rsplit(".", 1)[-1].upper()


class TimelineEvent(BaseModel):
    """Sanitized chronological timeline entry reconstructed from a verified `AuditLedgerEntry`."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    seq: int = Field(ge=0)
    timestamp_utc: str
    session_id: str
    zone: Zone
    action: str
    severity: Severity
    verdict_allow: bool
    rule_id: str
    reason_code: str
    reason: str
    tool_name: str | None = None
    rpc_id: int | str | None = None
    artifact_sha256: str


class TerminalTrigger(BaseModel):
    """Terminal `AAD_FIRE` event metadata surfaced at the top level for automated scoring and triage."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    seq: int = Field(ge=0)
    timestamp_utc: str
    session_id: str
    zone: Zone
    action: str
    rule_id: str
    reason_code: str
    rpc_id: int | str | None = None
    tool_name: str | None = None
    artifact_sha256: str
    redacted_summary: str
    trigger_event_id: str | None = None
    containment_confirmed: bool = False
    containment_seq: int | None = None


class SessionTimeline(BaseModel):
    """Per-session chronological reconstruction highlighting zone transitions, precursors, and terminal trigger."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    session_id: str
    event_count: int = Field(ge=0)
    zones_traversed: list[Zone] = Field(default_factory=list)
    zone_transitions: list[str] = Field(default_factory=list)
    block_precursors: list[TimelineEvent] = Field(default_factory=list)
    terminal_event: TerminalTrigger | None = None
    events: list[TimelineEvent] = Field(default_factory=list)
    # From the session's `airlock.session_started` event; None for ledgers written before sessions recorded it.
    enforcement_mode: Literal["enforce", "observe"] | None = None


class IncidentReport(BaseModel):
    """Deterministic post-incident forensic report produced by `mellyn-ir`."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    status: Literal[
        "CLEAN",
        "BLOCKED_ACTIVITY",
        "OBSERVED_VIOLATIONS",
        "AAD_CONTAINED",
        "AAD_TRIGGERED_UNCONFIRMED",
        "INTEGRITY_COMPROMISED",
    ]
    chain_valid: bool
    verification: ChainVerificationReport
    session_count: int = Field(ge=0)
    total_events: int = Field(ge=0)
    unconfirmed_aad_triggers: int = Field(default=0, ge=0)
    observed_aad_count: int = Field(default=0, ge=0)
    observed_block_count: int = Field(default=0, ge=0)
    sessions: list[SessionTimeline] = Field(default_factory=list)
    terminal_event: TerminalTrigger | None = None


@dataclass(frozen=True)
class _ParsedRecord:
    seq: int
    session_id: str
    timestamp_utc: str
    zone: Zone
    action: str
    verdict_allow: bool
    severity: Severity
    rule_id: str
    reason: str
    tool_name: str | None
    rpc_id: int | str | None
    artifact_sha256: str
    event_id: str
    enforcement_mode: Literal["enforce", "observe"] | None
    is_observed: bool
    trigger_event_id: str | None


def _parse_airlock_record(seq: int, ev_raw: dict[str, Any]) -> _ParsedRecord:
    ev = ZoneEvent.model_validate(ev_raw)
    raw_sid = ev.metadata.get("session_id")
    if isinstance(raw_sid, str) and raw_sid:
        sid = raw_sid
    elif ev.rule_id == "core.ledger_rotated":
        sid = "system"
    else:
        sid = "default"
    mode_raw = ev.metadata.get("enforcement_mode")
    enf_mode: Literal["enforce", "observe"] | None = (
        cast(Literal["enforce", "observe"], mode_raw) if mode_raw in ("enforce", "observe") else None
    )
    trig = ev.metadata.get("trigger_event_id")
    return _ParsedRecord(
        seq=seq,
        session_id=sid,
        timestamp_utc=ev.timestamp_utc,
        zone=ev.zone,
        action=ev.action,
        verdict_allow=ev.verdict_allow,
        severity=ev.severity,
        rule_id=ev.rule_id,
        reason=redact_core_secrets(ev.reason),
        tool_name=ev.tool_name,
        rpc_id=ev.request_id,
        artifact_sha256=ev.artifact_sha256,
        event_id=ev.event_id,
        enforcement_mode=enf_mode,
        is_observed=enf_mode == "observe",
        trigger_event_id=trig if isinstance(trig, str) else None,
    )


def _gateway_decision_mapping(
    decision: str, enf_mode: Literal["enforce", "observe"] | None
) -> tuple[Severity, bool, bool]:
    if decision == "allow":
        return "ALLOW", True, False
    if decision in ("tainted", "legacy_log_rotated", "v1_log_rotated"):
        return "INFO", True, False
    if decision == "require_approval":
        return "WARN", False, False
    if decision in ("deny", "blocked_egress", "blocked_listing"):
        return "BLOCK", False, False
    if decision in ("observed_block", "observed_hidden_unicode", "observed_require_approval"):
        return "BLOCK", False, True
    if decision == "aad_fire":
        return "AAD_FIRE", False, False
    if decision == "observed_aad":
        return "AAD_FIRE", False, True
    if decision.startswith("observed_") and enf_mode == "observe":
        return "BLOCK", False, True
    return "BLOCK", False, False


def _parse_gateway_record(seq: int, source: LedgerSource, ev_raw: dict[str, Any]) -> _ParsedRecord:
    raw_sid = ev_raw.get("session_id")
    sid = raw_sid if (isinstance(raw_sid, str) and raw_sid) else "default"
    event_type = str(ev_raw.get("event_type") or "authorization")
    decision = str(ev_raw.get("decision") or "deny")
    policy_id = ev_raw.get("policy_id")
    mode_raw = ev_raw.get("enforcement_mode")
    enf_mode: Literal["enforce", "observe"] | None = (
        cast(Literal["enforce", "observe"], mode_raw) if mode_raw in ("enforce", "observe") else None
    )
    severity, verdict_allow, is_observed = _gateway_decision_mapping(decision, enf_mode)

    zone: Zone
    if event_type == "ledger_rotated":
        zone = "core"
    elif event_type == "containment" and policy_id == "scanner.egress":
        zone = "egress"
    elif source == "authorizer":
        zone = "authorizer"
    else:
        zone = "gateway"

    rule_id = (
        f"{policy_id}.{decision}" if isinstance(policy_id, str) and policy_id else f"{source}.{event_type}.{decision}"
    )
    reasons = ev_raw.get("reasons")
    raw_reason = "; ".join(str(r) for r in reasons) if isinstance(reasons, list) and reasons else decision
    raw_sha = ev_raw.get("args_sha256")
    art_sha = (
        raw_sha
        if (isinstance(raw_sha, str) and _SHA256_HEX_RE.fullmatch(raw_sha) is not None)
        else EMPTY_JSON_OBJECT_SHA256
    )
    tool_raw = ev_raw.get("tool_name")
    return _ParsedRecord(
        seq=seq,
        session_id=sid,
        timestamp_utc=str(ev_raw.get("timestamp") or ""),
        zone=zone,
        action=event_type,
        verdict_allow=verdict_allow,
        severity=severity,
        rule_id=rule_id,
        reason=redact_core_secrets(raw_reason),
        tool_name=tool_raw if isinstance(tool_raw, str) else None,
        rpc_id=None,
        artifact_sha256=art_sha,
        event_id=str(ev_raw.get("audit_id") or f"gw-{seq}"),
        enforcement_mode=enf_mode,
        is_observed=is_observed,
        trigger_event_id=None,
    )


def _parse_verified_records(raw_bytes: bytes) -> list[_ParsedRecord]:
    """Parse verified bytes across v2 (Airlock/Gateway/Authorizer), v1 Airlock, and v1 Gateway ledgers."""
    records: list[_ParsedRecord] = []
    for line in raw_bytes.split(b"\n"):
        if not line:
            continue
        obj = json.loads(line.decode("utf-8"))
        if not isinstance(obj, dict):
            raise ValueError("Verified ledger line is not a JSON object.")
        seq = int(obj["seq"])
        if obj.get("schema_version") == 2:
            source = cast(LedgerSource, obj["source"])
            event_obj = obj["event"]
            if not isinstance(event_obj, dict):
                raise ValueError("Verified v2 event must be a JSON object.")
            if source == "airlock":
                records.append(_parse_airlock_record(seq, event_obj))
            else:
                records.append(_parse_gateway_record(seq, source, event_obj))
        elif "event" in obj:
            event_obj = obj["event"]
            if not isinstance(event_obj, dict):
                raise ValueError("Verified v1 Airlock event must be a JSON object.")
            records.append(_parse_airlock_record(seq, event_obj))
        else:
            records.append(_parse_gateway_record(seq, "gateway", obj))
    return records


def reconstruct_incident(path: Path, *, anchor: LedgerAnchor | None = None) -> IncidentReport:
    """
    Step 1: Verify the `audit.jsonl` hash chain fail-closed (v2, v1 Airlock, or v1 Gateway). If compromised,
    abort reconstruction and return `status="INTEGRITY_COMPROMISED"`.
    Step 2: Group verified events by `session_id`, recording zone transitions, `BLOCK` precursors, and
    `AAD_FIRE` containment state.
    """
    verification, raw_bytes = read_and_verify_chain(path, anchor=anchor)
    records: list[_ParsedRecord] = []
    if verification.valid and raw_bytes is not None:
        try:
            records = _parse_verified_records(raw_bytes)
        except (UnicodeDecodeError, ValueError, KeyError, TypeError, ValidationError):
            verification = verification.model_copy(
                update={"valid": False, "reason": "Verified ledger bytes could not be parsed."}
            )
    if not verification.valid:
        return IncidentReport(
            status="INTEGRITY_COMPROMISED",
            chain_valid=False,
            verification=verification,
            session_count=0,
            total_events=0,
            unconfirmed_aad_triggers=0,
            observed_aad_count=0,
            observed_block_count=0,
            sessions=[],
            terminal_event=None,
        )

    grouped: dict[str, list[_ParsedRecord]] = {}
    for rec in records:
        grouped.setdefault(rec.session_id, []).append(rec)

    sessions: list[SessionTimeline] = []
    all_aad_triggers: list[TerminalTrigger] = []
    saw_enforced_block = False
    observed_aad_count = 0
    observed_block_count = 0

    for sid, sid_records in grouped.items():
        zones_traversed: list[Zone] = []
        zone_transitions: list[str] = []
        block_precursors: list[TimelineEvent] = []
        events: list[TimelineEvent] = []
        aad_triggers: list[TerminalTrigger] = []
        aad_index_by_id: dict[str, int] = {}
        prev_zone: Zone | None = None
        session_mode: Literal["enforce", "observe"] | None = None

        for rec in sid_records:
            reason_code = map_reason_code(rec.rule_id)
            if rec.rule_id == SESSION_STARTED_RULE_ID and rec.enforcement_mode is not None:
                session_mode = rec.enforcement_mode
            elif (
                rec.zone in ("gateway", "egress", "authorizer")
                and sid != "system"
                and session_mode is None
                and rec.enforcement_mode is not None
            ):
                session_mode = rec.enforcement_mode

            t_ev = TimelineEvent(
                seq=rec.seq,
                timestamp_utc=rec.timestamp_utc,
                session_id=sid,
                zone=rec.zone,
                action=rec.action,
                severity=rec.severity,
                verdict_allow=rec.verdict_allow,
                rule_id=rec.rule_id,
                reason_code=reason_code,
                reason=rec.reason,
                tool_name=rec.tool_name,
                rpc_id=rec.rpc_id,
                artifact_sha256=rec.artifact_sha256,
            )
            events.append(t_ev)

            if rec.zone not in zones_traversed:
                zones_traversed.append(rec.zone)
            if prev_zone is not None and prev_zone != rec.zone:
                zone_transitions.append(f"{prev_zone} -> {rec.zone}")
            prev_zone = rec.zone

            if rec.severity == "BLOCK":
                if rec.is_observed:
                    observed_block_count += 1
                else:
                    saw_enforced_block = True
                block_precursors.append(t_ev)
            elif rec.severity == "AAD_FIRE":
                if rec.is_observed:
                    observed_aad_count += 1
                else:
                    trigger = TerminalTrigger(
                        seq=rec.seq,
                        timestamp_utc=rec.timestamp_utc,
                        session_id=sid,
                        zone=rec.zone,
                        action=rec.action,
                        rule_id=rec.rule_id,
                        reason_code=reason_code,
                        rpc_id=rec.rpc_id,
                        tool_name=rec.tool_name,
                        artifact_sha256=rec.artifact_sha256,
                        redacted_summary=rec.reason,
                        trigger_event_id=rec.event_id,
                        containment_confirmed=False,
                        containment_seq=None,
                    )
                    aad_index_by_id[rec.event_id] = len(aad_triggers)
                    aad_triggers.append(trigger)
            elif rec.rule_id == AAD_CONTAINMENT_CONFIRMED_RULE_ID:
                ref_id = rec.trigger_event_id
                if isinstance(ref_id, str) and ref_id in aad_index_by_id:
                    idx = aad_index_by_id[ref_id]
                    existing = aad_triggers[idx]
                    if rec.seq > existing.seq and not existing.containment_confirmed:
                        aad_triggers[idx] = existing.model_copy(
                            update={"containment_confirmed": True, "containment_seq": rec.seq}
                        )

        session_terminal: TerminalTrigger | None = None
        if aad_triggers:
            unconfirmed_in_session = [t for t in aad_triggers if not t.containment_confirmed]
            session_terminal = unconfirmed_in_session[-1] if unconfirmed_in_session else aad_triggers[-1]
            all_aad_triggers.extend(aad_triggers)

        sessions.append(
            SessionTimeline(
                session_id=sid,
                event_count=len(events),
                zones_traversed=zones_traversed,
                zone_transitions=zone_transitions,
                block_precursors=block_precursors,
                terminal_event=session_terminal,
                events=events,
                enforcement_mode=session_mode,
            )
        )

    unconfirmed_triggers = [t for t in all_aad_triggers if not t.containment_confirmed]
    unconfirmed_count = len(unconfirmed_triggers)
    global_terminal: TerminalTrigger | None = (
        unconfirmed_triggers[-1] if unconfirmed_triggers else (all_aad_triggers[-1] if all_aad_triggers else None)
    )

    status: Literal[
        "CLEAN",
        "BLOCKED_ACTIVITY",
        "OBSERVED_VIOLATIONS",
        "AAD_CONTAINED",
        "AAD_TRIGGERED_UNCONFIRMED",
    ]
    if unconfirmed_count > 0:
        status = "AAD_TRIGGERED_UNCONFIRMED"
    elif all_aad_triggers:
        status = "AAD_CONTAINED"
    elif saw_enforced_block:
        status = "BLOCKED_ACTIVITY"
    elif observed_aad_count > 0 or observed_block_count > 0:
        status = "OBSERVED_VIOLATIONS"
    else:
        status = "CLEAN"

    return IncidentReport(
        status=status,
        chain_valid=True,
        verification=verification,
        session_count=len(sessions),
        total_events=len(records),
        unconfirmed_aad_triggers=unconfirmed_count,
        observed_aad_count=observed_aad_count,
        observed_block_count=observed_block_count,
        sessions=sessions,
        terminal_event=global_terminal,
    )


def render_markdown(report: IncidentReport) -> str:
    """
    Format an `IncidentReport` as a forensic Markdown summary. Every value that comes from the ledger goes through
    `_md()`, so attacker-influenced text (ids, tool names, actions, reasons) cannot add rows or markup.
    """
    v = report.verification
    if not report.chain_valid:
        lines = [
            "# INTEGRITY_COMPROMISED",
            "",
            f"- **Ledger**: {_code(v.ledger_path)}",
            f"- **First Invalid Seq**: {_code(v.first_invalid_seq)}",
            f"- **First Invalid Line**: {_code(v.first_invalid_line)}",
            f"- **Reason**: {_md(v.reason)}",
        ]
        return "\n".join(lines)

    tail_note = (
        "checked against the supplied anchor"
        if v.anchored
        else "NOT checked (no anchor supplied: entries deleted from the end would not be detected)"
    )
    lines = [
        f"# Mellyn Incident Reconstruction ({report.status})",
        "",
        f"- **Chain Integrity**: VALID (`{v.entry_count}` entries, tail {_code(f'seq={v.last_seq}')}, "
        f"{_code(f'hash={v.last_hash}')})",
        f"- **Tail truncation**: {tail_note}",
        f"- **Sessions**: `{report.session_count}`",
    ]
    if report.status == "AAD_TRIGGERED_UNCONFIRMED":
        lines.append(
            f"- **Containment**: UNCONFIRMED ({report.unconfirmed_aad_triggers} AAD_FIRE trigger(s) lack a matching "
            f"`{AAD_CONTAINMENT_CONFIRMED_RULE_ID}` completion receipt; direct downstream exit is not proven)"
        )
    elif report.status == "AAD_CONTAINED":
        lines.append("- **Containment**: CONFIRMED (matching post-reap completion receipt attests direct child exit)")
    if report.status == "OBSERVED_VIOLATIONS" or report.observed_aad_count > 0 or report.observed_block_count > 0:
        lines.append(
            f"- **Observed Violations (observe mode)**: `observed_aad_count={report.observed_aad_count}`, "
            f"`observed_block_count={report.observed_block_count}`"
        )

    if report.terminal_event is not None:
        term = report.terminal_event
        confirm_str = f"True (seq={term.containment_seq})" if term.containment_confirmed else "False (unconfirmed)"
        lines.extend(
            [
                "",
                "## Terminal AAD_FIRE Trigger",
                f"- **reason_code**: {_code(term.reason_code)} ({_code(term.rule_id)})",
                f"- **session_id**: {_code(term.session_id)} (`seq={term.seq}`)",
                f"- **rpc_id**: {_code(term.rpc_id)}",
                f"- **artifact_sha256**: {_code(term.artifact_sha256)}",
                f"- **containment_confirmed**: `{confirm_str}`",
                f"- **redacted_summary**: {_md(term.redacted_summary)}",
            ]
        )

    for sess in report.sessions:
        zones_str = ", ".join(sess.zones_traversed) if sess.zones_traversed else "none"
        trans_str = ", ".join(sess.zone_transitions) if sess.zone_transitions else "none"
        lines.extend(
            [
                "",
                f"## Session {_code(sess.session_id)} ({sess.event_count} events)",
                f"- **Zones Traversed**: {_md(zones_str)}",
                f"- **Zone Transitions**: {_md(trans_str)}",
                f"- **Mode**: {sess.enforcement_mode or 'unknown (no session_start record)'}",
                f"- **BLOCK Precursors**: {len(sess.block_precursors)}",
                "",
                "| Seq | Time (UTC) | Zone | Action | Severity | Reason Code | RPC ID | Tool |",
                "| --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for ev in sess.events:
            cells = (ev.seq, ev.timestamp_utc, ev.zone, ev.action, ev.severity, ev.reason_code, ev.rpc_id, ev.tool_name)
            lines.append("| " + " | ".join(_md(cell) for cell in cells) + " |")

    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mellyn-ir",
        description="Verify an audit.jsonl ledger hash chain and reconstruct chronological session timelines.",
    )
    parser.add_argument("ledger", type=Path, help="Path to audit.jsonl flight recorder ledger.")
    parser.add_argument("--json", action="store_true", help="Emit deterministic machine-readable JSON report.")
    parser.add_argument("--anchor-seq", type=int, default=None, help="Optional external anchor seq number.")
    parser.add_argument("--anchor-hash", default=None, help="Optional external anchor SHA-256 hex digest.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `mellyn-ir`."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    anchor: LedgerAnchor | None = None
    if args.anchor_seq is not None or args.anchor_hash is not None:
        if args.anchor_seq is None or args.anchor_hash is None:
            sys.stderr.write("mellyn-ir: --anchor-seq and --anchor-hash must be supplied together.\n")
            return 2
        anchor = (args.anchor_seq, args.anchor_hash)

    report = reconstruct_incident(args.ledger, anchor=anchor)
    if args.json:
        sys.stdout.write(
            json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        )
    else:
        sys.stdout.write(render_markdown(report) + "\n")
    return 0 if report.chain_valid else 2


__all__ = [
    "REASON_CODE_MAP",
    "IncidentReport",
    "SessionTimeline",
    "TerminalTrigger",
    "TimelineEvent",
    "main",
    "map_reason_code",
    "reconstruct_incident",
    "render_markdown",
]


if __name__ == "__main__":
    raise SystemExit(main())
