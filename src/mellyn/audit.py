"""Redacted, hash-chained structured audit logger wrapping the unified `mellyn.core.audit` v2 ledger."""

from __future__ import annotations

import hashlib
import json
import secrets
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import IO, Any, TextIO, cast

from mellyn.core.audit import (
    GENESIS_PREV_HASH as _CORE_GENESIS_PREV_HASH,
)
from mellyn.core.audit import (
    CoreAuditLedger,
    CoreLedgerVerification,
    LedgerAnchor,
    LedgerIntegrityError,
    encode_ledger_line,
    is_legacy_unchained_bytes,
    verify_ledger_file_core,
    verify_ledger_lines_core,
)
from mellyn.core.audit import (
    split_audit_lines as split_audit_lines,
)
from mellyn.core.scan import (
    SECRET_REDACTION_PATTERNS as SECRET_REDACTION_PATTERNS,
)
from mellyn.core.scan import redact_core_secrets
from mellyn.models import Decision, RiskTier, TaintSource, canonical_json, canonical_json_value, utc_now

GENESIS_PREV_HASH = _CORE_GENESIS_PREV_HASH
MAX_AUDIT_REASON_CHARS = 512
MAX_TAINT_ENTRY_CHARS = 256
EMPTY_ARGS_SHA256 = hashlib.sha256(b"{}").hexdigest()


class AuditChainError(RuntimeError):
    """Raised fail-closed when an audit log fails hash-chain verification or path safety."""


@dataclass(frozen=True)
class ChainVerificationResult:
    """Result of verifying a JSONL audit hash chain."""

    valid: bool
    entry_count: int
    last_seq: int | None
    last_hash: str
    first_invalid_line: int | None
    reason: str | None
    ledger_format: str | None = None


def redact_text(value: str) -> str:
    """Replace all known credential/token patterns (including encoded/escaped forms) and URL passwords."""
    return redact_core_secrets(value)


def hash_arguments(arguments: Any) -> str:
    """
    Deterministic SHA-256 digest of tool arguments, for correlating events without storing payloads.

    It is unsalted, so low-entropy arguments (a branch name, a short path) can be recovered by guessing.
    Treat the audit log as confidential, not as anonymized.
    """
    try:
        payload = canonical_json(arguments).encode("utf-8")
    except (TypeError, ValueError):
        try:
            payload = canonical_json_value(arguments).encode("utf-8")
        except (TypeError, ValueError):
            payload = f"invalid:{type(arguments).__name__}".encode("utf-8", errors="replace")
    return hashlib.sha256(payload).hexdigest()


def hash_untrusted_identifier(prefix: str, raw_value: str) -> str:
    """
    Deterministic bounded digest label for unrecognized caller-supplied identifiers (`session_id`,
    `tool_name`, `mcp_server`), preventing arbitrary caller text or secrets from entering JSONL while
    keeping repeated attempts correlatable.
    """
    digest = hashlib.sha256(f"{prefix}:{raw_value}".encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"{prefix}:{digest}"


def format_taint_entry(source: TaintSource, *, max_chars: int = MAX_TAINT_ENTRY_CHARS) -> str:
    """Redact and bound a single taint entry once so repeated decisions do not re-scan full text."""
    s_type = redact_text(source.source_type)[:64]
    s_origin = redact_text(source.origin)
    combined = f"{s_type}:{s_origin}"
    return combined[:max_chars]


def compute_audit_entry_hash(event_dict: Mapping[str, Any]) -> str:
    """Compute v1 gateway canonical SHA-256 hash over an `AuditEvent` dictionary excluding `entry_hash`."""
    body = {k: v for k, v in event_dict.items() if k != "entry_hash"}
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _to_chain_result(res: CoreLedgerVerification) -> ChainVerificationResult:
    return ChainVerificationResult(
        valid=res.valid,
        entry_count=res.entry_count,
        last_seq=res.last_seq,
        last_hash=res.last_hash if res.last_hash is not None else GENESIS_PREV_HASH,
        first_invalid_line=res.first_invalid_line,
        reason=res.reason,
        ledger_format=res.ledger_format,
    )


def verify_gateway_audit_lines(lines: Sequence[str], *, anchor: LedgerAnchor | None = None) -> ChainVerificationResult:
    """Verify hash-chain links across JSONL lines via the single `mellyn.core.audit` verifier."""
    return _to_chain_result(verify_ledger_lines_core(lines, anchor=anchor))


def verify_gateway_audit_file(path: Path, *, anchor: LedgerAnchor | None = None) -> ChainVerificationResult:
    """Verify hash-chain integrity on a ledger file on disk (fails closed on symlink/unreadable/missing files)."""
    if path.is_symlink() or path.parent.is_symlink():
        raise AuditChainError(f"Refusing symlink audit log path '{path}'.")
    if not path.is_file():
        raise AuditChainError(f"Audit log file does not exist: '{path}'.")
    res = verify_ledger_file_core(path, anchor=anchor)
    if not res.valid and res.reason and res.reason.startswith("Could not read audit ledger:"):
        raise AuditChainError(res.reason)
    return _to_chain_result(res)


def _is_legacy_unchained_log(path: Path) -> bool:
    """True only when `path` is a non-empty unchained pre-1.1 log with no chain or schema fields."""
    if path.is_symlink() or path.parent.is_symlink() or not path.is_file():
        return False
    try:
        return is_legacy_unchained_bytes(path.read_bytes())
    except OSError:
        return False


class _LedgerHandle:
    """File-like close/context-manager handle returned by `AuditLogger.open_chained()`."""

    def __init__(self, core: CoreAuditLedger) -> None:
        self._core = core

    @property
    def closed(self) -> bool:
        return self._core.closed

    def flush(self) -> None:
        self._core.flush()

    def close(self) -> None:
        self._core.close()

    def __enter__(self) -> _LedgerHandle:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


@dataclass(frozen=True)
class AuditEvent:
    """Structured, redacted, hash-chained audit record (never stores raw prompts or secret/canary values)."""

    audit_id: str
    timestamp: str
    session_id: str
    tool_name: str
    mcp_server: str | None
    decision: str
    risk_tier: str
    tainted: bool
    taint_sources: list[str]
    args_sha256: str
    reasons: list[str]
    policy_id: str | None
    grant_id: str | None
    event_type: str = "authorization"
    taint_count: int = 0
    seq: int = 0
    prev_hash: str = GENESIS_PREV_HASH
    entry_hash: str = ""
    enforcement_mode: str = "enforce"


def _gateway_event_payload(event: AuditEvent) -> dict[str, Any]:
    """Extract the `event` object stored inside a `schema_version = 2` gateway/authorizer envelope."""
    return {
        "audit_id": event.audit_id,
        "timestamp": event.timestamp,
        "session_id": event.session_id,
        "tool_name": event.tool_name,
        "mcp_server": event.mcp_server,
        "decision": event.decision,
        "risk_tier": event.risk_tier,
        "tainted": event.tainted,
        "taint_sources": list(event.taint_sources),
        "args_sha256": event.args_sha256,
        "reasons": list(event.reasons),
        "policy_id": event.policy_id,
        "grant_id": event.grant_id,
        "event_type": event.event_type,
        "taint_count": event.taint_count,
        "enforcement_mode": event.enforcement_mode,
    }


def _audit_event_from_core(
    *,
    seq: int,
    prev_hash: str,
    entry_hash: str,
    ev: Mapping[str, Any],
) -> AuditEvent:
    return AuditEvent(
        audit_id=str(ev["audit_id"]),
        timestamp=str(ev["timestamp"]),
        session_id=str(ev["session_id"]),
        tool_name=str(ev["tool_name"]),
        mcp_server=cast(str | None, ev.get("mcp_server")),
        decision=str(ev["decision"]),
        risk_tier=str(ev["risk_tier"]),
        tainted=bool(ev["tainted"]),
        taint_sources=[str(item) for item in ev.get("taint_sources", ())],
        args_sha256=str(ev["args_sha256"]),
        reasons=[str(item) for item in ev.get("reasons", ())],
        policy_id=cast(str | None, ev.get("policy_id")),
        grant_id=cast(str | None, ev.get("grant_id")),
        event_type=str(ev.get("event_type", "authorization")),
        taint_count=int(ev.get("taint_count", 0)),
        seq=seq,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
        enforcement_mode=str(ev.get("enforcement_mode", "enforce")),
    )


class AuditLogger:
    """
    Redacted, hash-chained `schema_version = 2` audit sink backed by `CoreAuditLedger`.

    Keeps the most recent events in memory and persists each record with symlink refusal, `0o600` file
    creation, cross-process locking, `fsync`, zero-canary assertion before flush, and line-break escaping.
    """

    def __init__(
        self,
        sink: TextIO | None = None,
        max_in_memory: int = 10_000,
        *,
        canary_tokens: Sequence[str] = (),
        start_seq: int = 0,
        prev_hash: str = GENESIS_PREV_HASH,
        enforcement_mode: str = "enforce",
        source: str = "gateway",
        _core: CoreAuditLedger | None = None,
    ) -> None:
        self._events: deque[AuditEvent] = deque(maxlen=max_in_memory)
        self._lines: deque[str] = deque(maxlen=max_in_memory)
        self._canary_tokens = tuple(t for t in canary_tokens if t)
        self._enforcement_mode = enforcement_mode
        self._source = source
        self._core = (
            _core
            if _core is not None
            else CoreAuditLedger(
                sink=sink,
                source=source,
                canary_tokens=self._canary_tokens,
                start_seq=start_seq,
                prev_hash=prev_hash,
            )
        )
        # Set by open_chained() when it moved an existing pre-chain or v1 ledger aside; callers report it.
        self.rotated_legacy_path: Path | None = self._core.rotated_legacy_path
        self.rotated_legacy_format: str | None = self._core.rotated_legacy_format
        if self._core.rotation_entry is not None:
            rot = self._core.rotation_entry
            rot_event = _audit_event_from_core(
                seq=rot.seq,
                prev_hash=rot.prev_hash,
                entry_hash=rot.entry_hash,
                ev=rot.event,
            )
            self._events.append(rot_event)
            self._lines.append(
                encode_ledger_line(
                    {
                        "schema_version": rot.schema_version,
                        "seq": rot.seq,
                        "prev_hash": rot.prev_hash,
                        "entry_hash": rot.entry_hash,
                        "source": rot.source,
                        "event": rot.event,
                    }
                ).decode("utf-8")
            )

    @classmethod
    def open_chained(
        cls,
        path: Path,
        *,
        canary_tokens: Sequence[str] = (),
        enforcement_mode: str = "enforce",
        anchor: LedgerAnchor | None = None,
        source: str = "gateway",
    ) -> tuple[AuditLogger, IO[str]]:
        """
        Verify any existing ledger at `path` fail-closed (rotating unchained or v1 logs aside), then open for
        locked `fsync` appends (`0o600` on POSIX, `schema_version = 2`).
        """

        def _rotation_event(rotated: Path, rotated_format: str, rotated_sha: str) -> dict[str, Any]:
            if rotated_format == "pre_chain":
                decision = "legacy_log_rotated"
                reason = f"Moved the unchained pre-1.1 audit log to '{rotated.name}' and started a new v2 chain."
            else:
                decision = "v1_log_rotated"
                reason = f"Moved the {rotated_format} audit log to '{rotated.name}' and started a new v2 chain."
            return {
                "audit_id": f"aud_{secrets.token_hex(12)}",
                "timestamp": utc_now().isoformat(),
                "session_id": "system",
                "tool_name": "audit/ledger",
                "mcp_server": None,
                "decision": decision,
                "risk_tier": RiskTier.LOW.value,
                "tainted": False,
                "taint_sources": [],
                "args_sha256": rotated_sha,
                "reasons": [reason],
                "policy_id": "audit.migration",
                "grant_id": None,
                "event_type": "ledger_rotated",
                "taint_count": 0,
                "enforcement_mode": enforcement_mode,
            }

        try:
            core = CoreAuditLedger(
                path,
                source=source,
                canary_tokens=canary_tokens,
                anchor=anchor,
                create_empty=True,
                now_fn=utc_now,
                rotation_event_factory=_rotation_event,
                keep_open=True,  # closed through the returned handle
            )
        except (LedgerIntegrityError, OSError) as exc:
            raise AuditChainError(str(exc)) from exc

        logger = cls(
            canary_tokens=canary_tokens,
            enforcement_mode=enforcement_mode,
            source=source,
            _core=core,
        )
        return logger, cast(IO[str], _LedgerHandle(core))

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    @property
    def head(self) -> LedgerAnchor | None:
        return self._core.head

    def _scrub(self, text: str) -> str:
        return redact_core_secrets(text, canary_tokens=self._canary_tokens)

    def _emit(self, event: AuditEvent) -> AuditEvent:
        redacted_reasons = [self._scrub(reason)[:MAX_AUDIT_REASON_CHARS] for reason in event.reasons]
        redacted_taints = [self._scrub(item)[:MAX_TAINT_ENTRY_CHARS] for item in event.taint_sources]
        redacted_session = self._scrub(event.session_id)[:128]
        redacted_tool = self._scrub(event.tool_name)[:128]
        redacted_server = self._scrub(event.mcp_server)[:128] if event.mcp_server is not None else None

        draft = replace(
            event,
            session_id=redacted_session,
            tool_name=redacted_tool,
            mcp_server=redacted_server,
            taint_sources=redacted_taints,
            reasons=redacted_reasons,
            enforcement_mode=event.enforcement_mode or self._enforcement_mode,
        )
        try:
            core_entry = self._core.append(_gateway_event_payload(draft), source=self._source)
        except (LedgerIntegrityError, OSError) as exc:
            raise AuditChainError(str(exc)) from exc

        final = _audit_event_from_core(
            seq=core_entry.seq,
            prev_hash=core_entry.prev_hash,
            entry_hash=core_entry.entry_hash,
            ev=core_entry.event,
        )
        self._events.append(final)
        self._lines.append(
            encode_ledger_line(
                {
                    "schema_version": core_entry.schema_version,
                    "seq": core_entry.seq,
                    "prev_hash": core_entry.prev_hash,
                    "entry_hash": core_entry.entry_hash,
                    "source": core_entry.source,
                    "event": core_entry.event,
                }
            ).decode("utf-8")
        )
        return final

    def record(
        self,
        *,
        session_id: str,
        tool_name: str,
        mcp_server: str | None,
        arguments: dict[str, Any],
        decision: Decision,
        risk_tier: RiskTier,
        tainted: bool,
        taint_sources: tuple[TaintSource | str, ...],
        reasons: tuple[str, ...],
        policy_id: str | None = None,
        grant_id: str | None = None,
        taint_count: int | None = None,
        session_known: bool = True,
        tool_known: bool = True,
        server_known: bool = True,
    ) -> AuditEvent:
        safe_session = (
            redact_text(session_id)[:128] if session_known else hash_untrusted_identifier("unknown_ses", session_id)
        )
        safe_tool = (
            redact_text(tool_name)[:128] if tool_known else hash_untrusted_identifier("untrusted_tool", tool_name)
        )
        if mcp_server is None:
            safe_server: str | None = None
        elif server_known:
            safe_server = redact_text(mcp_server)[:128]
        else:
            safe_server = hash_untrusted_identifier("untrusted_srv", mcp_server)

        rendered_taints = [item if isinstance(item, str) else format_taint_entry(item) for item in taint_sources]
        effective_count = len(rendered_taints) if taint_count is None else taint_count

        event = AuditEvent(
            audit_id=f"aud_{secrets.token_hex(12)}",
            timestamp=utc_now().isoformat(),
            session_id=safe_session,
            tool_name=safe_tool,
            mcp_server=safe_server,
            decision=decision.value,
            risk_tier=risk_tier.value,
            tainted=tainted,
            taint_sources=rendered_taints,
            args_sha256=hash_arguments(arguments),
            reasons=[redact_text(reason)[:MAX_AUDIT_REASON_CHARS] for reason in reasons],
            policy_id=policy_id,
            grant_id=grant_id,
            event_type="authorization",
            taint_count=effective_count,
            enforcement_mode=self._enforcement_mode,
        )
        return self._emit(event)

    def record_taint(
        self,
        *,
        session_id: str,
        taint_count: int,
        taint_sources: tuple[str, ...],
        reason: str = "Session tainted by untrusted external content.",
    ) -> AuditEvent:
        """Emit a standalone durable structured record when untrusted content taints a session."""
        event = AuditEvent(
            audit_id=f"aud_{secrets.token_hex(12)}",
            timestamp=utc_now().isoformat(),
            session_id=redact_text(session_id)[:128],
            tool_name="session/taint",
            mcp_server=None,
            decision="tainted",
            risk_tier=RiskTier.LOW.value,
            tainted=True,
            taint_sources=list(taint_sources),
            args_sha256=EMPTY_ARGS_SHA256,
            reasons=[redact_text(reason)[:MAX_AUDIT_REASON_CHARS]],
            policy_id=None,
            grant_id=None,
            event_type="taint",
            taint_count=taint_count,
            enforcement_mode=self._enforcement_mode,
        )
        return self._emit(event)

    def record_containment(
        self,
        *,
        session_id: str,
        tool_name: str,
        mcp_server: str | None,
        decision: str,
        reasons: tuple[str, ...],
        payload: Any = None,
        tainted: bool = False,
        taint_count: int = 0,
        taint_sources: tuple[str, ...] = (),
        enforcement_mode: str | None = None,
        policy_id: str = "scanner.egress",
    ) -> AuditEvent:
        """Emit a structured redacted record when the egress scanner triggers containment or observation."""
        event = AuditEvent(
            audit_id=f"aud_{secrets.token_hex(12)}",
            timestamp=utc_now().isoformat(),
            session_id=redact_text(session_id)[:128],
            tool_name=redact_text(tool_name)[:128],
            mcp_server=redact_text(mcp_server)[:128] if mcp_server is not None else None,
            decision=decision,
            risk_tier=RiskTier.HIGH.value,
            tainted=tainted,
            taint_sources=list(taint_sources),
            args_sha256=EMPTY_ARGS_SHA256 if payload is None else hash_arguments(payload),
            reasons=[redact_text(r)[:MAX_AUDIT_REASON_CHARS] for r in reasons],
            policy_id=policy_id,
            grant_id=None,
            event_type="containment",
            taint_count=taint_count,
            enforcement_mode=enforcement_mode or self._enforcement_mode,
        )
        return self._emit(event)

    def to_jsonl(self) -> str:
        """Export all recorded v2 audit entries as newline-delimited JSON."""
        return "\n".join(self._lines)
