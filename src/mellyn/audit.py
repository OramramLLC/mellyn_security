"""Redacted, hash-chained structured audit logger for Mellyn Security authorization decisions."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import IO, Any, TextIO

from mellyn.models import Decision, RiskTier, TaintSource, canonical_json, canonical_json_value, utc_now
from mellyn.scanner import (
    _URL_USERINFO_SECRET_RE,
    redact_canaries_in_text,
)
from mellyn.scanner import (
    SECRET_REDACTION_PATTERNS as SECRET_REDACTION_PATTERNS,
)

GENESIS_PREV_HASH = "0" * 64
MAX_AUDIT_REASON_CHARS = 512
MAX_TAINT_ENTRY_CHARS = 256
EMPTY_ARGS_SHA256 = hashlib.sha256(b"{}").hexdigest()


class AuditChainError(RuntimeError):
    """Raised fail-closed when an audit log fails hash-chain verification or path safety."""


@dataclass(frozen=True)
class ChainVerificationResult:
    """Result of verifying a gateway JSONL hash chain."""

    valid: bool
    entry_count: int
    last_seq: int | None
    last_hash: str
    first_invalid_line: int | None
    reason: str | None


def redact_text(value: str) -> str:
    """Replace known credential/token patterns and embedded URL passwords with [REDACTED_SECRET]."""
    sanitized = _URL_USERINFO_SECRET_RE.sub(r"\1[REDACTED_SECRET]\2", value)
    for pattern in SECRET_REDACTION_PATTERNS:
        sanitized = pattern.sub("[REDACTED_SECRET]", sanitized)
    return sanitized


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
    """Compute canonical SHA-256 hash over an `AuditEvent` dictionary excluding `entry_hash`."""
    body = {k: v for k, v in event_dict.items() if k != "entry_hash"}
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


# Characters Python's str.splitlines() treats as line breaks but json.dumps(ensure_ascii=False) leaves raw. Written
# unescaped, one of them inside a logged string split that record in two on read, so the whole ledger failed
# verification and the next start refused. They are escaped on write, and ledgers are split on "\n" only.
_LINE_BREAK_ESCAPES = str.maketrans({"\u0085": "\\u0085", " ": "\\u2028", " ": "\\u2029"})
_CHAIN_FIELDS = ("seq", "prev_hash", "entry_hash")


def _dump_audit_line(record: Mapping[str, Any]) -> str:
    """One JSON line for the ledger. Escaping the line-break characters changes the text, not the parsed value."""
    return json.dumps(record, sort_keys=True, ensure_ascii=False).translate(_LINE_BREAK_ESCAPES)


def split_audit_lines(text: str) -> list[str]:
    """Split a ledger into records on "\\n" only; the verifier strips any trailing "\\r"."""
    return text.split("\n")


def _strict_json_loads(raw_line: str) -> Any:
    def _reject_dup_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in pairs:
            if k in out:
                raise ValueError(f"Duplicate JSON key '{k}' in audit entry.")
            out[k] = v
        return out

    return json.loads(raw_line, object_pairs_hook=_reject_dup_keys)


def verify_gateway_audit_lines(lines: Sequence[str]) -> ChainVerificationResult:
    """Verify sequential `seq`, `prev_hash`, and `entry_hash` links across gateway JSONL lines."""
    expected_seq = 0
    expected_prev = GENESIS_PREV_HASH
    entry_count = 0

    for line_no, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue
        try:
            obj = _strict_json_loads(stripped)
        except (ValueError, json.JSONDecodeError) as exc:
            return ChainVerificationResult(
                valid=False,
                entry_count=entry_count,
                last_seq=expected_seq - 1 if entry_count else None,
                last_hash=expected_prev,
                first_invalid_line=line_no,
                reason=f"Malformed JSON or duplicate key on line {line_no}: {exc}",
            )
        if not isinstance(obj, dict):
            return ChainVerificationResult(
                valid=False,
                entry_count=entry_count,
                last_seq=expected_seq - 1 if entry_count else None,
                last_hash=expected_prev,
                first_invalid_line=line_no,
                reason=f"Audit entry on line {line_no} is not a JSON object.",
            )

        seq = obj.get("seq")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq != expected_seq:
            return ChainVerificationResult(
                valid=False,
                entry_count=entry_count,
                last_seq=expected_seq - 1 if entry_count else None,
                last_hash=expected_prev,
                first_invalid_line=line_no,
                reason=f"Sequence mismatch on line {line_no}: expected seq={expected_seq}, got {seq!r}.",
            )

        prev_hash = obj.get("prev_hash")
        if not isinstance(prev_hash, str) or not hmac.compare_digest(prev_hash, expected_prev):
            return ChainVerificationResult(
                valid=False,
                entry_count=entry_count,
                last_seq=expected_seq - 1 if entry_count else None,
                last_hash=expected_prev,
                first_invalid_line=line_no,
                reason=f"Chain link mismatch on line {line_no}: prev_hash does not match previous entry_hash.",
            )

        entry_hash = obj.get("entry_hash")
        expected_hash = compute_audit_entry_hash(obj)
        if not isinstance(entry_hash, str) or not hmac.compare_digest(entry_hash, expected_hash):
            return ChainVerificationResult(
                valid=False,
                entry_count=entry_count,
                last_seq=expected_seq - 1 if entry_count else None,
                last_hash=expected_prev,
                first_invalid_line=line_no,
                reason=f"Entry digest mismatch on line {line_no} (tampered record).",
            )

        entry_count += 1
        expected_seq += 1
        expected_prev = entry_hash

    return ChainVerificationResult(
        valid=True,
        entry_count=entry_count,
        last_seq=expected_seq - 1 if entry_count else None,
        last_hash=expected_prev,
        first_invalid_line=None,
        reason=None,
    )


def verify_gateway_audit_file(path: Path) -> ChainVerificationResult:
    """Verify hash-chain integrity on a gateway JSONL file on disk (fails closed on unreadable/missing files)."""
    if path.is_symlink() or path.parent.is_symlink():
        raise AuditChainError(f"Refusing symlink audit log path '{path}'.")
    if not path.is_file():
        raise AuditChainError(f"Audit log file does not exist: '{path}'.")
    try:
        raw_lines = split_audit_lines(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        raise AuditChainError(f"Unable to read audit log '{path}': {exc}") from exc
    return verify_gateway_audit_lines(raw_lines)


def _is_legacy_unchained_log(path: Path) -> bool:
    """
    True only for a log written before the hash chain existed: every record is a JSON object and none carries any
    chain field. A file with even one chained record, or anything unparseable, is not legacy.
    """
    try:
        lines = split_audit_lines(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError):
        return False
    records = 0
    for raw in lines:
        stripped = raw.strip()
        if not stripped:
            continue
        try:
            obj = _strict_json_loads(stripped)
        except (ValueError, json.JSONDecodeError):
            return False
        if not isinstance(obj, dict) or any(field in obj for field in _CHAIN_FIELDS):
            return False
        records += 1
    return records > 0


def _rotate_legacy_log(path: Path) -> Path:
    """Rename a legacy log to `<name>.pre-chain-<UTC time>[-N]` in the same folder, never overwriting anything."""
    stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    target = path.with_name(f"{path.name}.pre-chain-{stamp}")
    counter = 1
    while target.exists() or target.is_symlink():
        target = path.with_name(f"{path.name}.pre-chain-{stamp}-{counter}")
        counter += 1
    try:
        path.rename(target)
    except OSError as exc:
        raise AuditChainError(f"Could not move the unchained audit log '{path}' aside: {exc}") from exc
    return target


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


class AuditLogger:
    """
    Redacted, hash-chained audit sink. Keeps the most recent events in memory and, when `sink` is given,
    appends each event as one JSON line and flushes. The gateway points `sink` at a dedicated file: never at a
    stream a downstream process can also write to (such as a shared stderr), or entries can be forged.
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
    ) -> None:
        self._events: deque[AuditEvent] = deque(maxlen=max_in_memory)
        self._sink = sink
        self._lock = threading.Lock()
        self._canary_tokens = tuple(t for t in canary_tokens if t)
        self._next_seq = start_seq
        self._last_hash = prev_hash
        self._enforcement_mode = enforcement_mode
        # Set by open_chained() when it moved an unchained 1.0.0 log aside; callers report it to the operator.
        self.rotated_legacy_path: Path | None = None

    @classmethod
    def open_chained(
        cls,
        path: Path,
        *,
        canary_tokens: Sequence[str] = (),
        enforcement_mode: str = "enforce",
    ) -> tuple[AuditLogger, IO[str]]:
        """
        Verify any existing ledger at `path` fail-closed, then open for append (mode 0600 on POSIX).
        """
        if path.is_symlink() or path.parent.is_symlink():
            raise AuditChainError(f"Refusing symlink audit log path '{path}'.")
        if path.exists() and path.is_dir():
            raise AuditChainError(f"Audit log path '{path}' is a directory.")

        start_seq = 0
        prev_hash = GENESIS_PREV_HASH
        rotated_from: Path | None = None
        if path.exists():
            res = verify_gateway_audit_file(path)
            if not res.valid:
                if not _is_legacy_unchained_log(path):
                    raise AuditChainError(res.reason or f"Existing audit log '{path}' failed hash-chain check.")
                # A 1.0.0 log has no chain to verify, so it cannot be appended to. Keep it, unchanged, beside the new
                # ledger. Anything partly chained is not legacy and still fails closed above.
                rotated_from = _rotate_legacy_log(path)
            elif res.last_seq is not None:
                start_seq = res.last_seq + 1
                prev_hash = res.last_hash

        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        handle = os.fdopen(fd, "a", encoding="utf-8")
        if os.name == "posix" and path.exists() and not path.is_symlink():
            os.chmod(path, 0o600)
        logger = cls(
            sink=handle,
            canary_tokens=canary_tokens,
            start_seq=start_seq,
            prev_hash=prev_hash,
            enforcement_mode=enforcement_mode,
        )
        logger.rotated_legacy_path = rotated_from
        if rotated_from is not None:
            # First record of the new chain, so the move itself is tamper-evident.
            logger._emit(
                AuditEvent(
                    audit_id=f"aud_{secrets.token_hex(12)}",
                    timestamp=utc_now().isoformat(),
                    session_id="system",
                    tool_name="audit/ledger",
                    mcp_server=None,
                    decision="legacy_log_rotated",
                    risk_tier=RiskTier.LOW.value,
                    tainted=False,
                    taint_sources=[],
                    args_sha256=EMPTY_ARGS_SHA256,
                    reasons=[
                        f"Moved the unchained pre-1.1 audit log to '{rotated_from.name}' and started a new chain."
                    ],
                    policy_id="audit.migration",
                    grant_id=None,
                    event_type="ledger_rotated",
                    enforcement_mode=enforcement_mode,
                )
            )
        return logger, handle

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    def _scrub(self, text: str) -> str:
        sanitized = redact_text(text)
        if self._canary_tokens:
            sanitized = redact_canaries_in_text(sanitized, self._canary_tokens)
        return sanitized

    def _emit(self, event: AuditEvent) -> AuditEvent:
        with self._lock:
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
                seq=self._next_seq,
                prev_hash=self._last_hash,
                entry_hash="",
                enforcement_mode=event.enforcement_mode or self._enforcement_mode,
            )
            entry_hash = compute_audit_entry_hash(asdict(draft))
            final = replace(draft, entry_hash=entry_hash)

            self._next_seq += 1
            self._last_hash = entry_hash
            self._events.append(final)
            if self._sink is not None:
                self._sink.write(_dump_audit_line(asdict(final)) + "\n")
                self._sink.flush()
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
        """Export all recorded audit events as newline-delimited JSON."""
        return "\n".join(_dump_audit_line(asdict(event)) for event in self._events)
