"""Redacted structured audit logger for Mellyn Security authorization decisions."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
from collections import deque
from dataclasses import asdict, dataclass
from typing import Any, TextIO

from mellyn.models import Decision, RiskTier, TaintSource, canonical_json, utc_now

SECRET_REDACTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-(?:proj|svcacct|None)-[A-Za-z0-9_-]{10,}"),
    re.compile(r"sk-[A-Za-z0-9]{48}"),
    re.compile(r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{10,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{20,}"),
    re.compile(r"hf_[A-Za-z0-9]{20,}"),
    re.compile(r"lsv2_(?:pt|sk)_[a-f0-9]{16,}_[a-f0-9]{6,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"xox[baprs]-[0-9A-Za-z-]{16,}"),
    re.compile(r"(?:sk|rk)_live_[0-9A-Za-z]{16,}"),
    re.compile(r"(?i)(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}"),
)

_URL_USERINFO_SECRET_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+(@)")


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
        payload = f"invalid:{type(arguments).__name__}:{arguments!r}".encode("utf-8", errors="replace")
    return hashlib.sha256(payload).hexdigest()


MAX_AUDIT_REASON_CHARS = 512
MAX_TAINT_ENTRY_CHARS = 256
EMPTY_ARGS_SHA256 = hashlib.sha256(b"{}").hexdigest()


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


@dataclass(frozen=True)
class AuditEvent:
    """Structured, redacted audit record (never stores raw prompts, secrets, or unrecognized caller IDs)."""

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


class AuditLogger:
    """
    Redacted audit sink. Keeps the most recent events in memory and, when `sink` is given, appends each
    event to it as one JSON line and flushes. The gateway points `sink` at a dedicated file: never at a
    stream a downstream process can also write to (such as a shared stderr), or entries can be forged.
    """

    def __init__(self, sink: TextIO | None = None, max_in_memory: int = 10_000) -> None:
        self._events: deque[AuditEvent] = deque(maxlen=max_in_memory)
        self._sink = sink
        self._lock = threading.Lock()

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    def _emit(self, event: AuditEvent) -> AuditEvent:
        with self._lock:
            self._events.append(event)
            if self._sink is not None:
                self._sink.write(json.dumps(asdict(event), sort_keys=True) + "\n")
                self._sink.flush()
        return event

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
        )
        return self._emit(event)

    def to_jsonl(self) -> str:
        """Export all recorded audit events as newline-delimited JSON."""
        return "\n".join(json.dumps(asdict(event), sort_keys=True) for event in self._events)
