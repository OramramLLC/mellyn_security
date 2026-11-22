"""Redacted structured audit logger for AegisAI authorization decisions."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
from collections import deque
from dataclasses import asdict, dataclass
from typing import Any, TextIO

from aegis_ai.models import Decision, RiskTier, TaintSource, canonical_json, utc_now

SECRET_REDACTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-(?:proj|svcacct|None)-[A-Za-z0-9_-]{10,}"),
    re.compile(r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{10,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{20,}"),
    re.compile(r"hf_[A-Za-z0-9]{20,}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{12,}"),
)


def redact_text(value: str) -> str:
    """Replace known credential/token patterns with [REDACTED_SECRET]."""
    sanitized = value
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


@dataclass(frozen=True)
class AuditEvent:
    """Structured, redacted audit record (never stores raw prompts or secrets)."""

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
        taint_sources: tuple[TaintSource, ...],
        reasons: tuple[str, ...],
        policy_id: str | None = None,
        grant_id: str | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            audit_id=f"aud_{secrets.token_hex(12)}",
            timestamp=utc_now().isoformat(),
            session_id=session_id,
            tool_name=tool_name,
            mcp_server=mcp_server,
            decision=decision.value,
            risk_tier=risk_tier.value,
            tainted=tainted,
            taint_sources=[redact_text(f"{src.source_type}:{src.origin}") for src in taint_sources],
            args_sha256=hash_arguments(arguments),
            reasons=[redact_text(reason) for reason in reasons],
            policy_id=policy_id,
            grant_id=grant_id,
        )
        with self._lock:
            self._events.append(event)
            if self._sink is not None:
                self._sink.write(json.dumps(asdict(event), sort_keys=True) + "\n")
                self._sink.flush()
        return event

    def to_jsonl(self) -> str:
        """Export all recorded audit events as newline-delimited JSON."""
        return "\n".join(json.dumps(asdict(event), sort_keys=True) for event in self._events)
