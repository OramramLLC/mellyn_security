"""Core domain models for the Mellyn Security (AegisAI) Tool-Call Authorizer."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


def validate_json_value(value: Any) -> None:
    """
    Ensure a value consists exclusively of strict RFC 8259 JSON types.

    Rejects NaN/Infinity floats, non-string mapping keys, and arbitrary Python objects so
    serialization never falls back to lossy stringification (`default=str`).
    """
    if value is None or isinstance(value, bool | int | str):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Non-finite float (NaN or Infinity) is not permitted in tool arguments.")
        return
    if isinstance(value, list | tuple):
        for item in value:
            validate_json_value(item)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("Tool argument mapping keys must be strings.")
            validate_json_value(item)
        return
    raise TypeError(f"Unsupported non-JSON value of type '{type(value).__name__}'.")


def _to_plain_json(value: Any) -> Any:
    if isinstance(value, list | tuple):
        return [_to_plain_json(v) for v in value]
    if isinstance(value, Mapping):
        return {k: _to_plain_json(v) for k, v in value.items()}
    return value


def canonical_json(arguments: Mapping[str, Any]) -> str:
    """Deterministic RFC 8259 JSON form of tool arguments, used for exact matching and hashing."""
    if not isinstance(arguments, Mapping):
        raise TypeError("Tool arguments must be a mapping.")
    validate_json_value(arguments)
    return json.dumps(_to_plain_json(arguments), sort_keys=True, separators=(",", ":"), allow_nan=False)


class RiskTier(StrEnum):
    """Risk classification for agent and MCP tools."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Decision(StrEnum):
    """Deterministic authorization outcome."""

    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


@dataclass(frozen=True)
class TaintSource:
    """Record of untrusted external content entering an agent session."""

    source_type: str
    origin: str
    recorded_at: datetime = field(default_factory=utc_now)


@dataclass(frozen=True)
class RiskSignals:
    """Supporting probabilistic signals. Signals can escalate risk, never grant access."""

    injection_score: float = 0.0
    dlp_secret_detected: bool = False
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.injection_score, bool) or not 0.0 <= self.injection_score <= 1.0:
            raise ValueError("injection_score must be between 0.0 and 1.0")


@dataclass(frozen=True)
class ToolCallRequest:
    """A single tool or MCP invocation submitted for authorization."""

    session_id: str
    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    mcp_server: str | None = None
    signals: RiskSignals = field(default_factory=RiskSignals)


@dataclass(frozen=True)
class ApprovalGrant:
    """
    Short-lived human approval for one exact tool call.

    The grant is bound to the session, the tool, the MCP server, and the complete argument set
    (compared as canonical RFC 8259 JSON). A call with any different, extra, or missing argument
    does not match, so approving `git_push(branch="feature/x")` can never authorize
    `branch="feature/x:main"` or an added `force=True`. Grants are single-use unless `max_uses`
    says otherwise.
    """

    grant_id: str
    session_id: str
    tool_name: str
    mcp_server: str | None
    arguments_json: str
    approved_by: str
    expires_at: datetime
    max_uses: int = 1

    def is_valid(self, now: datetime | None = None) -> bool:
        check_time = now or utc_now()
        return check_time < self.expires_at

    def matches(self, request: ToolCallRequest, now: datetime | None = None) -> bool:
        if not self.is_valid(now):
            return False
        try:
            req_json = canonical_json(request.arguments)
        except (TypeError, ValueError):
            return False
        return (
            self.session_id == request.session_id
            and self.tool_name == request.tool_name
            and self.mcp_server == request.mcp_server
            and self.arguments_json == req_json
        )


@dataclass(frozen=True)
class AuthorizationResult:
    """Deterministic output of Authorizer.authorize()."""

    decision: Decision
    risk_tier: RiskTier
    tainted: bool
    reasons: tuple[str, ...]
    audit_id: str
    policy_id: str | None = None
    grant_id: str | None = None
