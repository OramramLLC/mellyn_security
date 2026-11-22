"""Core domain models for the AegisAI Tool-Call Authorizer."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


def canonical_json(arguments: dict[str, Any]) -> str:
    """Deterministic JSON form of tool arguments, used for exact matching and hashing."""
    return json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)


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
        if not 0.0 <= self.injection_score <= 1.0:
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
    (compared as canonical JSON). A call with any different, extra, or missing argument does not
    match, so approving `git_push(branch="feature/x")` can never authorize `branch="feature/x:main"`
    or an added `force=True`. Grants are single-use unless `max_uses` says otherwise.
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
        return (
            self.session_id == request.session_id
            and self.tool_name == request.tool_name
            and self.mcp_server == request.mcp_server
            and self.arguments_json == canonical_json(request.arguments)
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
