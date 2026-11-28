"""Core domain models for the Mellyn Security Tool-Call Authorizer."""

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


_MAX_NORMALIZE_JSON_DEPTH = 128


def _normalize_json_tree(value: Any, *, _depth: int = 0) -> Any:
    """
    Validate that `value` consists exclusively of strict RFC 8259 JSON types and return canonical
    plain-JSON containers (`tuple` -> `list`, mapping -> `dict`, `-0.0` -> `0.0`).

    Rejects NaN/Infinity floats, non-string mapping keys, nesting beyond `_MAX_NORMALIZE_JSON_DEPTH`,
    and arbitrary Python objects so serialization never falls back to lossy stringification (`default=str`).
    """
    if _depth > _MAX_NORMALIZE_JSON_DEPTH:
        raise ValueError(f"JSON nesting is deeper than {_MAX_NORMALIZE_JSON_DEPTH} levels.")
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Non-finite float (NaN or Infinity) is not permitted in JSON values.")
        return 0.0 if value == 0.0 else value
    if isinstance(value, list | tuple):
        return [_normalize_json_tree(item, _depth=_depth + 1) for item in value]
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("Tool argument mapping keys must be strings.")
            out[key] = _normalize_json_tree(item, _depth=_depth + 1)
        return out
    raise TypeError(f"Unsupported non-JSON value of type '{type(value).__name__}'.")


def canonical_json_value(value: Any) -> str:
    """
    Deterministic RFC 8259 JSON string for any strict JSON scalar, array, or object.

    Preserves exact JSON scalar types (`"true"` != `"1"` != `"1.0"`), treats tuples and lists
    identically, sorts object keys, and canonicalizes `-0.0` to `0.0`.
    """
    return json.dumps(_normalize_json_tree(value), sort_keys=True, separators=(",", ":"), allow_nan=False)


def validate_json_value(value: Any) -> None:
    """Ensure a value consists exclusively of strict RFC 8259 JSON types."""
    _normalize_json_tree(value)


def canonical_json(arguments: Mapping[str, Any]) -> str:
    """Deterministic RFC 8259 JSON form of tool arguments, used for exact matching and hashing."""
    if not isinstance(arguments, Mapping):
        raise TypeError("Tool arguments must be a mapping.")
    return canonical_json_value(arguments)


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


def effective_mcp_method(tool_name: str, mcp_method: str | None) -> str:
    """Return the MCP operation identity ('tools/call' vs 'resources/read') for policy and grant matching."""
    if mcp_method is not None:
        return mcp_method
    return "resources/read" if tool_name == "resources/read" else "tools/call"


@dataclass(frozen=True)
class ToolCallRequest:
    """A single tool or MCP invocation submitted for authorization."""

    session_id: str
    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    mcp_server: str | None = None
    signals: RiskSignals = field(default_factory=RiskSignals)
    mcp_method: str | None = None


@dataclass(frozen=True)
class ApprovalGrant:
    """
    Short-lived human approval for one exact tool call.

    The grant is bound to the session, the MCP operation, the tool, the MCP server, and the complete
    argument set (compared as canonical RFC 8259 JSON). A call with any different, extra, or missing
    argument does not match, so approving `git_push(branch="feature/x")` can never authorize
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
    mcp_method: str | None = None

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
            and effective_mcp_method(self.tool_name, self.mcp_method)
            == effective_mcp_method(request.tool_name, request.mcp_method)
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


MAX_LINE_BYTES = 4 * 1024 * 1024
DOWNSTREAM_TIMEOUT_SECONDS = 60.0
SUPPORTED_PROTOCOL_VERSIONS: tuple[str, ...] = ("2025-06-18", "2025-03-26", "2024-11-05")
DOWNSTREAM_ERROR = -32000


class GatewayLocalError(dict):  # type: ignore[type-arg]
    """
    A JSON-RPC error the gateway generated itself because a downstream server never answered (timeout,
    closed pipe, HTTP/OAuth failure, refused input). Carries no server-written text, so it does not taint.

    Replies a server actually sent are parsed into plain `dict`s, so a server cannot make its own reply
    look like one of these, whatever fields it includes.
    """


def jsonrpc_error(req_id: Any, code: int, message: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    """Construct a JSON-RPC 2.0 error reply dict."""
    error_body: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error_body["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": error_body}


def local_downstream_error(req_id: Any, message: str) -> GatewayLocalError:
    """Construct a non-tainting gateway-authored JSON-RPC error reply."""
    return GatewayLocalError(jsonrpc_error(req_id, DOWNSTREAM_ERROR, message))
