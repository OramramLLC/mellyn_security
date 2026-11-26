"""
Strict frozen Pydantic v2 schemas shared across Mellyn zones.

Architectural invariants:
  - Every model configures `ConfigDict(extra="forbid", strict=True, frozen=True)`.
  - Zero `Any` on wire or event fields; JSON payloads use recursive `JsonValue` / `JsonObject`.
  - Any `BLOCK` or `AAD_FIRE` severity MUST enforce `verdict_allow=False` (fail closed).
"""

from __future__ import annotations

import math
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mellyn.core.normalize import JsonObject, JsonValue

type Severity = Literal["ALLOW", "INFO", "WARN", "BLOCK", "AAD_FIRE"]
type Zone = Literal["core", "egress", "airlock", "ir_lab"]
type RedactionKind = Literal["canary", "secret", "high_entropy", "blocked_pattern"]

GENESIS_PREV_HASH = "0" * 64
AAD_CONTAINMENT_CONFIRMED_RULE_ID = "airlock.aad_containment_confirmed"
# First event of every proxy session; its metadata records `enforcement_mode` and the operator flags.
SESSION_STARTED_RULE_ID = "airlock.session_started"
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def _check_finite_json(value: JsonValue) -> JsonValue:
    """Ensure floats inside nested JSON structures are finite."""
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("Non-finite float values are forbidden in strict JSON fields.")
    if isinstance(value, list):
        for item in value:
            _check_finite_json(item)
    elif isinstance(value, dict):
        for val in value.values():
            _check_finite_json(val)
    return value


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class RedactionRecord(_StrictModel):
    """Non-sensitive metadata describing one redacted secret, canary, or blocked pattern match."""

    kind: RedactionKind
    rule_id: str = Field(min_length=1)
    field_path: str = Field(min_length=1)
    match_sha256: str

    @field_validator("match_sha256")
    @classmethod
    def _validate_sha256(cls, v: str) -> str:
        if not _SHA256_HEX_RE.fullmatch(v):
            raise ValueError("match_sha256 must be a 64-character lowercase hex digest.")
        return v


class Verdict(_StrictModel):
    """Deterministic security gate decision returned by egress and airlock evaluators."""

    verdict_allow: bool
    severity: Severity
    rule_id: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    artifact_sha256: str
    redactions: list[RedactionRecord] = Field(default_factory=list)
    redacted_payload: JsonValue = None

    @field_validator("artifact_sha256")
    @classmethod
    def _validate_artifact_sha256(cls, v: str) -> str:
        if not _SHA256_HEX_RE.fullmatch(v):
            raise ValueError("artifact_sha256 must be a 64-character lowercase hex digest.")
        return v

    @field_validator("redacted_payload")
    @classmethod
    def _validate_redacted_payload(cls, v: JsonValue) -> JsonValue:
        return _check_finite_json(v)

    @model_validator(mode="after")
    def _enforce_fail_closed_severity(self) -> Verdict:
        if self.severity in ("BLOCK", "AAD_FIRE") and self.verdict_allow:
            raise ValueError(f"Severity {self.severity!r} cannot coexist with verdict_allow=True.")
        return self


class ZoneEvent(_StrictModel):
    """Structured audit telemetry record emitted from a security zone before ledger chaining."""

    event_id: str = Field(min_length=1)
    timestamp_utc: str = Field(min_length=1)
    zone: Zone
    action: str = Field(min_length=1)
    verdict_allow: bool
    severity: Severity
    rule_id: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    artifact_sha256: str
    tool_name: str | None = None
    request_id: int | str | None = None
    redactions: list[RedactionRecord] = Field(default_factory=list)
    metadata: JsonObject = Field(default_factory=dict)

    @field_validator("artifact_sha256")
    @classmethod
    def _validate_artifact_sha256(cls, v: str) -> str:
        if not _SHA256_HEX_RE.fullmatch(v):
            raise ValueError("artifact_sha256 must be a 64-character lowercase hex digest.")
        return v

    @field_validator("request_id")
    @classmethod
    def _reject_bool_request_id(cls, v: int | str | None) -> int | str | None:
        if isinstance(v, bool):
            raise ValueError("request_id must not be a boolean.")
        return v

    @field_validator("metadata")
    @classmethod
    def _validate_metadata(cls, v: JsonObject) -> JsonObject:
        _check_finite_json(v)
        return v

    @model_validator(mode="after")
    def _enforce_fail_closed_severity(self) -> ZoneEvent:
        if self.severity in ("BLOCK", "AAD_FIRE") and self.verdict_allow:
            raise ValueError(f"Severity {self.severity!r} cannot coexist with verdict_allow=True.")
        return self


class AuditLedgerEntry(_StrictModel):
    """Hash-chained JSONL entry persisted by `core.audit.AuditLedger`."""

    seq: int = Field(ge=0)
    prev_hash: str
    entry_hash: str
    event: ZoneEvent

    @field_validator("prev_hash", "entry_hash")
    @classmethod
    def _validate_hash_hex(cls, v: str) -> str:
        if not _SHA256_HEX_RE.fullmatch(v):
            raise ValueError("Hash fields must be 64-character lowercase hex digests.")
        return v

    @model_validator(mode="after")
    def _validate_genesis_prev_hash(self) -> AuditLedgerEntry:
        if self.seq == 0 and self.prev_hash != GENESIS_PREV_HASH:
            raise ValueError("seq 0 entry must reference GENESIS_PREV_HASH ('0' * 64).")
        return self


class LedgerVerification(_StrictModel):
    """Result of standalone cryptographic verification of an `audit.jsonl` ledger."""

    valid: bool
    entry_count: int = Field(ge=0)
    last_seq: int | None = None
    last_hash: str | None = None
    first_invalid_seq: int | None = None
    reason: str | None = None
