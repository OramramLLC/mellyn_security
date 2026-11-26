"""
Typed Pydantic egress scanner wrapper over the unified `mellyn.core.scan` core.

Architectural invariants:
  - Imports ONLY from `mellyn.core` (+ stdlib / pydantic).
  - Always computes `artifact_sha256` on the unredacted payload first via `sha256_exact()`.
  - Returns structured `EgressScanResult` with `RedactionRecord` findings and `redacted_payload`.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import cast

from pydantic import BaseModel, ConfigDict, Field

from mellyn.core.normalize import JsonValue, sha256_exact
from mellyn.core.scan import KNOWN_SECRET_RULES as KNOWN_SECRET_RULES
from mellyn.core.scan import scan_payload_core
from mellyn.core.scan import shannon_entropy as shannon_entropy
from mellyn.core.schemas import RedactionKind, RedactionRecord


class EgressScanResult(BaseModel):
    """Structured redacted output from `egress.scanner`."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    artifact_sha256: str
    clean: bool
    canary_matched: bool
    secret_matched: bool
    high_entropy_matched: bool
    blocked_pattern_matched: bool
    findings: list[RedactionRecord] = Field(default_factory=list)
    redacted_payload: JsonValue = None


def scan_payload(
    payload: JsonValue,
    *,
    canary_tokens: Sequence[str] = (),
    blocked_patterns: Sequence[str] = (),
    entropy_threshold: float = 4.0,
    min_entropy_length: int = 20,
) -> EgressScanResult:
    """
    Compute `artifact_sha256` on `payload` first, then delegate scanning and redaction to
    `mellyn.core.scan.scan_payload_core`.
    """
    if math.isnan(entropy_threshold) or entropy_threshold <= 0.0:
        raise ValueError("entropy_threshold must be > 0 (or math.inf to disable).")
    if min_entropy_length < 8:
        raise ValueError("min_entropy_length must be >= 8.")

    artifact_sha256 = sha256_exact(payload)
    outcome = scan_payload_core(
        payload,
        canary_tokens=canary_tokens,
        block_known_secrets=True,
        blocked_patterns=blocked_patterns,
        detect_high_entropy=math.isfinite(entropy_threshold),
        entropy_threshold=entropy_threshold,
        min_entropy_length=min_entropy_length,
        redact=True,
    )
    findings = [
        RedactionRecord(
            kind=cast(RedactionKind, f.kind),
            rule_id=f.rule_id,
            field_path=f.field_path,
            match_sha256=f.match_sha256,
        )
        for f in outcome.findings
    ]
    return EgressScanResult(
        artifact_sha256=artifact_sha256,
        clean=outcome.clean,
        canary_matched=outcome.canary_matched,
        secret_matched=outcome.secret_matched,
        high_entropy_matched=outcome.high_entropy_matched,
        blocked_pattern_matched=outcome.blocked_pattern_matched,
        findings=findings,
        redacted_payload=outcome.redacted_payload,
    )


def scan_text(
    text: str,
    *,
    canary_tokens: Sequence[str] = (),
    blocked_patterns: Sequence[str] = (),
    entropy_threshold: float = 4.0,
    min_entropy_length: int = 20,
) -> EgressScanResult:
    """Convenience wrapper scanning a single string payload via `scan_payload`."""
    return scan_payload(
        text,
        canary_tokens=canary_tokens,
        blocked_patterns=blocked_patterns,
        entropy_threshold=entropy_threshold,
        min_entropy_length=min_entropy_length,
    )


__all__ = [
    "EgressScanResult",
    "KNOWN_SECRET_RULES",
    "scan_payload",
    "scan_text",
    "shannon_entropy",
]
