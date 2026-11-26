"""Mellyn core primitives: Unicode/JSON canonicalization, stdlib scanner/redaction core, and lazy audit schemas."""

from __future__ import annotations

import importlib
from typing import Any

from mellyn.core.normalize import (
    JsonObject,
    JsonScalar,
    JsonValue,
    canonical_json_bytes,
    exact_json_bytes,
    has_invisible_unicode,
    is_invisible_codepoint,
    normalize_str,
    normalize_value,
    sha256_canonical,
    sha256_exact,
    strip_invisible,
)
from mellyn.core.scan import (
    canary_present,
    redact_canary_in_text,
    redact_core_secrets,
)

_AUDIT_EXPORTS = frozenset(
    {
        "AuditLedger",
        "LedgerAnchor",
        "verify_ledger",
        "verify_ledger_bytes",
    }
)
_SCHEMA_EXPORTS = frozenset(
    {
        "AAD_CONTAINMENT_CONFIRMED_RULE_ID",
        "AuditLedgerEntry",
        "GENESIS_PREV_HASH",
        "LedgerVerification",
        "RedactionKind",
        "RedactionRecord",
        "SESSION_STARTED_RULE_ID",
        "Severity",
        "Verdict",
        "Zone",
        "ZoneEvent",
    }
)


def __getattr__(name: str) -> Any:
    if name in _AUDIT_EXPORTS:
        return getattr(importlib.import_module("mellyn.core.audit"), name)
    if name in _SCHEMA_EXPORTS:
        return getattr(importlib.import_module("mellyn.core.schemas"), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "AAD_CONTAINMENT_CONFIRMED_RULE_ID",
    "AuditLedger",
    "AuditLedgerEntry",
    "GENESIS_PREV_HASH",
    "JsonObject",
    "JsonScalar",
    "JsonValue",
    "LedgerAnchor",
    "LedgerVerification",
    "RedactionKind",
    "RedactionRecord",
    "SESSION_STARTED_RULE_ID",
    "Severity",
    "Verdict",
    "Zone",
    "ZoneEvent",
    "canonical_json_bytes",
    "canary_present",
    "exact_json_bytes",
    "has_invisible_unicode",
    "is_invisible_codepoint",
    "normalize_str",
    "normalize_value",
    "redact_canary_in_text",
    "redact_core_secrets",
    "sha256_canonical",
    "sha256_exact",
    "strip_invisible",
    "verify_ledger",
    "verify_ledger_bytes",
]
