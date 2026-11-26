"""
Stdlib scanner wrapper for Mellyn Security Control Plane.

Re-exports the unified standard-library scanning core from `mellyn.core.scan` so container
builds and local CLI installs share one zero-dependency scanner without circular imports.
"""

from __future__ import annotations

from mellyn.core.scan import (
    _INVISIBLE_UNICODE_RE,
    _URL_USERINFO_SECRET_RE,
    SECRET_REDACTION_PATTERNS,
    SPLIT_COVERAGE_MIN_CANARY_CHARS,
    ScanFinding,
    ScannerConfig,
    ScanResult,
    canary_present_in_text,
    invisible_unicode_tools,
    normalize_scan_text,
    redact_canaries_in_text,
    scan_value,
    strip_invisible_unicode,
)

__all__ = [
    "SECRET_REDACTION_PATTERNS",
    "SPLIT_COVERAGE_MIN_CANARY_CHARS",
    "ScanFinding",
    "ScanResult",
    "ScannerConfig",
    "_INVISIBLE_UNICODE_RE",
    "_URL_USERINFO_SECRET_RE",
    "canary_present_in_text",
    "invisible_unicode_tools",
    "normalize_scan_text",
    "redact_canaries_in_text",
    "scan_value",
    "strip_invisible_unicode",
]
