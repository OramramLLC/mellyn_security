"""Mellyn egress zone: destination/workspace guards and deterministic secret/canary scanner."""

from __future__ import annotations

import importlib
from typing import Any

from mellyn.egress.guards import (
    _CONTROL_CHARACTERS,
    GUARDRAIL_PATHS,
    SENSITIVE_FILENAME_PATTERNS,
    SENSITIVE_PATH_PARTS,
    SENSITIVE_RELATIVE_PATHS,
    EgressValidator,
    SearchMatch,
    WorkspaceConfigError,
    WorkspacePathGuard,
    check_workspace_root,
)

_SCANNER_EXPORTS = frozenset(
    {
        "EgressScanResult",
        "KNOWN_SECRET_RULES",
        "scan_payload",
        "scan_text",
        "shannon_entropy",
    }
)


def __getattr__(name: str) -> Any:
    if name in _SCANNER_EXPORTS:
        scanner = importlib.import_module("mellyn.egress.scanner")
        return getattr(scanner, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "EgressValidator",
    "GUARDRAIL_PATHS",
    "SENSITIVE_FILENAME_PATTERNS",
    "SENSITIVE_PATH_PARTS",
    "SENSITIVE_RELATIVE_PATHS",
    "SearchMatch",
    "WorkspaceConfigError",
    "WorkspacePathGuard",
    "_CONTROL_CHARACTERS",
    "check_workspace_root",
]
