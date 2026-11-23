"""Mellyn egress zone: destination/workspace guards and deterministic secret/canary scanner."""

from mcp_airlock.egress.guards import (
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
from mcp_airlock.egress.scanner import (
    KNOWN_SECRET_RULES,
    EgressScanResult,
    scan_payload,
    scan_text,
    shannon_entropy,
)

__all__ = [
    "EgressScanResult",
    "EgressValidator",
    "GUARDRAIL_PATHS",
    "KNOWN_SECRET_RULES",
    "SENSITIVE_FILENAME_PATTERNS",
    "SENSITIVE_PATH_PARTS",
    "SENSITIVE_RELATIVE_PATHS",
    "SearchMatch",
    "WorkspaceConfigError",
    "WorkspacePathGuard",
    "check_workspace_root",
    "scan_payload",
    "scan_text",
    "shannon_entropy",
]
