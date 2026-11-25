"""Mellyn Security — Authorization-First MCP Tool-Call Security Engine."""

from mellyn.audit import (
    AuditChainError,
    AuditEvent,
    AuditLogger,
    ChainVerificationResult,
    verify_gateway_audit_file,
    verify_gateway_audit_lines,
)
from mellyn.authorizer import Authorizer
from mellyn.credentials import CredentialConfig, CredentialConfigError, Role
from mellyn.egress import EgressValidator, WorkspacePathGuard
from mellyn.http_downstream import StreamableHttpDownstream

# MCPGateway is not re-exported here: `python -m mellyn.mcp_gateway` would otherwise import the module twice
# (once via this package, once as __main__). Import it from mellyn.mcp_gateway.
from mellyn.models import (
    ApprovalGrant,
    AuthorizationResult,
    Decision,
    RiskSignals,
    RiskTier,
    TaintSource,
    ToolCallRequest,
)
from mellyn.oauth_client import OAuthClientConfig, OAuthError, OAuthToken, OAuthTokenProvider
from mellyn.pin_gateway import (
    GatewayPinError,
    GatewayPinResult,
    inspect_gateway_server,
    inspect_remote_gateway_server,
    upsert_server_in_unified_toml,
)
from mellyn.policy import (
    MCP_CAPABILITY_PRESETS,
    SMB_SERVER_PRESETS,
    PolicyConfig,
    PolicyEngine,
    ScopedRule,
    ServerPresetProfile,
    ToolCapability,
)
from mellyn.policy_loader import PolicyLoadError, load_policy_file, parse_policy_dict
from mellyn.scanner import ScanFinding, ScannerConfig, ScanResult, scan_value
from mellyn.state_store import InMemoryStateStore, SessionLimitError, SqliteStateStore, StateStoreError
from mellyn.unified_config import UnifiedConfig, load_mellyn_config, load_unified_config

__all__ = [
    "ApprovalGrant",
    "AuditChainError",
    "AuditEvent",
    "AuditLogger",
    "AuthorizationResult",
    "Authorizer",
    "ChainVerificationResult",
    "CredentialConfig",
    "CredentialConfigError",
    "Decision",
    "EgressValidator",
    "GatewayPinError",
    "GatewayPinResult",
    "InMemoryStateStore",
    "MCP_CAPABILITY_PRESETS",
    "OAuthClientConfig",
    "OAuthError",
    "OAuthToken",
    "OAuthTokenProvider",
    "PolicyConfig",
    "PolicyEngine",
    "PolicyLoadError",
    "RiskSignals",
    "RiskTier",
    "Role",
    "SMB_SERVER_PRESETS",
    "ScanFinding",
    "ScanResult",
    "ScannerConfig",
    "ScopedRule",
    "ServerPresetProfile",
    "SessionLimitError",
    "SqliteStateStore",
    "StateStoreError",
    "StreamableHttpDownstream",
    "TaintSource",
    "ToolCallRequest",
    "ToolCapability",
    "UnifiedConfig",
    "WorkspacePathGuard",
    "inspect_gateway_server",
    "inspect_remote_gateway_server",
    "load_mellyn_config",
    "load_policy_file",
    "load_unified_config",
    "parse_policy_dict",
    "scan_value",
    "upsert_server_in_unified_toml",
    "verify_gateway_audit_file",
    "verify_gateway_audit_lines",
]
