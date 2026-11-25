"""Mellyn Security — Authorization-First MCP Tool-Call Security Engine."""

from mellyn.audit import AuditEvent, AuditLogger
from mellyn.authorizer import Authorizer
from mellyn.credentials import CredentialConfig, CredentialConfigError, Role
from mellyn.egress import EgressValidator, WorkspacePathGuard

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
from mellyn.policy import MCP_CAPABILITY_PRESETS, PolicyConfig, PolicyEngine, ScopedRule, ToolCapability
from mellyn.policy_loader import PolicyLoadError, load_policy_file, parse_policy_dict
from mellyn.state_store import InMemoryStateStore, SessionLimitError, SqliteStateStore, StateStoreError

__all__ = [
    "ApprovalGrant",
    "AuditEvent",
    "AuditLogger",
    "AuthorizationResult",
    "Authorizer",
    "CredentialConfig",
    "CredentialConfigError",
    "Decision",
    "EgressValidator",
    "InMemoryStateStore",
    "MCP_CAPABILITY_PRESETS",
    "PolicyConfig",
    "PolicyEngine",
    "PolicyLoadError",
    "RiskSignals",
    "RiskTier",
    "Role",
    "ScopedRule",
    "SessionLimitError",
    "SqliteStateStore",
    "StateStoreError",
    "TaintSource",
    "ToolCallRequest",
    "ToolCapability",
    "WorkspacePathGuard",
    "load_policy_file",
    "parse_policy_dict",
]
