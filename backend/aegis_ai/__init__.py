"""Mellyn Security (AegisAI) — Authorization-First MCP Tool-Call Security Engine."""

from aegis_ai.audit import AuditEvent, AuditLogger
from aegis_ai.authorizer import Authorizer
from aegis_ai.credentials import CredentialConfig, CredentialConfigError, Role
from aegis_ai.egress import EgressValidator, WorkspacePathGuard

# MCPGateway is not re-exported here: `python -m aegis_ai.mcp_gateway` would otherwise import the module twice
# (once via this package, once as __main__). Import it from aegis_ai.mcp_gateway.
from aegis_ai.models import (
    ApprovalGrant,
    AuthorizationResult,
    Decision,
    RiskSignals,
    RiskTier,
    TaintSource,
    ToolCallRequest,
)
from aegis_ai.policy import PolicyConfig, PolicyEngine, ScopedRule
from aegis_ai.policy_loader import PolicyLoadError, load_policy_file, parse_policy_dict

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
    "PolicyConfig",
    "PolicyEngine",
    "PolicyLoadError",
    "RiskSignals",
    "RiskTier",
    "Role",
    "ScopedRule",
    "TaintSource",
    "ToolCallRequest",
    "WorkspacePathGuard",
    "load_policy_file",
    "parse_policy_dict",
]
