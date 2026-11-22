"""Scoped tool-call policy definitions and evaluation rules."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from aegis_ai.models import Decision, RiskTier, ToolCallRequest

DEFAULT_TOOL_RISK_TIERS: dict[str, RiskTier] = {
    # Low-risk: read-only inside workspace
    "workspace_read": RiskTier.LOW,
    "workspace_search": RiskTier.LOW,
    "git_status": RiskTier.LOW,
    "git_diff": RiskTier.LOW,
    # Medium-risk: workspace writes or allowlisted read-only HTTP
    "workspace_write": RiskTier.MEDIUM,
    "http_get": RiskTier.MEDIUM,
    # High-risk: shell, arbitrary HTTP, messaging, payments, cloud mutations
    "shell_exec": RiskTier.HIGH,
    "http_post": RiskTier.HIGH,
    "send_email": RiskTier.HIGH,
    "send_slack_message": RiskTier.HIGH,
    "payment_transfer": RiskTier.HIGH,
    "git_push": RiskTier.HIGH,
}

# Tools that execute a program. They must receive an argv list, never a shell command string.
SHELL_TOOL_NAMES: frozenset[str] = frozenset({"shell_exec"})

# Programs that interpret a command string, which would reintroduce shell injection through argv.
SHELL_INTERPRETERS: frozenset[str] = frozenset(
    {"sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "cmd", "powershell", "pwsh", "env", "xargs"}
)

# Tools whose results bring outside content into the agent's context. Allowing one taints the session.
DEFAULT_UNTRUSTED_CONTENT_TOOLS: frozenset[str] = frozenset({"http_get", "http_fetch", "web_fetch", "web_search"})


def tool_key(tool_name: str, mcp_server: str | None) -> str:
    """Risk-tier key: the bare name for local tools, "<server>/<tool>" for MCP tools."""
    return tool_name if mcp_server is None else f"{mcp_server}/{tool_name}"


def program_name(argv0: str) -> str:
    """Basename of argv[0], lower-cased, without a Windows executable suffix ('/bin/RM.exe' -> 'rm')."""
    name = re.split(r"[\\/]", argv0)[-1].lower()
    return re.sub(r"\.(exe|cmd|bat|com)$", "", name)


def validate_argv(arguments: Mapping[str, Any]) -> tuple[bool, str]:
    """Shell tools take a non-empty list of strings under 'argv' and nothing that a shell would parse."""
    if "command" in arguments:
        return False, "Shell command strings are not accepted; pass an 'argv' list so no shell parses it."
    argv = arguments.get("argv")
    if not isinstance(argv, list | tuple) or not argv or not all(isinstance(a, str) and a for a in argv):
        return False, "Shell tools require 'argv' as a non-empty list of non-empty strings."
    if program_name(argv[0]) in SHELL_INTERPRETERS:
        return False, f"Running the command interpreter '{program_name(argv[0])}' is denied."
    return True, f"Program '{program_name(argv[0])}' with {len(argv) - 1} argument(s)."


def _freeze(value: Any) -> Any:
    """Make JSON-like values comparable regardless of list/tuple: ['a', 'b'] == ('a', 'b')."""
    if isinstance(value, list | tuple):
        return tuple(_freeze(v) for v in value)
    return value


@dataclass(frozen=True)
class ScopedRule:
    """
    Explicit policy rule for one tool. Matching is exact, never by string prefix.

    - `arg_equals`: each named argument must equal one of the listed values exactly
      (lists compare element by element, so argv ("pytest", "tests") matches ["pytest", "tests"]).
    - `programs`: for shell tools, the basename of argv[0] must be one of these
      ('/bin/rm', 'RM.EXE' and 'rm' are all 'rm'), whatever flags follow.
    - ALLOW and REQUIRE_APPROVAL rules match only when the call has no arguments beyond those the rule
      names, so an extra `force=True` falls through to the default decision. DENY rules ignore extra
      arguments.
    - `programs` is only for DENY and REQUIRE_APPROVAL rules. An ALLOW rule keyed on a program name would
      allow any arguments (`git -c core.sshCommand=...`), so ALLOW rules must list exact `arg_equals`.
    - `mcp_server`: the server the tool must come from (None = a local, non-MCP tool). ALLOW and
      REQUIRE_APPROVAL rules match only that exact server, so a downstream server cannot borrow a rule by
      naming its tool `shell_exec`. A DENY rule with no `mcp_server` applies to every server.

    Deny rules are defense in depth, not the boundary: anything a rule does not explicitly allow
    already defaults to REQUIRE_APPROVAL for HIGH-risk tools.
    """

    rule_id: str
    tool_name: str
    effect: Decision
    arg_equals: Mapping[str, tuple[Any, ...]] = field(default_factory=dict)
    programs: frozenset[str] = frozenset()
    allow_when_tainted: bool = False
    description: str = ""
    mcp_server: str | None = None

    def __post_init__(self) -> None:
        if self.effect == Decision.ALLOW and self.programs:
            raise ValueError(
                f"Rule '{self.rule_id}': ALLOW rules cannot use 'programs' (it would allow any arguments); "
                "list the exact argv under 'arg_equals' instead."
            )

    def matches(self, request: ToolCallRequest) -> bool:
        if self.tool_name != request.tool_name:
            return False
        if self.mcp_server != request.mcp_server and not (self.effect == Decision.DENY and self.mcp_server is None):
            return False
        args = request.arguments
        for key, allowed_values in self.arg_equals.items():
            if key not in args or not any(_freeze(args[key]) == _freeze(v) for v in allowed_values):
                return False
        if self.programs:
            argv = args.get("argv")
            if not isinstance(argv, list | tuple) or not argv or not isinstance(argv[0], str):
                return False
            if program_name(argv[0]) not in {p.lower() for p in self.programs}:
                return False
        if self.effect != Decision.DENY:
            named = set(self.arg_equals) | ({"argv"} if self.programs else set())
            if set(args) - named:
                return False
        return True


@dataclass(frozen=True)
class PolicyConfig:
    """Configuration for PolicyEngine."""

    tool_risk_tiers: dict[str, RiskTier] = field(default_factory=lambda: dict(DEFAULT_TOOL_RISK_TIERS))
    allowed_mcp_servers: frozenset[str] | None = None
    # MCP servers whose responses are trusted not to carry injected instructions. A call to any other
    # MCP server taints the session once allowed, because its response enters the agent's context.
    trusted_mcp_servers: frozenset[str] = frozenset()
    untrusted_content_tools: frozenset[str] = DEFAULT_UNTRUSTED_CONTENT_TOOLS
    allowed_egress_domains: frozenset[str] = field(default_factory=frozenset)
    # Extra workspace paths (prefixes ending in "/" or exact files) the agent may never write.
    protected_paths: tuple[str, ...] = ()
    scoped_rules: tuple[ScopedRule, ...] = ()
    injection_escalate_threshold: float = 0.70
    injection_deny_threshold: float = 0.90
    deny_on_dlp_secret: bool = True


class PolicyEngine:
    """Evaluates tool risk tiers, MCP server allowlists, and scoped rules."""

    def __init__(self, config: PolicyConfig | None = None) -> None:
        self.config = config or PolicyConfig()

    def classify_risk(self, tool_name: str, mcp_server: str | None = None) -> RiskTier:
        """
        Fail closed: unknown tools default to HIGH risk.

        Local tools are looked up by name. MCP tools are looked up only as "<server>/<tool>", so a
        downstream server cannot get a low tier by naming its tool `git_status` or `workspace_read`.
        """
        key = tool_key(tool_name, mcp_server)
        return self.config.tool_risk_tiers.get(key, RiskTier.HIGH)

    def check_mcp_server(self, mcp_server: str | None) -> tuple[bool, str]:
        """Verify MCP server against the allowlist when an allowlist is configured."""
        if mcp_server is None:
            return True, "Local/non-MCP tool call."
        if self.config.allowed_mcp_servers is None:
            return True, f"MCP server '{mcp_server}' accepted (no allowlist configured)."
        if mcp_server in self.config.allowed_mcp_servers:
            return True, f"MCP server '{mcp_server}' is allowlisted."
        return False, f"MCP server '{mcp_server}' is not in the approved MCP server allowlist."

    def brings_untrusted_content(self, request: ToolCallRequest) -> bool:
        """True when the call's result will put outside content into the agent's context."""
        if request.tool_name in self.config.untrusted_content_tools:
            return True
        return request.mcp_server is not None and request.mcp_server not in self.config.trusted_mcp_servers

    def match_scoped_rule(self, request: ToolCallRequest) -> ScopedRule | None:
        """
        Return the highest-precedence matching scoped rule.
        Explicit DENY rules always take precedence over ALLOW/REQUIRE_APPROVAL rules.
        """
        matched = [rule for rule in self.config.scoped_rules if rule.matches(request)]
        for rule in matched:
            if rule.effect == Decision.DENY:
                return rule
        return matched[0] if matched else None
