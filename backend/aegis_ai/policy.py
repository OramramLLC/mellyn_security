"""Scoped tool-call policy definitions, capability bindings, and evaluation rules."""

from __future__ import annotations

import math
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

# Tools that execute a program when no explicit ToolCapability overrides them.
SHELL_TOOL_NAMES: frozenset[str] = frozenset({"shell_exec"})

# Programs that interpret a command string, which would reintroduce shell injection through argv.
SHELL_INTERPRETERS: frozenset[str] = frozenset(
    {"sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "cmd", "powershell", "pwsh", "env", "xargs"}
)

# Tools whose results bring outside content into the agent's context. Allowing one taints the session.
DEFAULT_UNTRUSTED_CONTENT_TOOLS: frozenset[str] = frozenset({"http_get", "http_fetch", "web_fetch", "web_search"})


@dataclass(frozen=True)
class ToolCapability:
    """
    Binds a tool ("<server>/<tool>" or local "<tool>") to deterministic hard-boundary argument guards.

    Eliminates nominal coupling: any MCP server's tool names (`read_file`, `move_file`, `fetch`, etc.)
    can be bound to workspace path confinement, URL egress allowlists, or argv-only execution.
    Every LOW or MEDIUM tool in `tool_risk_tiers` MUST have a declared ToolCapability (or `pure=True`).
    """

    path_read_args: tuple[str, ...] = ()
    optional_path_read_args: tuple[str, ...] = ()
    path_read_list_args: tuple[str, ...] = ()
    path_write_args: tuple[str, ...] = ()
    url_args: tuple[str, ...] = ()
    shell_argv_arg: str | None = None
    pure: bool = False

    def __post_init__(self) -> None:
        has_guards = any(
            (
                self.path_read_args,
                self.optional_path_read_args,
                self.path_read_list_args,
                self.path_write_args,
                self.url_args,
                self.shell_argv_arg is not None,
            )
        )
        if self.pure and has_guards:
            raise ValueError("ToolCapability with pure=True cannot also declare path, URL, or shell guards.")
        if not self.pure and not has_guards:
            raise ValueError("ToolCapability must declare at least one argument guard or set pure=True.")
        if self.shell_argv_arg is not None and not self.shell_argv_arg.strip():
            raise ValueError("ToolCapability.shell_argv_arg must be a non-empty string.")


# Argument names treated as paths on tools that have NO capability binding (unknown, HIGH-risk tools).
# They are checked as writes, the strictest mode: secrets, paths outside the workspace and guardrail files
# are denied even when a human grant approves the call. Binding the tool with a ToolCapability replaces
# this name-based guess with exact per-argument rules.
UNBOUND_PATH_ARG_NAMES: frozenset[str] = frozenset(
    {
        "path",
        "paths",
        "file",
        "files",
        "filename",
        "file_path",
        "filepath",
        "source",
        "destination",
        "dest",
        "directory",
        "dir",
        "cwd",
    }
)

# Built-in baseline capabilities for canonical tool names.
DEFAULT_TOOL_CAPABILITIES: dict[str, ToolCapability] = {
    "workspace_read": ToolCapability(path_read_args=("path",)),
    "workspace_search": ToolCapability(optional_path_read_args=("path",)),
    "workspace_write": ToolCapability(path_write_args=("path",)),
    "workspace_delete": ToolCapability(path_write_args=("path",)),
    "git_status": ToolCapability(pure=True),
    "git_diff": ToolCapability(pure=True),
    "http_get": ToolCapability(url_args=("url",)),
    "http_post": ToolCapability(url_args=("url",)),
    "http_fetch": ToolCapability(url_args=("url",)),
    "webhook_call": ToolCapability(url_args=("url",)),
    "shell_exec": ToolCapability(shell_argv_arg="argv"),
}

# Presets for widely deployed off-the-shelf MCP servers (e.g., @modelcontextprotocol/server-filesystem).
MCP_CAPABILITY_PRESETS: dict[str, dict[str, ToolCapability]] = {
    "mcp-filesystem": {
        "read_file": ToolCapability(path_read_args=("path",)),
        "read_text_file": ToolCapability(path_read_args=("path",)),
        "read_media_file": ToolCapability(path_read_args=("path",)),
        "read_multiple_files": ToolCapability(path_read_list_args=("paths",)),
        "list_directory": ToolCapability(path_read_args=("path",)),
        "list_directory_with_sizes": ToolCapability(path_read_args=("path",)),
        "directory_tree": ToolCapability(path_read_args=("path",)),
        "search_files": ToolCapability(path_read_args=("path",)),
        "get_file_info": ToolCapability(path_read_args=("path",)),
        "list_allowed_directories": ToolCapability(pure=True),
        "write_file": ToolCapability(path_write_args=("path",)),
        "edit_file": ToolCapability(path_write_args=("path",)),
        "create_directory": ToolCapability(path_write_args=("path",)),
        "move_file": ToolCapability(path_write_args=("source", "destination")),
    },
    "mcp-fetch": {
        "fetch": ToolCapability(url_args=("url",)),
    },
}


def tool_key(tool_name: str, mcp_server: str | None) -> str:
    """Risk-tier and capability key: bare name for local tools, '<server>/<tool>' for MCP tools."""
    return tool_name if mcp_server is None else f"{mcp_server}/{tool_name}"


def program_name(argv0: str) -> str:
    """Basename of argv[0], lower-cased, without a Windows executable suffix ('/bin/RM.exe' -> 'rm')."""
    name = re.split(r"[\\/]", argv0)[-1].lower()
    return re.sub(r"\.(exe|cmd|bat|com)$", "", name)


def validate_argv(arguments: Mapping[str, Any], *, argv_key: str = "argv") -> tuple[bool, str]:
    """Shell tools take a non-empty list of strings under `argv_key` and nothing that a shell would parse."""
    if "command" in arguments and argv_key != "command":
        return False, "Shell command strings are not accepted; pass an 'argv' list so no shell parses it."
    argv = arguments.get(argv_key)
    if not isinstance(argv, list | tuple) or not argv or not all(isinstance(a, str) and a for a in argv):
        return False, f"Shell tools require '{argv_key}' as a non-empty list of non-empty strings."
    if program_name(argv[0]) in SHELL_INTERPRETERS:
        return False, f"Running the command interpreter '{program_name(argv[0])}' is denied."
    return True, f"Program '{program_name(argv[0])}' with {len(argv) - 1} argument(s)."


def normalize_arg_value(value: Any) -> Any:
    """
    Recursively normalize JSON-compatible values with explicit scalar type tags.

    Isomorphic to `canonical_json`:
      - `True` -> `("bool", True)` vs `1` -> `("int", 1)` (never confuses booleans with integers)
      - `1` -> `("int", 1)` vs `1.0` -> `("float", 1.0)`
      - `["a", "b"]` == `("a", "b")` at any nesting depth, including inside nested dicts
      - Rejects NaN, Infinity, and arbitrary non-JSON Python objects.
    """
    if value is None:
        return ("null", None)
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, int):
        return ("int", value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Non-finite float (NaN or Infinity) is not permitted in policy values.")
        return ("float", value)
    if isinstance(value, str):
        return ("str", value)
    if isinstance(value, list | tuple):
        return ("array", tuple(normalize_arg_value(v) for v in value))
    if isinstance(value, Mapping):
        if not all(isinstance(k, str) for k in value):
            raise ValueError("Mapping keys in policy/tool arguments must be strings.")
        return ("object", tuple(sorted((k, normalize_arg_value(v)) for k, v in value.items())))
    raise TypeError(f"Unsupported non-JSON value type '{type(value).__name__}'.")


@dataclass(frozen=True)
class ScopedRule:
    """
    Explicit policy rule for one tool. Matching is exact and type-strict, never by string prefix.

    - `arg_equals`: each named argument must equal one of the listed values with exact JSON type identity.
    - `programs`: for shell tools, the basename of argv[0] must be one of these, whatever flags follow.
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
        # Validate that every rule literal is strict JSON-compatible at construction time
        for allowed_values in self.arg_equals.values():
            for val in allowed_values:
                normalize_arg_value(val)

    def matches(self, request: ToolCallRequest) -> bool:
        if self.tool_name != request.tool_name:
            return False
        if self.mcp_server != request.mcp_server and not (self.effect == Decision.DENY and self.mcp_server is None):
            return False
        args = request.arguments
        for key, allowed_values in self.arg_equals.items():
            if key not in args:
                return False
            try:
                actual_norm = normalize_arg_value(args[key])
            except (TypeError, ValueError):
                return False
            if not any(actual_norm == normalize_arg_value(v) for v in allowed_values):
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


def resolve_capability(
    tool_name: str,
    mcp_server: str | None,
    *,
    tool_capabilities: Mapping[str, ToolCapability],
    server_presets: Mapping[str, str],
) -> ToolCapability | None:
    """
    Resolve the hard-boundary capability profile for `(mcp_server, tool_name)`:
      1. Explicit `tool_capabilities` entry (`"<server>/<tool>"` for MCP, `"<tool>"` for local).
      2. Server preset (`MCP_CAPABILITY_PRESETS[preset][tool_name]`) when `mcp_server` uses a preset.
      3. Built-in `DEFAULT_TOOL_CAPABILITIES` for canonical tool names (`workspace_read`, `shell_exec`, ...).
    """
    key = tool_key(tool_name, mcp_server)
    if key in tool_capabilities:
        return tool_capabilities[key]
    if mcp_server is not None and mcp_server in server_presets:
        preset_map = MCP_CAPABILITY_PRESETS.get(server_presets[mcp_server], {})
        if tool_name in preset_map:
            return preset_map[tool_name]
    return DEFAULT_TOOL_CAPABILITIES.get(tool_name)


@dataclass(frozen=True)
class PolicyConfig:
    """Configuration for PolicyEngine."""

    tool_risk_tiers: dict[str, RiskTier] = field(default_factory=lambda: dict(DEFAULT_TOOL_RISK_TIERS))
    tool_capabilities: Mapping[str, ToolCapability] = field(default_factory=dict)
    server_presets: Mapping[str, str] = field(default_factory=dict)
    pinned_tool_hashes: Mapping[str, str] = field(default_factory=dict)
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

    def __post_init__(self) -> None:
        for srv, preset in self.server_presets.items():
            if preset not in MCP_CAPABILITY_PRESETS:
                raise ValueError(
                    f"Unknown capability preset '{preset}' for server '{srv}'; "
                    f"known presets: {sorted(MCP_CAPABILITY_PRESETS)}."
                )
        for srv, digest in self.pinned_tool_hashes.items():
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError(f"pinned_tool_hashes['{srv}'] must be a 64-character lowercase hex SHA-256 digest.")

        # Fail-closed invariant: any LOW or MEDIUM tool in tool_risk_tiers MUST have a known capability
        # profile (either an argument guard or explicit pure=True), so lowering e.g. "fs/read_file" to LOW
        # without binding it to path_read_args is rejected at policy construction time.
        for key, tier in self.tool_risk_tiers.items():
            if tier not in (RiskTier.LOW, RiskTier.MEDIUM):
                continue
            if "/" in key:
                srv, _, tname = key.partition("/")
                if tname == "resources" and key.endswith("/resources/read"):
                    continue
                mcp_srv: str | None = srv
                tool = key[len(srv) + 1 :]
            else:
                mcp_srv = None
                tool = key
            if tool == "resources/read":
                continue
            cap = resolve_capability(
                tool,
                mcp_srv,
                tool_capabilities=self.tool_capabilities,
                server_presets=self.server_presets,
            )
            if cap is None:
                raise ValueError(
                    f"Tool '{key}' has risk tier '{tier.value}' without a declared ToolCapability "
                    f'(add [tool_capabilities."{key}"] or a server_presets entry so hard boundaries apply).'
                )


class PolicyEngine:
    """Evaluates tool risk tiers, capability bindings, MCP server allowlists, and scoped rules."""

    def __init__(self, config: PolicyConfig | None = None) -> None:
        self.config = config or PolicyConfig()

    def classify_risk(self, tool_name: str, mcp_server: str | None = None) -> RiskTier:
        """
        Fail closed: unknown tools default to HIGH risk.

        Local tools are looked up by name. MCP tools are looked up only as '<server>/<tool>', so a
        downstream server cannot get a low tier by naming its tool `git_status` or `workspace_read`.
        """
        key = tool_key(tool_name, mcp_server)
        return self.config.tool_risk_tiers.get(key, RiskTier.HIGH)

    def capability_for(self, tool_name: str, mcp_server: str | None = None) -> ToolCapability | None:
        """Return the resolved ToolCapability for `(mcp_server, tool_name)`, if any."""
        return resolve_capability(
            tool_name,
            mcp_server,
            tool_capabilities=self.config.tool_capabilities,
            server_presets=self.config.server_presets,
        )

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
