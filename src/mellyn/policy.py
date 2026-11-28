"""Scoped tool-call policy definitions, capability bindings, and evaluation rules."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from mellyn.models import Decision, RiskTier, ToolCallRequest, canonical_json_value

DEFAULT_TOOL_RISK_TIERS: dict[str, RiskTier] = {
    # Low-risk: single-file read-only or pure metadata inside workspace
    "workspace_read": RiskTier.LOW,
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

# Programs that interpret a command string or dispatch arbitrary child commands, which would
# reintroduce shell/command injection through argv.
SHELL_INTERPRETERS: frozenset[str] = frozenset(
    {
        "sh",
        "bash",
        "zsh",
        "dash",
        "ksh",
        "fish",
        "csh",
        "tcsh",
        "cmd",
        "powershell",
        "pwsh",
        "env",
        "xargs",
        "busybox",
        "toybox",
        "nohup",
        "sudo",
        "su",
        "doas",
        "eval",
        "exec",
        "awk",
        "gawk",
        "mawk",
        "nawk",
    }
)

_PYTHON_PROG_RE = re.compile(r"^(?:python(?:\d+(?:\.\d+)?)?|py)$")
_NODE_RUNTIMES: frozenset[str] = frozenset({"node", "nodejs", "deno", "bun"})
_PERL_RUBY_RUNTIMES: frozenset[str] = frozenset({"perl", "ruby"})
_LUA_RUNTIMES: frozenset[str] = frozenset({"lua", "luajit"})
_FIND_EXEC_FLAGS: frozenset[str] = frozenset({"-exec", "-execdir", "-ok", "-okdir", "-delete"})

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
# Recursive content-search tools are intentionally excluded unless implemented by a guard-enforcing adapter
# (see WorkspacePathGuard.search_content), because checking only a starting directory does not enforce
# per-file secret denial inside an opaque downstream tool.
DEFAULT_TOOL_CAPABILITIES: dict[str, ToolCapability] = {
    "workspace_read": ToolCapability(path_read_args=("path",)),
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
# Recursive directory/content traversal tools (`search_files`, `directory_tree`) are omitted so they cannot
# be marked LOW/MEDIUM without a per-file secret-filtering implementation.
MCP_CAPABILITY_PRESETS: dict[str, dict[str, ToolCapability]] = {
    "mcp-filesystem": {
        "read_file": ToolCapability(path_read_args=("path",)),
        "read_text_file": ToolCapability(path_read_args=("path",)),
        "read_media_file": ToolCapability(path_read_args=("path",)),
        "read_multiple_files": ToolCapability(path_read_list_args=("paths",)),
        "list_directory": ToolCapability(path_read_args=("path",)),
        "list_directory_with_sizes": ToolCapability(path_read_args=("path",)),
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
    "github": {
        "get_issue": ToolCapability(pure=True),
        "list_issues": ToolCapability(pure=True),
        "search_issues": ToolCapability(pure=True),
        "get_pull_request": ToolCapability(pure=True),
        "list_pull_requests": ToolCapability(pure=True),
        "get_pull_request_diff": ToolCapability(pure=True),
        "get_pull_request_files": ToolCapability(pure=True),
        "get_file_contents": ToolCapability(pure=True),
        "list_commits": ToolCapability(pure=True),
        "get_commit": ToolCapability(pure=True),
        "search_code": ToolCapability(pure=True),
        "search_repositories": ToolCapability(pure=True),
        "list_branches": ToolCapability(pure=True),
    },
    "linear": {
        "list_issues": ToolCapability(pure=True),
        "get_issue": ToolCapability(pure=True),
        "search_issues": ToolCapability(pure=True),
        "list_projects": ToolCapability(pure=True),
        "get_project": ToolCapability(pure=True),
        "list_teams": ToolCapability(pure=True),
        "list_issue_statuses": ToolCapability(pure=True),
        "list_issue_labels": ToolCapability(pure=True),
        "list_comments": ToolCapability(pure=True),
    },
    "slack": {
        "list_channels": ToolCapability(pure=True),
        "get_channel_history": ToolCapability(pure=True),
        "get_thread_replies": ToolCapability(pure=True),
        "search_messages": ToolCapability(pure=True),
        "get_user_profile": ToolCapability(pure=True),
        "list_users": ToolCapability(pure=True),
    },
    "postgres": {
        "query": ToolCapability(pure=True),
        "list_tables": ToolCapability(pure=True),
        "describe_table": ToolCapability(pure=True),
        "list_schemas": ToolCapability(pure=True),
    },
}


@dataclass(frozen=True)
class ServerPresetProfile:
    """Turn-key SMB onboarding defaults pairing a capability preset with risk, trust, and egress settings."""

    preset_name: str
    default_server_name: str
    trusted: bool
    egress_domains: tuple[str, ...]
    default_tool_risk_tiers: dict[str, RiskTier]
    example_command: tuple[str, ...]
    description: str


SMB_SERVER_PRESETS: dict[str, ServerPresetProfile] = {
    "mcp-filesystem": ServerPresetProfile(
        preset_name="mcp-filesystem",
        default_server_name="local-workspace",
        trusted=True,
        egress_domains=(),
        default_tool_risk_tiers={
            "read_file": RiskTier.LOW,
            "read_text_file": RiskTier.LOW,
            "read_media_file": RiskTier.LOW,
            "read_multiple_files": RiskTier.LOW,
            "list_directory": RiskTier.LOW,
            "list_directory_with_sizes": RiskTier.LOW,
            "get_file_info": RiskTier.LOW,
            "list_allowed_directories": RiskTier.LOW,
            "write_file": RiskTier.MEDIUM,
            "edit_file": RiskTier.MEDIUM,
            "create_directory": RiskTier.MEDIUM,
            "move_file": RiskTier.MEDIUM,
        },
        example_command=("replace-with-your-workspace-mcp-server", "--root", "."),
        description="Local workspace file read/write tools (trusted, workspace-jailed paths).",
    ),
    "mcp-fetch": ServerPresetProfile(
        preset_name="mcp-fetch",
        default_server_name="web-fetch",
        trusted=False,
        egress_domains=(),
        default_tool_risk_tiers={"fetch": RiskTier.MEDIUM},
        example_command=("replace-with-your-fetch-mcp-server",),
        description="Outbound HTTPS fetch tool (untrusted responses; SSRF & allowlist guarded).",
    ),
    "github": ServerPresetProfile(
        preset_name="github",
        default_server_name="github",
        trusted=False,
        egress_domains=("api.github.com",),
        default_tool_risk_tiers={name: RiskTier.LOW for name in MCP_CAPABILITY_PRESETS["github"]},
        example_command=("replace-with-your-github-mcp-server", "--read-only"),
        description="GitHub read tools LOW (tainting session); writes/merges/pushes remain HIGH.",
    ),
    "linear": ServerPresetProfile(
        preset_name="linear",
        default_server_name="linear",
        trusted=False,
        egress_domains=("api.linear.app",),
        default_tool_risk_tiers={name: RiskTier.LOW for name in MCP_CAPABILITY_PRESETS["linear"]},
        example_command=("replace-with-your-linear-mcp-server", "--read-only"),
        description="Linear read tools LOW (tainting session); mutations remain HIGH.",
    ),
    "slack": ServerPresetProfile(
        preset_name="slack",
        default_server_name="slack",
        trusted=False,
        egress_domains=("api.slack.com", "slack.com"),
        default_tool_risk_tiers={name: RiskTier.LOW for name in MCP_CAPABILITY_PRESETS["slack"]},
        example_command=("replace-with-your-slack-mcp-server", "--read-only"),
        description="Slack channel/history read tools LOW (tainting session); posting stays HIGH.",
    ),
    "postgres": ServerPresetProfile(
        preset_name="postgres",
        default_server_name="postgres",
        trusted=False,
        egress_domains=(),
        default_tool_risk_tiers={
            "list_tables": RiskTier.LOW,
            "describe_table": RiskTier.LOW,
            "list_schemas": RiskTier.LOW,
            # `query` runs whatever SQL it is given: SELECT, but also DROP, UPDATE, or COPY ... TO PROGRAM on servers
            # that are not truly read-only, and this preset cannot verify that. MEDIUM means it needs human approval
            # once the session is tainted, so injected instructions cannot run SQL on their own.
            "query": RiskTier.MEDIUM,
        },
        example_command=("replace-with-your-postgres-mcp-server", "--readonly"),
        description="Schema inspection LOW (tainting); arbitrary SQL `query` MEDIUM, needing approval once tainted.",
    ),
}


def tool_key(tool_name: str, mcp_server: str | None) -> str:
    """Risk-tier and capability key: bare name for local tools, '<server>/<tool>' for MCP tools."""
    return tool_name if mcp_server is None else f"{mcp_server}/{tool_name}"


def program_name(argv0: str) -> str:
    """Basename of argv[0], lower-cased, without trailing Win32 dots/spaces or executable suffix."""
    name = re.split(r"[\\/]", argv0)[-1].lower().rstrip(". ")
    return re.sub(r"\.(exe|cmd|bat|com)$", "", name).rstrip(". ")


def _short_option_clusters(rest: tuple[str, ...], value_letters: str, long_with_value: frozenset[str]):
    """
    Yield (letter, cluster) for each short option letter before the first operand, the way getopt reads
    them: `-Ic` is `-I -c`; a letter in `value_letters` takes the rest of its cluster (`-Wignore`) or, when
    nothing follows it, the next argument (`-W ignore`) as its value. Long options in `long_with_value`
    consume the next argument. Stops at the first operand (the script or module) or `--`.
    """
    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg == "--" or not arg.startswith("-") or arg == "-":
            return
        if arg.startswith("--"):
            if arg in long_with_value:
                i += 1  # skip its separate value
            i += 1
            continue
        for pos, letter in enumerate(arg[1:], start=1):
            yield letter, arg
            if letter in value_letters:
                if pos == len(arg) - 1:
                    i += 1  # value is the next argument
                break  # the rest of this cluster is the value
        i += 1


def _has_inline_eval_flag(prog: str, rest: tuple[str, ...]) -> str | None:
    """
    Return a denial reason if argv asks an interpreter to evaluate inline code or hook a command.

    This is a best-effort blocklist, not a boundary: shell tools are HIGH risk and need an exact allow rule
    or a human approval regardless. It parses each runtime's own option syntax (combined short flags such
    as `-Ic` or `-le`, and flags that take a value such as `-W ignore`), so the obvious spellings of the
    same command are caught too.
    """
    if _PYTHON_PROG_RE.fullmatch(prog):
        for letter, _cluster in _short_option_clusters(rest, "WXQm", frozenset({"--check-hash-based-pycs"})):
            if letter == "c":
                return "Inline Python code evaluation ('-c') is denied."
            if letter == "m":
                return None  # `-m module`: everything after belongs to the module
    elif prog in _NODE_RUNTIMES:
        operands = [arg for arg in rest if not arg.startswith("-")]
        if prog == "deno" and operands[:1] == ["eval"]:
            return "Inline JavaScript evaluation ('deno eval') is denied."
        for arg in rest:
            if arg in ("-e", "--eval", "-p", "--print") or arg.startswith(("--eval=", "--print=")):
                return "Inline JavaScript evaluation flag is denied."
            if arg.startswith("-") and not arg.startswith("--") and any(c in "ep" for c in arg[1:]):
                return "Inline JavaScript evaluation flag is denied."
            if "data:" in arg:
                return "Loading code from a data: URL is denied."
    elif prog == "perl":
        for letter, cluster in _short_option_clusters(rest, "IMmixdDC0", frozenset()):
            if letter in "eE":
                return f"Inline Perl evaluation ('-{letter}') is denied."
            if letter in "Mm":
                value = cluster.split(letter, 1)[1]
                if value and not re.fullmatch(r"-?[A-Za-z0-9_:]+(=[A-Za-z0-9_,:]*)?", value):
                    return "Perl module option contains inline code, which is denied."
    elif prog == "ruby":
        for letter, _cluster in _short_option_clusters(rest, "IrCEKxi0FW", frozenset()):
            if letter == "e":
                return "Inline Ruby evaluation ('-e') is denied."
    elif prog == "php":
        for letter, _cluster in _short_option_clusters(rest, "cdfz", frozenset()):
            if letter in "rRBE":
                return f"Inline PHP evaluation ('-{letter}') is denied."
        if "--run" in rest:
            return "Inline PHP evaluation ('--run') is denied."
    elif prog in _LUA_RUNTIMES:
        for letter, _cluster in _short_option_clusters(rest, "l", frozenset()):
            if letter == "e":
                return "Inline Lua evaluation ('-e') is denied."
    elif prog == "find":
        for arg in rest:
            if arg in _FIND_EXEC_FLAGS:
                return f"Dangerous 'find' action flag '{arg}' is denied."
    elif prog == "git":
        i = 0
        while i < len(rest):
            arg = rest[i]
            if arg == "-c" or arg.startswith("-c") or arg == "--config-env" or arg.startswith("--config-env="):
                return "Inline git configuration override is denied."
            if arg.startswith("--exec-path="):
                return "Overriding git's helper directory is denied."
            if arg in ("-C", "--git-dir", "--work-tree", "--namespace", "--super-prefix"):
                i += 2  # these take the next argument as their value
                continue
            if not arg.startswith("-"):
                break  # the git subcommand
            i += 1
    return None


def validate_argv(arguments: Mapping[str, Any], *, argv_key: str = "argv") -> tuple[bool, str]:
    """Shell tools take a non-empty list of strings under `argv_key`, and nothing a shell or inline eval would parse."""
    if "command" in arguments and argv_key != "command":
        return False, "Shell command strings are not accepted; pass an 'argv' list so no shell parses it."
    argv = arguments.get(argv_key)
    if not isinstance(argv, list | tuple) or not argv or not all(isinstance(a, str) and a for a in argv):
        return False, f"Shell tools require '{argv_key}' as a non-empty list of non-empty strings."
    prog = program_name(argv[0])
    if prog in SHELL_INTERPRETERS:
        return False, f"Running the command interpreter '{prog}' is denied."
    eval_reason = _has_inline_eval_flag(prog, tuple(argv[1:]))
    if eval_reason is not None:
        return False, eval_reason
    return True, f"Shell argv validated ({len(argv) - 1} argument(s))."


# Alias to the single strict canonical JSON value normalizer in models.py.
normalize_arg_value = canonical_json_value


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
    _compiled_arg_equals: Mapping[str, frozenset[str]] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.effect == Decision.ALLOW and self.programs:
            raise ValueError(
                f"Rule '{self.rule_id}': ALLOW rules cannot use 'programs' (it would allow any arguments); "
                "list the exact argv under 'arg_equals' instead."
            )
        compiled: dict[str, frozenset[str]] = {}
        for key, allowed_values in self.arg_equals.items():
            compiled[key] = frozenset(canonical_json_value(val) for val in allowed_values)
        object.__setattr__(self, "_compiled_arg_equals", compiled)

    def matches(self, request: ToolCallRequest, *, argv_key: str = "argv") -> bool:
        if self.tool_name != request.tool_name:
            return False
        if self.mcp_server != request.mcp_server and not (self.effect == Decision.DENY and self.mcp_server is None):
            return False
        args = request.arguments
        for key, allowed_canonical in self._compiled_arg_equals.items():
            if key not in args:
                return False
            try:
                actual_norm = canonical_json_value(args[key])
            except (TypeError, ValueError):
                return False
            if actual_norm not in allowed_canonical:
                return False
        if self.programs:
            argv = args.get(argv_key)
            if not isinstance(argv, list | tuple) or not argv or not isinstance(argv[0], str):
                return False
            if program_name(argv[0]) not in {p.lower() for p in self.programs}:
                return False
        if self.effect != Decision.DENY:
            named = set(self.arg_equals) | ({argv_key} if self.programs else set())
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
      3. Built-in `DEFAULT_TOOL_CAPABILITIES` for canonical tool names (`workspace_read`, `shell_exec`, ...);
         unbound MCP servers never inherit `pure=True` by bare name alone.
    """
    key = tool_key(tool_name, mcp_server)
    if key in tool_capabilities:
        return tool_capabilities[key]
    if mcp_server is not None and mcp_server in server_presets:
        preset_map = MCP_CAPABILITY_PRESETS.get(server_presets[mcp_server], {})
        if tool_name in preset_map:
            return preset_map[tool_name]
    default_cap = DEFAULT_TOOL_CAPABILITIES.get(tool_name)
    if mcp_server is not None and default_cap is not None and default_cap.pure:
        return None
    return default_cap


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
        configured_servers: set[str] = set(self.config.allowed_mcp_servers or ())
        configured_servers.update(self.config.trusted_mcp_servers)
        configured_servers.update(self.config.server_presets)
        configured_servers.update(self.config.pinned_tool_hashes)
        for key in (*self.config.tool_risk_tiers, *self.config.tool_capabilities):
            if "/" in key:
                srv, _, _ = key.partition("/")
                if srv:
                    configured_servers.add(srv)
        for rule in self.config.scoped_rules:
            if rule.mcp_server:
                configured_servers.add(rule.mcp_server)
        self._known_servers: frozenset[str] = frozenset(configured_servers)

        known_tools: set[str] = {
            "resources/read",
            *DEFAULT_TOOL_RISK_TIERS,
            *DEFAULT_TOOL_CAPABILITIES,
            *DEFAULT_UNTRUSTED_CONTENT_TOOLS,
            *SHELL_TOOL_NAMES,
        }
        for preset_tools in MCP_CAPABILITY_PRESETS.values():
            known_tools.update(preset_tools)
        for key in (*self.config.tool_risk_tiers, *self.config.tool_capabilities):
            if "/" in key and not key.endswith("/resources/read"):
                _, _, tname = key.partition("/")
                known_tools.add(tname)
            else:
                known_tools.add(key)
        for rule in self.config.scoped_rules:
            known_tools.add(rule.tool_name)
        self._known_tools: frozenset[str] = frozenset(known_tools)

    def is_known_mcp_server(self, mcp_server: str | None) -> bool:
        """True when `mcp_server` is None (local) or declared in policy configuration."""
        return mcp_server is None or mcp_server in self._known_servers

    def is_known_tool(self, tool_name: str, mcp_server: str | None = None) -> bool:
        """True when `tool_name` is a built-in, preset, or policy-configured tool identifier."""
        if tool_key(tool_name, mcp_server) in self.config.tool_risk_tiers:
            return True
        if tool_key(tool_name, mcp_server) in self.config.tool_capabilities:
            return True
        return tool_name in self._known_tools

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

    def has_explicit_capability(self, tool_name: str, mcp_server: str | None = None) -> bool:
        """True when `(mcp_server, tool_name)` is bound via `tool_capabilities` or `server_presets`."""
        key = tool_key(tool_name, mcp_server)
        if key in self.config.tool_capabilities:
            return True
        if mcp_server is not None and mcp_server in self.config.server_presets:
            preset_map = MCP_CAPABILITY_PRESETS.get(self.config.server_presets[mcp_server], {})
            return tool_name in preset_map
        return False

    def check_mcp_server(self, mcp_server: str | None) -> tuple[bool, str]:
        """Verify MCP server against the allowlist (defaults to an empty allowlist when omitted)."""
        if mcp_server is None:
            return True, "Local/non-MCP tool call."
        if self.config.allowed_mcp_servers and mcp_server in self.config.allowed_mcp_servers:
            return True, f"MCP server '{mcp_server}' is allowlisted."
        return False, "MCP server is not in the approved MCP server allowlist."

    def brings_untrusted_content(self, request: ToolCallRequest) -> bool:
        """True when the call's result will put outside content into the agent's context."""
        if request.tool_name in self.config.untrusted_content_tools:
            return True
        return request.mcp_server is not None and request.mcp_server not in self.config.trusted_mcp_servers

    def match_scoped_rule(self, request: ToolCallRequest, *, argv_key: str | None = None) -> ScopedRule | None:
        """
        Return the highest-precedence matching scoped rule.
        Explicit DENY rules always take precedence over ALLOW/REQUIRE_APPROVAL rules.
        """
        if argv_key is None:
            cap = self.capability_for(request.tool_name, request.mcp_server)
            resolved_argv_key = cap.shell_argv_arg if cap is not None and cap.shell_argv_arg is not None else "argv"
        else:
            resolved_argv_key = argv_key
        matched = [rule for rule in self.config.scoped_rules if rule.matches(request, argv_key=resolved_argv_key)]
        for rule in matched:
            if rule.effect == Decision.DENY:
                return rule
        return matched[0] if matched else None
