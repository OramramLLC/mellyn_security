"""Strict, fail-closed loader for the MCP gateway's deployment file (which servers to launch, which policy)."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from mellyn.oauth_client import OAuthClientConfig
from mellyn.policy import validate_argv
from mellyn.policy_loader import MAX_POLICY_BYTES, PolicyLoadError

# Lowercase letters, digits and single hyphens. No underscores, so "<server>__<tool>" always splits cleanly.
SERVER_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){0,62}$")
_TOP_LEVEL_KEYS = frozenset({"schema_version", "policy", "servers"})
_SERVER_KEYS = frozenset({"name", "command"})

# Variables a downstream server never receives, even when a `[[servers]] pass_env` entry names them: each makes the
# child's loader or language runtime load or run extra code (preloads, interpreter startup files, option strings).
# Enforced both when the config is parsed (`mellyn.unified_config`) and in `mellyn.mcp_gateway.downstream_environment`.
CODE_INJECTION_ENV_NAMES: frozenset[str] = frozenset(
    {
        # Dynamic loaders (glibc, macOS dyld)
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        # Python
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
        # Node.js
        "NODE_OPTIONS",
        "NODE_PATH",
        # Perl, Ruby, Java/JVM
        "PERL5OPT",
        "PERL5LIB",
        "PERLLIB",
        "RUBYOPT",
        "RUBYLIB",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_JAVA_OPTIONS",
        # Shell startup files for non-interactive shells
        "BASH_ENV",
        "ENV",
    }
)


@dataclass(frozen=True)
class ServerSpec:
    name: str
    command: tuple[str, ...] = ()
    transport: Literal["stdio", "streamable-http"] = "stdio"
    url: str | None = None
    oauth: OAuthClientConfig | None = None
    pass_env: tuple[str, ...] = ()


@dataclass(frozen=True)
class GatewayConfig:
    path: Path
    policy_path: Path
    servers: tuple[ServerSpec, ...]


def load_gateway_config(path: Path) -> GatewayConfig:
    """Load a gateway .toml file. `policy` is resolved relative to the config file's directory."""
    if not path.is_file():
        raise PolicyLoadError(f"Gateway config does not exist: {path}")
    raw = path.read_bytes()
    if len(raw) > MAX_POLICY_BYTES:
        raise PolicyLoadError("Gateway config is too large.")
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise PolicyLoadError(f"Failed to parse gateway config '{path.name}': {exc}") from exc

    unknown = set(data) - _TOP_LEVEL_KEYS
    if unknown:
        raise PolicyLoadError(f"Gateway config contains unknown key(s): {sorted(unknown)}")
    if data.get("schema_version") != 1:
        raise PolicyLoadError("Gateway config requires schema_version = 1.")
    policy = data.get("policy")
    if not isinstance(policy, str) or not policy.strip():
        raise PolicyLoadError("Gateway config requires 'policy', the path to a policy file.")

    servers_raw = data.get("servers")
    if not isinstance(servers_raw, list) or not servers_raw:
        raise PolicyLoadError("Gateway config requires at least one [[servers]] entry.")
    servers: list[ServerSpec] = []
    for idx, entry in enumerate(servers_raw):
        if not isinstance(entry, dict) or set(entry) != _SERVER_KEYS:
            raise PolicyLoadError(f"servers[{idx}] must have exactly the keys 'name' and 'command'.")
        name, command = entry["name"], entry["command"]
        if not isinstance(name, str) or not SERVER_NAME.fullmatch(name):
            raise PolicyLoadError(f"servers[{idx}] name must be lowercase letters, digits and single hyphens.")
        if any(s.name == name for s in servers):
            raise PolicyLoadError(f"Duplicate server name '{name}'.")
        argv_ok, argv_reason = validate_argv({"argv": command})
        if not argv_ok:
            raise PolicyLoadError(f"Server '{name}' command rejected: {argv_reason}")
        servers.append(ServerSpec(name=name, command=tuple(command)))

    return GatewayConfig(
        path=path.resolve(),
        policy_path=(path.parent / policy.strip()).resolve(),
        servers=tuple(servers),
    )
