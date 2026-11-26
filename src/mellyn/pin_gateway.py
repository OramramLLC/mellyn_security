"""
Guided AgBOM pinning CLI (`mellyn pin`) for unified `mellyn.toml` (`schema_version = 2`) deployments.

Spawns a downstream MCP stdio server inside a short-lived quarantined environment (explicit minimal env,
strict overall deadline, DEVNULL stderr), runs `initialize` and strict paginated `tools/list`, flags any
invisible or non-NFKC Unicode characters in tool definitions, computes `compute_tools_hash`, and upserts the
pinned `[[servers]]` block into `mellyn.toml` with fail-closed validation.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
import time
import tomllib
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from mellyn.egress_proxy import validate_egress_domain
from mellyn.gateway_config import SERVER_NAME
from mellyn.http_downstream import StreamableHttpDownstream
from mellyn.legacy_env import LEGACY_ENV_PREFIX
from mellyn.oauth_client import OAuthClientConfig, OAuthError, extract_url_host, validate_outbound_url
from mellyn.policy import SMB_SERVER_PRESETS, validate_argv
from mellyn.policy_loader import MAX_POLICY_BYTES, PolicyLoadError
from mellyn.scanner import _INVISIBLE_UNICODE_RE, invisible_unicode_tools
from mellyn.unified_config import load_unified_config, parse_unified_dict

DEFAULT_PIN_TIMEOUT_SECONDS = 15.0

_POSIX_DEFAULT_ENV_KEYS: tuple[str, ...] = ("PATH", "LANG", "LC_ALL", "HOME", "TMPDIR")
_WIN32_DEFAULT_ENV_KEYS: tuple[str, ...] = (
    "PATH",
    "SYSTEMROOT",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
    "LOCALAPPDATA",
    "APPDATA",
    "USERPROFILE",
)
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_BARE_TOML_KEY_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_SENSITIVE_ENV_PREFIXES: tuple[str, ...] = ("MELLYN_", LEGACY_ENV_PREFIX)


class GatewayPinError(RuntimeError):
    """Raised fail-closed when a downstream MCP server or unified config cannot be safely pinned."""


@dataclass(frozen=True)
class GatewayPinResult:
    """Structured result from inspecting and hashing a downstream MCP server's `tools/list`."""

    server_name: str
    command: tuple[str, ...] = ()
    preset: str | None = None
    trusted: bool = False
    tools: tuple[dict[str, Any], ...] = ()
    tools_sha256: str = ""
    warnings: tuple[str, ...] = ()
    transport: Literal["stdio", "streamable-http"] = "stdio"
    url: str | None = None
    oauth: OAuthClientConfig | None = None


def build_pin_env(allowed_env_keys: Sequence[str] = ()) -> dict[str, str]:
    """
    Build an explicit minimal environment for `mellyn pin`.

    Copies only minimal platform keys plus explicitly allowed variable names, rejecting empty/malformed
    names and refusing any `MELLYN_*` or retired-prefix variables.
    """
    defaults = _WIN32_DEFAULT_ENV_KEYS if sys.platform == "win32" else _POSIX_DEFAULT_ENV_KEYS
    env: dict[str, str] = {}
    for base_key in defaults:
        val = os.environ.get(base_key)
        if val is not None:
            env[base_key] = val

    for raw_entry in allowed_env_keys:
        if not isinstance(raw_entry, str):
            raise GatewayPinError("Allowed environment variable names must be strings.")
        for part in raw_entry.split(","):
            key = part.strip()
            if not key or not _ENV_KEY_RE.fullmatch(key):
                raise GatewayPinError(f"Invalid environment variable name '{key}' in --allow-env.")
            if key.upper().startswith(_SENSITIVE_ENV_PREFIXES):
                raise GatewayPinError(f"Refusing sensitive Mellyn variable '{key}' in --allow-env.")
            val = os.environ.get(key)
            if val is not None:
                env[key] = val

    env.setdefault("PYTHONUTF8", "1")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    return env


def _walk_unicode_anomalies(value: Any, *, tool_label: str, path: str, out: list[str]) -> None:
    if isinstance(value, str):
        if _INVISIBLE_UNICODE_RE.search(value):
            out.append(
                f"SECURITY WARNING: invisible/tag Unicode characters detected in tool '{tool_label}' at '{path}'."
            )
        if unicodedata.normalize("NFKC", value) != value:
            out.append(f"WARNING: non-NFKC compatibility Unicode characters in tool '{tool_label}' at '{path}'.")
        return
    if isinstance(value, list):
        for idx, item in enumerate(value):
            _walk_unicode_anomalies(item, tool_label=tool_label, path=f"{path}[{idx}]", out=out)
        return
    if isinstance(value, Mapping):
        for k, v in value.items():
            key_str = str(k)
            _walk_unicode_anomalies(key_str, tool_label=tool_label, path=f"{path}.<key:{key_str}>", out=out)
            _walk_unicode_anomalies(v, tool_label=tool_label, path=f"{path}.{key_str}", out=out)


def _scan_tool_warnings(tools: Sequence[Mapping[str, Any]]) -> tuple[str, ...]:
    warnings: list[str] = []
    seen: set[str] = set()
    for idx, entry in enumerate(tools):
        tname = entry.get("name")
        label = tname if isinstance(tname, str) and tname else f"index_{idx}"
        local: list[str] = []
        _walk_unicode_anomalies(entry, tool_label=label, path="definition", out=local)
        for msg in local:
            if msg not in seen:
                seen.add(msg)
                warnings.append(msg)
    return tuple(warnings)


def _inspect_downstream_tools(
    server: Any, *, name: str, timeout_seconds: float
) -> tuple[tuple[dict[str, Any], ...], str, tuple[str, ...]]:
    from mellyn.mcp_gateway import (
        MAX_LIST_PAGES,
        _valid_jsonrpc_response,
        _valid_name,
        compute_tools_hash,
        initialize_downstream,
    )

    tools: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    seen_cursors: set[str] = set()
    cursor: str | None = None
    deadline = time.monotonic() + timeout_seconds

    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise GatewayPinError(f"Timed out before initializing server '{name}'.")
        try:
            initialize_downstream(server, timeout=remaining)
        except (RuntimeError, TimeoutError, ValueError, OSError) as exc:
            raise GatewayPinError(f"MCP initialize failed for '{name}': {exc}") from exc

        for _ in range(MAX_LIST_PAGES):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GatewayPinError(f"Timed out fetching tools/list from '{name}'.")
            response = server.request("tools/list", {"cursor": cursor} if cursor else {}, timeout=remaining)
            if not _valid_jsonrpc_response(response) or not isinstance(response.get("result"), dict):
                err = response.get("error") if isinstance(response, dict) else None
                detail = f" ({err})" if isinstance(err, dict) else ""
                raise GatewayPinError(f"Server '{name}' did not return a valid tools/list result{detail}.")

            raw_tools = response["result"].get("tools")
            if not isinstance(raw_tools, list):
                raise GatewayPinError(f"Server '{name}' returned a malformed tools array.")
            for entry in raw_tools:
                if not isinstance(entry, dict) or not _valid_name(entry.get("name")):
                    raise GatewayPinError(f"Server '{name}' returned an invalid tool definition.")
                tname = entry["name"]
                if tname in seen_names:
                    raise GatewayPinError(f"Server '{name}' returned duplicate tool '{tname}'.")
                seen_names.add(tname)
                tools.append(dict(entry))

            next_cursor = response["result"].get("nextCursor")
            if next_cursor is None or next_cursor == "":
                break
            if not isinstance(next_cursor, str) or next_cursor in seen_cursors:
                raise GatewayPinError(f"Server '{name}' returned an invalid pagination cursor.")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        else:
            raise GatewayPinError(f"Server '{name}' exceeded MAX_LIST_PAGES ({MAX_LIST_PAGES}).")
    finally:
        try:
            server.kill_now()
        finally:
            server.close()

    try:
        tools_sha256 = compute_tools_hash(tools)
    except (TypeError, ValueError) as exc:
        raise GatewayPinError(f"Tool definitions from '{name}' could not be canonically hashed: {exc}") from exc

    invisible = invisible_unicode_tools(tools)
    if invisible:
        # A pinned server's tool descriptions are not tainted at runtime, so pinning hidden text would hand it to the
        # agent as trusted. Refuse, as the Airlock's pinner does.
        raise GatewayPinError(
            f"Tool definition(s) {', '.join(invisible)} from '{name}' contain invisible Unicode format/tag characters "
            "(potential pre-poisoned server); refusing to pin."
        )
    warnings = _scan_tool_warnings(tools)
    return tuple(tools), tools_sha256, warnings


def _validate_pin_common(
    name: str, *, preset: str | None, trusted: bool | None, timeout_seconds: float
) -> tuple[str | None, bool]:
    if not isinstance(name, str) or not SERVER_NAME.fullmatch(name):
        raise GatewayPinError(f"Server name '{name}' must use lowercase letters, digits, and single hyphens.")
    clean_preset: str | None = None
    if preset is not None:
        clean_preset = preset.strip().lower()
        if clean_preset not in SMB_SERVER_PRESETS:
            known = ", ".join(sorted(SMB_SERVER_PRESETS))
            raise GatewayPinError(f"Unknown preset '{preset}'. Known presets: {known}.")
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise GatewayPinError("timeout_seconds must be a finite positive number.")
    effective_trusted = (
        trusted
        if trusted is not None
        else (SMB_SERVER_PRESETS[clean_preset].trusted if clean_preset is not None else False)
    )
    return clean_preset, effective_trusted


def inspect_gateway_server(
    name: str,
    command: Sequence[str],
    *,
    preset: str | None = None,
    trusted: bool | None = None,
    allowed_env_keys: Sequence[str] = (),
    timeout_seconds: float = DEFAULT_PIN_TIMEOUT_SECONDS,
    cwd: Path | None = None,
) -> GatewayPinResult:
    """
    Launch `command` briefly inside a quarantined minimal environment, run `initialize` and strict paginated
    `tools/list`, kill the child immediately, and compute the canonical `tools_sha256` digest.
    """
    # Lazy import avoids importing `mellyn.mcp_gateway` during `mellyn.__init__` so
    # `python -m mellyn.mcp_gateway` does not import the module twice.
    from mellyn.mcp_gateway import StdioDownstream

    clean_preset, effective_trusted = _validate_pin_common(
        name, preset=preset, trusted=trusted, timeout_seconds=timeout_seconds
    )
    if not command:
        raise GatewayPinError("Downstream MCP server command must not be empty.")
    argv_list = list(command)
    argv_ok, argv_reason = validate_argv({"argv": argv_list})
    if not argv_ok:
        raise GatewayPinError(f"Server '{name}' command rejected: {argv_reason}")

    pin_env = build_pin_env(allowed_env_keys)

    effective_cwd: Path | None = None
    if cwd is not None:
        if cwd.is_symlink() or not cwd.is_dir():
            raise GatewayPinError(f"Working directory '{cwd}' does not exist or is a symlink.")
        effective_cwd = cwd.resolve()

    try:
        server = StdioDownstream(
            name,
            argv_list,
            cwd=effective_cwd,
            env=pin_env,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, ValueError) as exc:
        raise GatewayPinError(f"Failed to start MCP server '{name}': {exc}") from exc

    tools, tools_sha256, warnings = _inspect_downstream_tools(server, name=name, timeout_seconds=timeout_seconds)
    return GatewayPinResult(
        server_name=name,
        command=tuple(argv_list),
        preset=clean_preset,
        trusted=effective_trusted,
        tools=tools,
        tools_sha256=tools_sha256,
        warnings=warnings,
        transport="stdio",
    )


def inspect_remote_gateway_server(
    name: str,
    url: str,
    *,
    preset: str | None = None,
    trusted: bool | None = None,
    oauth: OAuthClientConfig | None = None,
    allowed_domains: frozenset[str] | None = None,
    timeout_seconds: float = DEFAULT_PIN_TIMEOUT_SECONDS,
    _allow_loopback_http: bool = False,
) -> GatewayPinResult:
    """
    Connect briefly to a remote `streamable-http` MCP server (with optional OAuth 2.1), run `initialize`
    and strict paginated `tools/list`, terminate the remote session cleanly, and compute `tools_sha256`.
    """
    clean_preset, effective_trusted = _validate_pin_common(
        name, preset=preset, trusted=trusted, timeout_seconds=timeout_seconds
    )
    try:
        clean_url = validate_outbound_url(
            url, allowed_domains=allowed_domains, allow_loopback_http=_allow_loopback_http
        )
        server = StreamableHttpDownstream(
            name,
            clean_url,
            oauth_config=oauth,
            allowed_domains=allowed_domains,
            _allow_loopback_http=_allow_loopback_http,
        )
    except (OSError, ValueError, OAuthError) as exc:
        raise GatewayPinError(f"Remote MCP server '{name}' URL or OAuth config rejected: {exc}") from exc

    tools, tools_sha256, warnings = _inspect_downstream_tools(server, name=name, timeout_seconds=timeout_seconds)
    return GatewayPinResult(
        server_name=name,
        command=(),
        preset=clean_preset,
        trusted=effective_trusted,
        tools=tools,
        tools_sha256=tools_sha256,
        warnings=warnings,
        transport="streamable-http",
        url=clean_url,
        oauth=oauth,
    )


def _toml_key(key: str) -> str:
    return key if _BARE_TOML_KEY_RE.fullmatch(key) else json.dumps(key, ensure_ascii=False)


def _toml_value(val: Any) -> str:
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, int):
        return str(val)
    if isinstance(val, float):
        if not math.isfinite(val):
            raise GatewayPinError("Non-finite float values cannot be serialized to TOML.")
        return repr(val)
    if isinstance(val, str):
        return json.dumps(val, ensure_ascii=False)
    if isinstance(val, list):
        return "[" + ", ".join(_toml_value(item) for item in val) + "]"
    raise GatewayPinError(f"Unsupported TOML value type: {type(val).__name__}")


_OAUTH_KEY_ORDER: tuple[str, ...] = (
    "flow",
    "allowed_authorization_servers",
    "client_id",
    "client_id_env",
    "client_secret_env",
    "bearer_token_env",
    "scopes",
    "resource",
    "token_endpoint",
    "authorization_endpoint",
    "token_cache_path",
)


def _oauth_dict(oauth: OAuthClientConfig) -> dict[str, Any]:
    out: dict[str, Any] = {"flow": oauth.flow}
    if oauth.allowed_authorization_servers:
        out["allowed_authorization_servers"] = list(oauth.allowed_authorization_servers)
    if oauth.client_id is not None:
        out["client_id"] = oauth.client_id
    if oauth.client_id_env is not None:
        out["client_id_env"] = oauth.client_id_env
    if oauth.client_secret_env is not None:
        out["client_secret_env"] = oauth.client_secret_env
    if oauth.bearer_token_env is not None:
        out["bearer_token_env"] = oauth.bearer_token_env
    if oauth.scopes:
        out["scopes"] = list(oauth.scopes)
    if oauth.resource is not None:
        out["resource"] = oauth.resource
    if oauth.token_endpoint is not None:
        out["token_endpoint"] = oauth.token_endpoint
    if oauth.authorization_endpoint is not None:
        out["authorization_endpoint"] = oauth.authorization_endpoint
    if oauth.token_cache_path is not None:
        out["token_cache_path"] = str(oauth.token_cache_path)
    return out


def _server_entry_dict(result: GatewayPinResult) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "name": result.server_name,
        "transport": result.transport,
    }
    if result.preset is not None:
        entry["preset"] = result.preset
    entry["trusted"] = result.trusted
    if result.transport == "streamable-http":
        if result.url is None:
            raise GatewayPinError("Remote server pin result requires 'url'.")
        entry["url"] = result.url
        if result.oauth is not None:
            entry["oauth"] = _oauth_dict(result.oauth)
    else:
        entry["command"] = list(result.command)
    entry["tools_sha256"] = result.tools_sha256
    return entry


def render_server_block(result: GatewayPinResult) -> str:
    """Render a standalone `[[servers]]` TOML block ready for inclusion in `mellyn.toml`."""
    entry = _server_entry_dict(result)
    lines = ["[[servers]]"]
    for key in ("name", "transport", "preset", "trusted", "command", "url", "tools_sha256"):
        if key in entry:
            lines.append(f"{key} = {_toml_value(entry[key])}")
    if "oauth" in entry and isinstance(entry["oauth"], Mapping):
        lines.append("")
        _emit_flat_table(lines, "servers.oauth", entry["oauth"], _OAUTH_KEY_ORDER)
    return "\n".join(lines).rstrip() + "\n"


def _emit_flat_table(
    lines: list[str], header: str, data: Mapping[str, Any], preferred_order: Sequence[str] = ()
) -> None:
    lines.append(f"[{header}]")
    emitted: set[str] = set()
    for key in preferred_order:
        if key in data:
            lines.append(f"{_toml_key(key)} = {_toml_value(data[key])}")
            emitted.add(key)
    for key in sorted(data):
        if key not in emitted:
            lines.append(f"{_toml_key(key)} = {_toml_value(data[key])}")
    lines.append("")


def _serialize_policy_section(lines: list[str], policy: Mapping[str, Any]) -> None:
    preferred = (
        "protected_paths",
        "untrusted_content_tools",
        "injection_escalate_threshold",
        "injection_deny_threshold",
        "deny_on_dlp_secret",
    )
    lines.append("[policy]")
    for key in preferred:
        if key in policy:
            lines.append(f"{_toml_key(key)} = {_toml_value(policy[key])}")
    lines.append("")

    risk_tiers = policy.get("tool_risk_tiers")
    if isinstance(risk_tiers, Mapping) and risk_tiers:
        _emit_flat_table(lines, "policy.tool_risk_tiers", risk_tiers)

    capabilities = policy.get("tool_capabilities")
    if isinstance(capabilities, Mapping):
        for cap_key in sorted(capabilities):
            cap_val = capabilities[cap_key]
            if isinstance(cap_val, Mapping):
                _emit_flat_table(lines, f"policy.tool_capabilities.{_toml_key(cap_key)}", cap_val)

    scoped_rules = policy.get("scoped_rules")
    if isinstance(scoped_rules, list):
        rule_order = ("rule_id", "tool_name", "mcp_server", "effect", "programs", "allow_when_tainted", "description")
        for rule in scoped_rules:
            if not isinstance(rule, Mapping):
                continue
            lines.append("[[policy.scoped_rules]]")
            for key in rule_order:
                if key in rule:
                    lines.append(f"{_toml_key(key)} = {_toml_value(rule[key])}")
            arg_equals = rule.get("arg_equals")
            lines.append("")
            if isinstance(arg_equals, Mapping) and arg_equals:
                _emit_flat_table(lines, "policy.scoped_rules.arg_equals", arg_equals)


def _serialize_unified_toml(data: Mapping[str, Any]) -> str:
    """Deterministically serialize a `schema_version = 2` `mellyn.toml` dictionary."""
    lines = [
        "# Mellyn Security — Unified Configuration (schema_version = 2)",
        "",
        f"schema_version = {int(data['schema_version'])}",
        "",
    ]

    if "runtime" in data and isinstance(data["runtime"], Mapping):
        _emit_flat_table(lines, "runtime", data["runtime"], ("mode", "allow_observe_mode", "state_db", "audit_log"))
    if "egress" in data and isinstance(data["egress"], Mapping):
        _emit_flat_table(lines, "egress", data["egress"], ("allowed_domains", "auto_sync_squid"))
    if "scanner" in data and isinstance(data["scanner"], Mapping):
        _emit_flat_table(
            lines,
            "scanner",
            data["scanner"],
            ("canary_tokens", "block_known_secrets", "aad_kill_on_leak", "blocked_patterns"),
        )
    if "policy" in data and isinstance(data["policy"], Mapping):
        _serialize_policy_section(lines, data["policy"])

    servers = data.get("servers", [])
    if isinstance(servers, list):
        srv_order = ("name", "transport", "preset", "trusted", "command", "url", "tools_sha256")
        for srv in servers:
            if not isinstance(srv, Mapping):
                continue
            lines.append("[[servers]]")
            emitted: set[str] = set()
            for key in srv_order:
                if key in srv:
                    lines.append(f"{key} = {_toml_value(srv[key])}")
                    emitted.add(key)
            for key in sorted(srv):
                if key not in emitted and key != "oauth":
                    lines.append(f"{_toml_key(key)} = {_toml_value(srv[key])}")
            lines.append("")
            if isinstance(srv.get("oauth"), Mapping):
                _emit_flat_table(lines, "servers.oauth", srv["oauth"], _OAUTH_KEY_ORDER)

    return "\n".join(lines).rstrip() + "\n"


def _add_public_url_domain(url: str, domains: list[str]) -> None:
    try:
        norm = validate_egress_domain(extract_url_host(url))
    except ValueError:
        return
    if norm not in domains:
        domains.append(norm)


def _starter_unified_dict(result: GatewayPinResult) -> dict[str, Any]:
    domains: list[str] = []
    if result.preset is not None:
        for dom in SMB_SERVER_PRESETS[result.preset].egress_domains:
            norm = validate_egress_domain(dom)
            if norm not in domains:
                domains.append(norm)
    if result.url is not None:
        _add_public_url_domain(result.url, domains)
    if result.oauth is not None:
        for oauth_url in (
            *result.oauth.allowed_authorization_servers,
            *([result.oauth.resource] if result.oauth.resource else ()),
            *([result.oauth.token_endpoint] if result.oauth.token_endpoint else ()),
            *([result.oauth.authorization_endpoint] if result.oauth.authorization_endpoint else ()),
        ):
            _add_public_url_domain(oauth_url, domains)
    return {
        "schema_version": 2,
        "runtime": {
            "mode": "enforce",
            "allow_observe_mode": False,
        },
        "egress": {
            "allowed_domains": domains,
            "auto_sync_squid": True,
        },
        "scanner": {
            "canary_tokens": [],
            "block_known_secrets": True,
            "aad_kill_on_leak": True,
            "blocked_patterns": [],
        },
        "policy": {
            "protected_paths": [],
            "injection_escalate_threshold": 0.70,
            "injection_deny_threshold": 0.90,
            "deny_on_dlp_secret": True,
        },
        "servers": [_server_entry_dict(result)],
    }


def upsert_server_in_unified_toml(config_path: Path, result: GatewayPinResult) -> str:
    """
    Create or update a `[[servers]]` entry inside a `schema_version = 2` `mellyn.toml`.

    Existing v1 files, symlinks, directories, and invalid TOML documents fail closed without modification.
    Round-trip validates rendered TOML through `parse_unified_dict` before writing.
    """
    try:
        if config_path.is_symlink() or config_path.parent.is_symlink():
            raise GatewayPinError(f"Refusing symlink config path '{config_path}'.")
    except OSError as exc:
        raise GatewayPinError(f"Unable to inspect config path '{config_path}': {exc}") from exc

    original_text: str | None = None
    if config_path.exists():
        if config_path.is_dir():
            raise GatewayPinError(f"Config path '{config_path}' is a directory.")
        # Fail closed on non-v2 (including v1 gateway/policy TOMLs) or invalid existing configs.
        load_unified_config(config_path)
        raw_bytes = config_path.read_bytes()
        if len(raw_bytes) > MAX_POLICY_BYTES:
            raise GatewayPinError("Unified config exceeds maximum byte size.")
        original_text = raw_bytes.decode("utf-8").replace("\r\n", "\n")
        data = tomllib.loads(original_text)
        servers = list(data.get("servers", []))
        new_entry = _server_entry_dict(result)
        replaced = False
        for idx, existing in enumerate(servers):
            if isinstance(existing, dict) and existing.get("name") == result.server_name:
                servers[idx] = new_entry
                replaced = True
                break
        if not replaced:
            servers.append(new_entry)
        data["servers"] = servers
    else:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        data = _starter_unified_dict(result)

    rendered: str | None = None
    if original_text is not None:
        # Edit only this server's block so the operator's comments (review notes, sign-offs) survive. Accept the edit
        # only if it means exactly what was intended: the original config with this one server added or replaced.
        candidate = _splice_server_block(original_text, result.server_name, render_server_block(result))
        try:
            if tomllib.loads(candidate) == data:
                rendered = candidate
        except tomllib.TOMLDecodeError:
            rendered = None
    if rendered is None:
        rendered = _serialize_unified_toml(data)
        if original_text is not None:
            backup = _write_atomic(config_path.with_name(f"{config_path.name}.bak"), original_text)
            print(
                f"mellyn pin: could not update '{config_path.name}' in place, so it was rewritten and its comments "
                f"were not kept; the previous version is saved as '{backup.name}'.",
                file=sys.stderr,
            )

    base_dir = config_path.parent.resolve()
    parse_unified_dict(tomllib.loads(rendered), base_dir=base_dir, config_path=config_path)
    _write_atomic(config_path, rendered)
    return rendered


def _splice_server_block(text: str, server_name: str, block: str) -> str:
    """
    Replace the `[[servers]]` block named `server_name` with `block`, or append `block`, leaving all other text as is.

    A block runs from its header to the next table header. Comment and blank lines at its end are kept, since they
    usually introduce the next section.
    """
    lines = text.split("\n")
    headers = [i for i, line in enumerate(lines) if line.lstrip().startswith("[")]
    block_lines = block.rstrip("\n").split("\n")
    for position, start in enumerate(headers):
        if lines[start].strip() != "[[servers]]":
            continue
        end = len(lines)
        for next_hdr in headers[position + 1 :]:
            stripped_hdr = lines[next_hdr].strip()
            if stripped_hdr.startswith("[servers.") and not stripped_hdr.startswith("[["):
                continue
            end = next_hdr
            break
        try:
            parsed = tomllib.loads("\n".join(lines[start:end]))
        except tomllib.TOMLDecodeError:
            continue
        entries = parsed.get("servers")
        if not (isinstance(entries, list) and entries and entries[0].get("name") == server_name):
            continue
        body_end = end
        while body_end > start + 1 and (
            not lines[body_end - 1].strip() or lines[body_end - 1].lstrip().startswith("#")
        ):
            body_end -= 1
        return "\n".join([*lines[:start], *block_lines, *lines[body_end:end], *lines[end:]])
    return text.rstrip("\n") + "\n\n" + "\n".join(block_lines) + "\n"


def _write_atomic(path: Path, text: str) -> Path:
    """Write `text` to `path` via a temporary file in the same folder, so a crash never leaves a half-written file."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except OSError as exc:
        tmp.unlink(missing_ok=True)
        raise GatewayPinError(f"Could not write '{path}': {exc}") from exc
    return path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mellyn pin",
        description="Inspect a downstream MCP server in isolation and pin its AgBOM SHA-256 digest into mellyn.toml.",
    )
    parser.add_argument("--name", required=True, help="Gateway server identifier (lowercase, digits, single hyphens)")
    parser.add_argument(
        "--preset",
        default=None,
        help=f"Optional curated SMB preset ({', '.join(sorted(SMB_SERVER_PRESETS))})",
    )
    parser.add_argument("--config", type=Path, default=None, help="Target unified mellyn.toml file to create/update")
    trust_grp = parser.add_mutually_exclusive_group()
    trust_grp.add_argument(
        "--trusted",
        dest="trusted",
        action="store_true",
        default=None,
        help="Mark server as trusted (tool descriptions and responses skip auto-tainting)",
    )
    trust_grp.add_argument(
        "--untrusted",
        dest="trusted",
        action="store_false",
        help="Mark server as untrusted (default unless preset sets trusted = true)",
    )
    parser.add_argument(
        "--allow-env",
        action="append",
        dest="allow_env",
        default=[],
        help="Explicitly allow an environment variable name when launching command (repeatable or comma-separated)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_PIN_TIMEOUT_SECONDS,
        help=f"Overall inspection timeout in seconds (default: {DEFAULT_PIN_TIMEOUT_SECONDS})",
    )
    parser.add_argument("--cwd", type=Path, default=None, help="Working directory for spawning the MCP server")
    parser.add_argument("--url", default=None, help="Remote Streamable HTTP MCP server URL (https://...)")
    parser.add_argument(
        "--oauth-flow",
        choices=("client_credentials", "pkce", "bearer_env"),
        default=None,
        help="OAuth 2.1 flow for remote Streamable HTTP MCP servers",
    )
    parser.add_argument(
        "--oauth-as",
        action="append",
        dest="oauth_as",
        default=[],
        help="Policy-pinned OAuth Authorization Server issuer URL (repeatable or comma-separated)",
    )
    parser.add_argument(
        "--bearer-token-env",
        default=None,
        help="Environment variable name holding a pre-provisioned bearer token (for --oauth-flow bearer_env)",
    )
    parser.add_argument("--client-id", default=None, help="Static OAuth client_id")
    parser.add_argument("--client-id-env", default=None, help="Environment variable name holding OAuth client_id")
    parser.add_argument(
        "--client-secret-env",
        default=None,
        help="Environment variable name holding OAuth client_secret",
    )
    parser.add_argument(
        "--scope",
        action="append",
        dest="scopes",
        default=[],
        help="OAuth scope to request (repeatable or comma-separated)",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON pin output")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Downstream MCP server command argv (after `--`)")
    return parser


def _split_csv_list(raw_entries: Sequence[str]) -> tuple[str, ...]:
    items: list[str] = []
    for raw in raw_entries:
        for part in raw.split(","):
            clean = part.strip()
            if clean:
                items.append(clean)
    return tuple(items)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for guided `mellyn pin` into unified `mellyn.toml`."""
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0

    cmd = list(args.command)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]

    oauth_as = _split_csv_list(args.oauth_as)
    oauth_scopes = _split_csv_list(args.scopes)
    has_oauth_flags = any(
        [
            args.oauth_flow,
            oauth_as,
            args.bearer_token_env,
            args.client_id,
            args.client_id_env,
            args.client_secret_env,
            oauth_scopes,
        ]
    )

    if args.url is not None and cmd:
        print("mellyn pin failed: specify either --url or a stdio command after `--`, not both.", file=sys.stderr)
        return 2

    if args.url is None:
        if has_oauth_flags:
            print("mellyn pin failed: --oauth-* flags require --url (streamable-http transport).", file=sys.stderr)
            return 2
        if not cmd:
            print("mellyn pin failed: downstream MCP server command or --url is required.", file=sys.stderr)
            return 2
    else:
        if args.cwd is not None or args.allow_env:
            print("mellyn pin failed: --cwd and --allow-env apply only to local stdio commands.", file=sys.stderr)
            return 2
        if has_oauth_flags and args.oauth_flow is None:
            print("mellyn pin failed: --oauth-flow is required when passing OAuth flags.", file=sys.stderr)
            return 2

    try:
        if args.url is not None:
            oauth_cfg: OAuthClientConfig | None = None
            if args.oauth_flow is not None:
                oauth_cfg = OAuthClientConfig(
                    flow=args.oauth_flow,
                    allowed_authorization_servers=oauth_as,
                    client_id=args.client_id,
                    client_id_env=args.client_id_env,
                    client_secret_env=args.client_secret_env,
                    bearer_token_env=args.bearer_token_env,
                    scopes=oauth_scopes,
                )
            result = inspect_remote_gateway_server(
                args.name,
                args.url,
                preset=args.preset,
                trusted=args.trusted,
                oauth=oauth_cfg,
                timeout_seconds=args.timeout,
            )
        else:
            result = inspect_gateway_server(
                args.name,
                cmd,
                preset=args.preset,
                trusted=args.trusted,
                allowed_env_keys=args.allow_env,
                timeout_seconds=args.timeout,
                cwd=args.cwd,
            )
        for warning in result.warnings:
            print(warning, file=sys.stderr)
        if args.config is not None:
            upsert_server_in_unified_toml(args.config, result)
    except (GatewayPinError, PolicyLoadError, OAuthError, ValueError, OSError, RuntimeError) as exc:
        print(f"mellyn pin failed (fail-closed): {exc}", file=sys.stderr)
        return 2

    if args.json:
        payload: dict[str, Any] = {
            "server_name": result.server_name,
            "transport": result.transport,
            "command": list(result.command),
            "url": result.url,
            "preset": result.preset,
            "trusted": result.trusted,
            "tools_count": len(result.tools),
            "tools_sha256": result.tools_sha256,
            "warnings": list(result.warnings),
            "config_path": str(args.config) if args.config is not None else None,
        }
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(
            f"Pinned MCP server '{result.server_name}' ({result.transport}, {len(result.tools)} tools, "
            f"trusted={str(result.trusted).lower()}, tools_sha256={result.tools_sha256})"
        )
        if args.config is not None:
            print(f"Updated unified config: {args.config}")
        else:
            print("\nAdd this entry to config/mellyn.toml:\n")
            sys.stdout.write(render_server_block(result))
    return 0


__all__ = [
    "DEFAULT_PIN_TIMEOUT_SECONDS",
    "GatewayPinError",
    "GatewayPinResult",
    "build_pin_env",
    "inspect_gateway_server",
    "inspect_remote_gateway_server",
    "main",
    "render_server_block",
    "upsert_server_in_unified_toml",
]


if __name__ == "__main__":
    raise SystemExit(main())
