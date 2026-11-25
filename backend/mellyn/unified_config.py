"""
Unified `mellyn.toml` (`schema_version = 2`) configuration loader and backward-compatible v1 dispatcher.

Combines policy rules, downstream server declarations, egress settings, obfuscated canary/secret
scanning, and runtime containment/observe options into one fail-closed file.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from mellyn.egress_proxy import validate_egress_domain
from mellyn.gateway_config import SERVER_NAME, GatewayConfig, ServerSpec, load_gateway_config
from mellyn.models import RiskTier
from mellyn.notifications import NotificationsConfig
from mellyn.oauth_client import OAuthClientConfig, extract_url_host, validate_outbound_url
from mellyn.oauth_resource import AuthConfig
from mellyn.policy import (
    SMB_SERVER_PRESETS,
    PolicyConfig,
    ServerPresetProfile,
    validate_argv,
)
from mellyn.policy_loader import MAX_POLICY_BYTES, PolicyLoadError, load_policy_file, parse_policy_dict
from mellyn.scanner import ScannerConfig

_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

_UNIFIED_TOP_KEYS = frozenset(
    {"schema_version", "runtime", "egress", "auth", "notifications", "policy", "scanner", "servers"}
)
_RUNTIME_KEYS = frozenset({"mode", "allow_observe_mode", "state_db", "audit_log"})
_EGRESS_KEYS = frozenset({"allowed_domains", "auto_sync_squid"})
_NOTIFICATIONS_KEYS = frozenset(
    {
        "approval_webhook_url_env",
        "webhook_host",
        "webhook_format",
        "console_base_url",
        "timeout_seconds",
    }
)
# A webhook URL is itself the credential (anyone holding it can post to the channel), so it lives in the
# environment like every other secret, never in mellyn.toml.
_FORBIDDEN_NOTIFICATION_KEYS = frozenset(
    {"approval_webhook_url", "webhook_url", "webhook_secret", "signing_secret", "bot_token", "slack_token"}
)
_AUTH_KEYS = frozenset(
    {
        "mode",
        "issuer",
        "audience",
        "resource",
        "jwks_uri",
        "required_scopes",
        "approver_scopes",
        "approver_subjects",
        "approver_groups",
        "allowed_origins",
        "allowed_hosts",
        "clock_skew_seconds",
    }
)
_FORBIDDEN_AUTH_RAW_KEYS = frozenset(
    {"client_secret", "hmac_secret", "pepper", "signing_key", "private_key", "jwt_secret"}
)
_SCANNER_KEYS = frozenset({"canary_tokens", "block_known_secrets", "aad_kill_on_leak", "blocked_patterns"})
_SERVER_KEYS = frozenset({"name", "transport", "preset", "trusted", "command", "url", "oauth", "tools_sha256"})
_OAUTH_KEYS = frozenset(
    {
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
    }
)
_FORBIDDEN_OAUTH_RAW_KEYS = frozenset({"client_secret", "bearer_token", "access_token", "refresh_token"})
_POLICY_SECTION_KEYS = frozenset(
    {
        "protected_paths",
        "untrusted_content_tools",
        "tool_risk_tiers",
        "tool_capabilities",
        "scoped_rules",
        "injection_escalate_threshold",
        "injection_deny_threshold",
        "deny_on_dlp_secret",
    }
)


@dataclass(frozen=True)
class RuntimeConfig:
    """Execution mode and durable file paths for the unified proxy runtime."""

    mode: Literal["enforce", "observe"] = "enforce"
    allow_observe_mode: bool = False
    state_db: Path | None = None
    audit_log: Path | None = None


@dataclass(frozen=True)
class UnifiedConfig:
    """Resolved Mellyn runtime configuration parsed from v2 `mellyn.toml` or v1 paired files."""

    path: Path
    schema_version: int
    policy: PolicyConfig
    gateway: GatewayConfig
    runtime: RuntimeConfig
    scanner: ScannerConfig
    auto_sync_squid: bool = True
    auth: AuthConfig = field(default_factory=AuthConfig)
    notifications: NotificationsConfig = field(default_factory=NotificationsConfig)
    # Hosts only the gateway process contacts (identity provider, approval webhook). Kept out of
    # `policy.allowed_egress_domains`, which bounds where tools may send data: a shared webhook host such as
    # hooks.slack.com there would let a tool post to anyone's webhook. Squid still allows them (see egress_proxy).
    gateway_egress_domains: frozenset[str] = frozenset()

    @property
    def secret_env_names(self) -> tuple[str, ...]:
        """Environment variables this config names as secrets; downstream MCP servers must not inherit them."""
        names: list[str] = list(self.notifications.secret_env_names)
        for spec in self.gateway.servers:
            if spec.oauth is not None:
                names.extend(n for n in (spec.oauth.client_secret_env, spec.oauth.bearer_token_env) if n)
        return tuple(dict.fromkeys(names))


def _require_mapping(raw: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping):
        raise PolicyLoadError(f"Section '{label}' must be a TOML table/object.")
    return raw


def _require_bool(mapping: Mapping[str, Any], key: str, default: bool, label: str) -> bool:
    if key not in mapping:
        return default
    val = mapping[key]
    if not isinstance(val, bool):
        raise PolicyLoadError(f"Field '{label}.{key}' must be a boolean.")
    return val


def _require_str_list(mapping: Mapping[str, Any], key: str, label: str) -> list[str]:
    if key not in mapping:
        return []
    val = mapping[key]
    if not isinstance(val, list) or not all(isinstance(item, str) and item.strip() for item in val):
        raise PolicyLoadError(f"Field '{label}.{key}' must be a list of non-empty strings.")
    return [item.strip() for item in val]


def _parse_runtime_section(raw: Any, *, base_dir: Path) -> RuntimeConfig:
    if raw is None:
        return RuntimeConfig()
    sec = _require_mapping(raw, "runtime")
    unknown = set(sec) - _RUNTIME_KEYS
    if unknown:
        raise PolicyLoadError(f"[runtime] contains unknown key(s): {sorted(unknown)}")

    mode_raw = sec.get("mode", "enforce")
    if not isinstance(mode_raw, str) or mode_raw.strip() not in ("enforce", "observe"):
        raise PolicyLoadError("[runtime].mode must be 'enforce' or 'observe'.")
    mode: Literal["enforce", "observe"] = "observe" if mode_raw.strip() == "observe" else "enforce"

    allow_observe = _require_bool(sec, "allow_observe_mode", False, "runtime")
    if mode == "observe" and not allow_observe:
        raise PolicyLoadError(
            "[runtime].mode = 'observe' requires explicit [runtime].allow_observe_mode = true (fail closed)."
        )

    def _opt_path(key: str) -> Path | None:
        if key not in sec:
            return None
        val = sec[key]
        if not isinstance(val, str) or not val.strip():
            raise PolicyLoadError(f"[runtime].{key} must be a non-empty path string.")
        raw_p = Path(val.strip())
        return raw_p.resolve() if raw_p.is_absolute() else (base_dir / raw_p).resolve()

    return RuntimeConfig(
        mode=mode,
        allow_observe_mode=allow_observe,
        state_db=_opt_path("state_db"),
        audit_log=_opt_path("audit_log"),
    )


def _parse_scanner_section(raw: Any) -> ScannerConfig:
    if raw is None:
        return ScannerConfig()
    sec = _require_mapping(raw, "scanner")
    unknown = set(sec) - _SCANNER_KEYS
    if unknown:
        raise PolicyLoadError(f"[scanner] contains unknown key(s): {sorted(unknown)}")

    canary_tokens = tuple(_require_str_list(sec, "canary_tokens", "scanner"))
    block_known_secrets = _require_bool(sec, "block_known_secrets", True, "scanner")
    aad_kill_on_leak = _require_bool(sec, "aad_kill_on_leak", True, "scanner")
    blocked_patterns = tuple(_require_str_list(sec, "blocked_patterns", "scanner"))
    try:
        return ScannerConfig(
            canary_tokens=canary_tokens,
            block_known_secrets=block_known_secrets,
            aad_kill_on_leak=aad_kill_on_leak,
            blocked_patterns=blocked_patterns,
        )
    except ValueError as exc:
        raise PolicyLoadError(f"[scanner] configuration invalid: {exc}") from exc


def _parse_auth_section(raw: Any) -> AuthConfig:
    if raw is None:
        return AuthConfig()
    sec = _require_mapping(raw, "auth")
    forbidden = _FORBIDDEN_AUTH_RAW_KEYS & set(sec)
    if forbidden:
        raise PolicyLoadError(f"[auth] must not store raw secret fields {sorted(forbidden)}.")
    unknown = set(sec) - _AUTH_KEYS
    if unknown:
        raise PolicyLoadError(f"[auth] contains unknown key(s): {sorted(unknown)}")

    mode_raw = sec.get("mode", "hmac")
    if not isinstance(mode_raw, str) or mode_raw.strip() not in ("hmac", "oidc"):
        raise PolicyLoadError("[auth].mode must be 'hmac' or 'oidc'.")
    mode_val: Literal["hmac", "oidc"] = "oidc" if mode_raw.strip() == "oidc" else "hmac"

    def _opt_auth_str(key: str) -> str | None:
        if key not in sec:
            return None
        val = sec[key]
        if not isinstance(val, str) or not val.strip():
            raise PolicyLoadError(f"[auth].{key} must be a non-empty string.")
        return val.strip()

    skew = sec.get("clock_skew_seconds", 60)
    if isinstance(skew, bool) or not isinstance(skew, int):
        raise PolicyLoadError("[auth].clock_skew_seconds must be an integer.")

    try:
        return AuthConfig(
            mode=mode_val,
            issuer=_opt_auth_str("issuer"),
            audience=_opt_auth_str("audience"),
            resource=_opt_auth_str("resource"),
            jwks_uri=_opt_auth_str("jwks_uri"),
            required_scopes=tuple(_require_str_list(sec, "required_scopes", "auth")),
            approver_scopes=tuple(_require_str_list(sec, "approver_scopes", "auth")),
            approver_subjects=tuple(_require_str_list(sec, "approver_subjects", "auth")),
            approver_groups=tuple(_require_str_list(sec, "approver_groups", "auth")),
            allowed_origins=tuple(_require_str_list(sec, "allowed_origins", "auth")),
            allowed_hosts=tuple(_require_str_list(sec, "allowed_hosts", "auth")),
            clock_skew_seconds=skew,
            allow_insecure_loopback_for_tests=False,
        )
    except ValueError as exc:
        raise PolicyLoadError(f"[auth] configuration invalid: {exc}") from exc


def _parse_notifications_section(raw: Any) -> NotificationsConfig:
    if raw is None:
        return NotificationsConfig()
    sec = _require_mapping(raw, "notifications")
    forbidden = _FORBIDDEN_NOTIFICATION_KEYS & set(sec)
    if forbidden:
        raise PolicyLoadError(
            f"[notifications] must not store secrets {sorted(forbidden)}; a webhook URL is a credential, so put it "
            "in an environment variable and name it with approval_webhook_url_env."
        )
    unknown = set(sec) - _NOTIFICATIONS_KEYS
    if unknown:
        raise PolicyLoadError(f"[notifications] contains unknown key(s): {sorted(unknown)}")

    def _opt_notif_str(key: str) -> str | None:
        if key not in sec:
            return None
        val = sec[key]
        if not isinstance(val, str) or not val.strip():
            raise PolicyLoadError(f"[notifications].{key} must be a non-empty string.")
        return val.strip()

    fmt_raw = sec.get("webhook_format", "auto")
    if not isinstance(fmt_raw, str) or fmt_raw.strip() not in ("auto", "slack", "teams", "generic"):
        raise PolicyLoadError("[notifications].webhook_format must be 'auto', 'slack', 'teams', or 'generic'.")
    fmt_clean = fmt_raw.strip()
    webhook_fmt: Literal["auto", "slack", "teams", "generic"] = (
        "slack"
        if fmt_clean == "slack"
        else ("teams" if fmt_clean == "teams" else ("generic" if fmt_clean == "generic" else "auto"))
    )

    timeout_raw = sec.get("timeout_seconds", 5.0)
    if isinstance(timeout_raw, bool) or not isinstance(timeout_raw, int | float):
        raise PolicyLoadError("[notifications].timeout_seconds must be numeric.")

    try:
        return NotificationsConfig(
            approval_webhook_url_env=_opt_notif_str("approval_webhook_url_env"),
            webhook_host=_opt_notif_str("webhook_host"),
            webhook_format=webhook_fmt,
            console_base_url=_opt_notif_str("console_base_url"),
            timeout_seconds=float(timeout_raw),
            allow_insecure_loopback_for_tests=False,
        )
    except ValueError as exc:
        raise PolicyLoadError(f"[notifications] configuration invalid: {exc}") from exc


def _add_domain_from_url(url: str, seen_domains: set[str], allowed_domains: list[str]) -> None:
    host = extract_url_host(url)
    norm = validate_egress_domain(host)
    if norm not in seen_domains:
        seen_domains.add(norm)
        allowed_domains.append(norm)


def _parse_oauth_section(raw: Any, *, server_idx: int, server_name: str, base_dir: Path) -> OAuthClientConfig:
    sec = _require_mapping(raw, f"servers[{server_idx}] ({server_name}).oauth")
    forbidden = _FORBIDDEN_OAUTH_RAW_KEYS & set(sec)
    if forbidden:
        raise PolicyLoadError(
            f"servers[{server_idx}] ({server_name}).oauth must not store raw secret fields {sorted(forbidden)}; "
            "reference environment variable names with *_env instead."
        )
    unknown = set(sec) - _OAUTH_KEYS
    if unknown:
        raise PolicyLoadError(f"servers[{server_idx}] ({server_name}).oauth contains unknown key(s): {sorted(unknown)}")

    flow_raw = sec.get("flow")
    if not isinstance(flow_raw, str) or flow_raw.strip() not in ("client_credentials", "pkce", "bearer_env"):
        raise PolicyLoadError(
            f"servers[{server_idx}] ({server_name}).oauth.flow must be 'client_credentials', 'pkce', or 'bearer_env'."
        )
    flow_str = flow_raw.strip()
    flow: Literal["client_credentials", "pkce", "bearer_env"] = (
        "client_credentials" if flow_str == "client_credentials" else ("pkce" if flow_str == "pkce" else "bearer_env")
    )

    label = f"servers[{server_idx}].oauth"
    allowed_as = tuple(_require_str_list(sec, "allowed_authorization_servers", label))
    scopes = tuple(_require_str_list(sec, "scopes", label))

    def _opt_str(key: str) -> str | None:
        if key not in sec:
            return None
        val = sec[key]
        if not isinstance(val, str) or not val.strip():
            raise PolicyLoadError(f"{label}.{key} must be a non-empty string.")
        return val.strip()

    raw_cache = _opt_str("token_cache_path")
    cache_path: Path | None = None
    if raw_cache is not None:
        raw_p = Path(raw_cache)
        cache_path = raw_p.resolve() if raw_p.is_absolute() else (base_dir / raw_p).resolve()

    try:
        return OAuthClientConfig(
            flow=flow,
            allowed_authorization_servers=allowed_as,
            client_id=_opt_str("client_id"),
            client_id_env=_opt_str("client_id_env"),
            client_secret_env=_opt_str("client_secret_env"),
            bearer_token_env=_opt_str("bearer_token_env"),
            scopes=scopes,
            resource=_opt_str("resource"),
            token_endpoint=_opt_str("token_endpoint"),
            authorization_endpoint=_opt_str("authorization_endpoint"),
            token_cache_path=cache_path,
        )
    except ValueError as exc:
        raise PolicyLoadError(f"servers[{server_idx}] ({server_name}).oauth invalid: {exc}") from exc


def parse_unified_dict(data: Mapping[str, Any], *, base_dir: Path, config_path: Path) -> UnifiedConfig:
    """Validate a `schema_version = 2` unified configuration dictionary and compile Policy/Gateway models."""
    if not isinstance(data, Mapping):
        raise PolicyLoadError("Unified config root must be a table/object.")
    unknown = set(data) - _UNIFIED_TOP_KEYS
    if unknown:
        raise PolicyLoadError(f"Unified config contains unknown top-level key(s): {sorted(unknown)}")
    if data.get("schema_version") != 2:
        raise PolicyLoadError(f"Unified config expects schema_version = 2, got {data.get('schema_version')!r}.")

    runtime = _parse_runtime_section(data.get("runtime"), base_dir=base_dir)
    scanner = _parse_scanner_section(data.get("scanner"))
    auth = _parse_auth_section(data.get("auth"))
    notifications = _parse_notifications_section(data.get("notifications"))

    egress_raw = data.get("egress")
    allowed_domains: list[str] = []
    seen_domains: set[str] = set()
    auto_sync_squid = True
    if egress_raw is not None:
        egress_sec = _require_mapping(egress_raw, "egress")
        unknown_egress = set(egress_sec) - _EGRESS_KEYS
        if unknown_egress:
            raise PolicyLoadError(f"[egress] contains unknown key(s): {sorted(unknown_egress)}")
        auto_sync_squid = _require_bool(egress_sec, "auto_sync_squid", True, "egress")
        for dom in _require_str_list(egress_sec, "allowed_domains", "egress"):
            try:
                norm = validate_egress_domain(dom)
            except ValueError as exc:
                raise PolicyLoadError(f"[egress].allowed_domains entry '{dom}' invalid: {exc}") from exc
            if norm not in seen_domains:
                seen_domains.add(norm)
                allowed_domains.append(norm)

    gateway_domains: list[str] = []
    seen_gateway_domains: set[str] = set()
    if auth.mode == "oidc":
        for auth_url in (*([auth.issuer] if auth.issuer else ()), *([auth.jwks_uri] if auth.jwks_uri else ())):
            _add_domain_from_url(auth_url, seen_gateway_domains, gateway_domains)
    if notifications.webhook_host is not None:
        host = validate_egress_domain(notifications.webhook_host)
        if host not in seen_gateway_domains:
            seen_gateway_domains.add(host)
            gateway_domains.append(host)

    servers_raw = data.get("servers")
    if not isinstance(servers_raw, list) or not servers_raw:
        raise PolicyLoadError("Unified config requires at least one [[servers]] entry.")

    server_specs: list[ServerSpec] = []
    allowed_servers: list[str] = []
    trusted_servers: list[str] = []
    server_presets: dict[str, str] = {}
    pinned_hashes: dict[str, str] = {}
    merged_tiers: dict[str, str] = {}

    for idx, entry in enumerate(servers_raw):
        if not isinstance(entry, Mapping):
            raise PolicyLoadError(f"servers[{idx}] must be a table/object.")
        unknown_srv = set(entry) - _SERVER_KEYS
        if unknown_srv:
            raise PolicyLoadError(f"servers[{idx}] contains unknown key(s): {sorted(unknown_srv)}")

        name = entry.get("name")
        if not isinstance(name, str) or not SERVER_NAME.fullmatch(name):
            raise PolicyLoadError(f"servers[{idx}].name must be lowercase letters, digits and single hyphens.")
        if any(s.name == name for s in server_specs):
            raise PolicyLoadError(f"Duplicate server name '{name}'.")

        transport_raw = entry.get("transport", "stdio")
        if not isinstance(transport_raw, str) or transport_raw.strip() not in ("stdio", "streamable-http"):
            raise PolicyLoadError(
                f"servers[{idx}] ({name}) specifies unsupported transport {transport_raw!r}; "
                "expected 'stdio' or 'streamable-http'."
            )
        transport_str = transport_raw.strip()
        transport: Literal["stdio", "streamable-http"] = (
            "streamable-http" if transport_str == "streamable-http" else "stdio"
        )

        cmd_tuple: tuple[str, ...] = ()
        server_url: str | None = None
        oauth_cfg: OAuthClientConfig | None = None
        if transport == "stdio":
            if "url" in entry or "oauth" in entry:
                raise PolicyLoadError(
                    f"servers[{idx}] ({name}) with transport='stdio' must not specify 'url' or 'oauth'."
                )
            if "command" not in entry:
                raise PolicyLoadError(f"servers[{idx}] ({name}) requires 'command'.")
            command = entry["command"]
            argv_ok, argv_reason = validate_argv({"argv": command})
            if not argv_ok:
                raise PolicyLoadError(f"Server '{name}' command rejected: {argv_reason}")
            cmd_tuple = tuple(command)
        else:
            if "command" in entry:
                raise PolicyLoadError(
                    f"servers[{idx}] ({name}) with transport='streamable-http' must not specify 'command'."
                )
            url_raw = entry.get("url")
            if not isinstance(url_raw, str) or not url_raw.strip():
                raise PolicyLoadError(f"servers[{idx}] ({name}) with transport='streamable-http' requires 'url'.")
            try:
                server_url = validate_outbound_url(url_raw, allow_loopback_http=False)
            except ValueError as exc:
                raise PolicyLoadError(f"servers[{idx}] ({name}).url rejected: {exc}") from exc
            _add_domain_from_url(server_url, seen_domains, allowed_domains)

            oauth_raw = entry.get("oauth")
            if oauth_raw is not None:
                oauth_cfg = _parse_oauth_section(oauth_raw, server_idx=idx, server_name=name, base_dir=base_dir)
                for oauth_url in (
                    *oauth_cfg.allowed_authorization_servers,
                    *([oauth_cfg.resource] if oauth_cfg.resource else ()),
                    *([oauth_cfg.token_endpoint] if oauth_cfg.token_endpoint else ()),
                    *([oauth_cfg.authorization_endpoint] if oauth_cfg.authorization_endpoint else ()),
                ):
                    _add_domain_from_url(oauth_url, seen_domains, allowed_domains)

        trusted = _require_bool(entry, "trusted", False, f"servers[{idx}]")

        preset_raw = entry.get("preset")
        if preset_raw is not None:
            if not isinstance(preset_raw, str) or not preset_raw.strip():
                raise PolicyLoadError(f"servers[{idx}].preset must be a non-empty string.")
            preset_name = preset_raw.strip()
            if preset_name not in SMB_SERVER_PRESETS:
                raise PolicyLoadError(
                    f"servers[{idx}].preset '{preset_name}' is unknown; known: {sorted(SMB_SERVER_PRESETS)}."
                )
            profile = SMB_SERVER_PRESETS[preset_name]
            server_presets[name] = preset_name
            for dom in profile.egress_domains:
                norm = validate_egress_domain(dom)
                if norm not in seen_domains:
                    seen_domains.add(norm)
                    allowed_domains.append(norm)
            for tool_name, tier in profile.default_tool_risk_tiers.items():
                tier_val = tier.value if isinstance(tier, RiskTier) else str(tier)
                merged_tiers[f"{name}/{tool_name}"] = tier_val

        pin_raw = entry.get("tools_sha256")
        if pin_raw is not None:
            if not isinstance(pin_raw, str):
                raise PolicyLoadError(f"servers[{idx}].tools_sha256 must be a string.")
            pin_clean = pin_raw.strip()
            if pin_clean:
                if not _SHA256_HEX_RE.fullmatch(pin_clean):
                    raise PolicyLoadError(
                        f"servers[{idx}].tools_sha256 must be a 64-character lowercase hex SHA-256 digest."
                    )
                pinned_hashes[name] = pin_clean

        server_specs.append(
            ServerSpec(
                name=name,
                command=cmd_tuple,
                transport=transport,
                url=server_url,
                oauth=oauth_cfg,
            )
        )
        allowed_servers.append(name)
        if trusted:
            trusted_servers.append(name)

    # Two servers sharing a token cache would send each other's tokens; refuse the config instead.
    cache_owner: dict[Path, str] = {}
    for spec in server_specs:
        cache = spec.oauth.token_cache_path if spec.oauth is not None else None
        if cache is None:
            continue
        if cache in cache_owner:
            raise PolicyLoadError(
                f"Servers '{cache_owner[cache]}' and '{spec.name}' share oauth.token_cache_path '{cache}'; "
                "each server needs its own cache."
            )
        cache_owner[cache] = spec.name

    policy_dict: dict[str, Any] = {
        "schema_version": 1,
        "allowed_mcp_servers": allowed_servers,
        "trusted_mcp_servers": trusted_servers,
        "allowed_egress_domains": allowed_domains,
        "server_presets": server_presets,
    }
    if pinned_hashes:
        policy_dict["pinned_tool_hashes"] = pinned_hashes

    policy_raw = data.get("policy")
    if policy_raw is not None:
        policy_sec = _require_mapping(policy_raw, "policy")
        unknown_pol = set(policy_sec) - _POLICY_SECTION_KEYS
        if unknown_pol:
            raise PolicyLoadError(f"[policy] contains unknown key(s): {sorted(unknown_pol)}")
        for key, value in policy_sec.items():
            if key == "tool_risk_tiers":
                if not isinstance(value, Mapping):
                    raise PolicyLoadError("[policy].tool_risk_tiers must be a mapping.")
                merged_tiers.update(value)
            else:
                policy_dict[key] = value

    if merged_tiers:
        policy_dict["tool_risk_tiers"] = merged_tiers

    policy_cfg = parse_policy_dict(policy_dict)
    resolved_cfg_path = config_path.resolve() if config_path.exists() else config_path
    gateway_cfg = GatewayConfig(path=resolved_cfg_path, policy_path=resolved_cfg_path, servers=tuple(server_specs))

    return UnifiedConfig(
        path=resolved_cfg_path,
        schema_version=2,
        policy=policy_cfg,
        gateway=gateway_cfg,
        runtime=runtime,
        scanner=scanner,
        auto_sync_squid=auto_sync_squid,
        auth=auth,
        notifications=notifications,
        gateway_egress_domains=frozenset(gateway_domains),
    )


def _read_toml_checked(path: Path) -> dict[str, Any]:
    if path.is_symlink() or path.parent.is_symlink():
        raise PolicyLoadError(f"Refusing symlink config path '{path}'.")
    if not path.is_file():
        raise PolicyLoadError(f"Config file does not exist: '{path}'.")
    raw = path.read_bytes()
    if len(raw) > MAX_POLICY_BYTES:
        raise PolicyLoadError("Config file is too large.")
    try:
        return tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise PolicyLoadError(f"Failed to parse config '{path.name}': {exc}") from exc


def load_unified_config(path: Path) -> UnifiedConfig:
    """Load and strictly validate a unified `schema_version = 2` `mellyn.toml` file."""
    data = _read_toml_checked(path)
    return parse_unified_dict(data, base_dir=path.parent.resolve(), config_path=path)


def load_mellyn_config(path: Path) -> UnifiedConfig:
    """Auto-detect `schema_version = 2` (`mellyn.toml`) or `schema_version = 1` (legacy gateway + policy TOMLs)."""
    data = _read_toml_checked(path)
    if data.get("schema_version") == 2:
        return parse_unified_dict(data, base_dir=path.parent.resolve(), config_path=path)
    gw = load_gateway_config(path)
    pol = load_policy_file(gw.policy_path)
    return UnifiedConfig(
        path=gw.path,
        schema_version=1,
        policy=pol,
        gateway=gw,
        runtime=RuntimeConfig(),
        scanner=ScannerConfig(),
        auto_sync_squid=True,
    )


def load_gateway_egress_domains_any(path: Path) -> frozenset[str]:
    """Hosts the gateway itself contacts, from a `schema_version = 2` `mellyn.toml` (empty for v1 policy files)."""
    if path.suffix.lower() == ".toml":
        data = _read_toml_checked(path)
        if data.get("schema_version") == 2:
            return parse_unified_dict(data, base_dir=path.parent.resolve(), config_path=path).gateway_egress_domains
    return frozenset()


def load_policy_any(path: Path) -> PolicyConfig:
    """Load `PolicyConfig` from either a standalone policy file or a `schema_version = 2` `mellyn.toml`."""
    if path.suffix.lower() == ".toml":
        data = _read_toml_checked(path)
        if data.get("schema_version") == 2:
            return parse_unified_dict(data, base_dir=path.parent.resolve(), config_path=path).policy
    return load_policy_file(path)


def render_unified_config(
    presets: Sequence[str],
    *,
    extra_domains: Sequence[str] = (),
    canary_tokens: Sequence[str] = (),
    audit_log: str | None = None,
    state_db: str | None = None,
) -> str:
    """Render and round-trip validate a `schema_version = 2` `mellyn.toml` string."""
    if not presets:
        raise PolicyLoadError("Select at least one preset (see `mellyn presets`).")
    profiles: list[ServerPresetProfile] = []
    seen_presets: set[str] = set()
    for raw_name in presets:
        clean = raw_name.strip().lower()
        if clean not in SMB_SERVER_PRESETS:
            raise PolicyLoadError(f"Unknown preset '{raw_name}'. Known: {sorted(SMB_SERVER_PRESETS)}.")
        if clean in seen_presets:
            continue
        seen_presets.add(clean)
        profiles.append(SMB_SERVER_PRESETS[clean])

    domains: list[str] = []
    seen_domains: set[str] = set()
    for prof in profiles:
        for dom in prof.egress_domains:
            norm = validate_egress_domain(dom)
            if norm not in seen_domains:
                seen_domains.add(norm)
                domains.append(norm)
    for raw_dom in extra_domains:
        try:
            norm = validate_egress_domain(raw_dom)
        except ValueError as exc:
            raise PolicyLoadError(f"Invalid egress domain '{raw_dom}': {exc}") from exc
        if norm not in seen_domains:
            seen_domains.add(norm)
            domains.append(norm)

    lines = [
        "# Mellyn Security — Unified Configuration (schema_version = 2)",
        "# Combines policy, egress, canary/secret scanner, runtime mode, and downstream MCP servers.",
        "",
        "schema_version = 2",
        "",
        "[runtime]",
        'mode = "enforce"',
        "allow_observe_mode = false",
    ]
    if state_db:
        lines.append(f"state_db = {json.dumps(state_db)}")
    if audit_log:
        lines.append(f"audit_log = {json.dumps(audit_log)}")

    lines.extend(
        [
            "",
            "[egress]",
            f"allowed_domains = {json.dumps(domains)}",
            "auto_sync_squid = true",
            "",
            "[scanner]",
            f"canary_tokens = {json.dumps(list(canary_tokens))}",
            "block_known_secrets = true",
            "aad_kill_on_leak = true",
            "blocked_patterns = []",
            "",
            "[policy]",
            "protected_paths = []",
            "injection_escalate_threshold = 0.70",
            "injection_deny_threshold = 0.90",
            "deny_on_dlp_secret = true",
            "",
            "[[policy.scoped_rules]]",
            'rule_id = "deny-destructive-programs"',
            'tool_name = "shell_exec"',
            'effect = "deny"',
            'programs = ["rm", "curl", "wget", "nc", "ncat"]',
            'description = "Defense-in-depth denial of destructive deletion and raw network binaries."',
        ]
    )

    for prof in profiles:
        lines.extend(
            [
                "",
                "[[servers]]",
                f"name = {json.dumps(prof.default_server_name)}",
                'transport = "stdio"',
                f"preset = {json.dumps(prof.preset_name)}",
                f"trusted = {'true' if prof.trusted else 'false'}",
                f"command = {json.dumps(list(prof.example_command))}",
                'tools_sha256 = ""',
            ]
        )
    lines.append("")
    rendered = "\n".join(lines)
    parse_unified_dict(tomllib.loads(rendered), base_dir=Path.cwd(), config_path=Path("mellyn.toml"))
    return rendered
