"""Fail-closed TOML/JSON policy loader for Mellyn Security (AegisAI)."""

from __future__ import annotations

import json
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from aegis_ai.models import Decision, RiskTier
from aegis_ai.policy import DEFAULT_TOOL_RISK_TIERS, DEFAULT_UNTRUSTED_CONTENT_TOOLS, PolicyConfig, ScopedRule

MAX_POLICY_BYTES = 256 * 1024

_ALLOWED_TOP_LEVEL_KEYS: frozenset[str] = frozenset(
    {
        "schema_version",
        "allowed_mcp_servers",
        "trusted_mcp_servers",
        "untrusted_content_tools",
        "allowed_egress_domains",
        "protected_paths",
        "tool_risk_tiers",
        "scoped_rules",
        "injection_escalate_threshold",
        "injection_deny_threshold",
        "deny_on_dlp_secret",
    }
)

_ALLOWED_RULE_KEYS: frozenset[str] = frozenset(
    {
        "rule_id",
        "tool_name",
        "effect",
        "arg_equals",
        "programs",
        "allow_when_tainted",
        "description",
        "mcp_server",
    }
)


class PolicyLoadError(ValueError):
    """Raised when a policy file is missing, unreadable, or fails strict schema validation."""


def _require_str_list(data: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = data[key]
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise PolicyLoadError(f"Policy field '{key}' must be a list of non-empty strings.")
    return tuple(item.strip() for item in value)


def _require_threshold(data: Mapping[str, Any], key: str, default: float) -> float:
    if key not in data:
        return default
    value = data[key]
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise PolicyLoadError(f"Policy field '{key}' must be a number between 0.0 and 1.0.")
    score = float(value)
    if not 0.0 <= score <= 1.0:
        raise PolicyLoadError(f"Policy field '{key}' must be between 0.0 and 1.0.")
    return score


def _parse_risk_tiers(raw: Any) -> dict[str, RiskTier]:
    if not isinstance(raw, Mapping):
        raise PolicyLoadError(
            "Policy field 'tool_risk_tiers' must map a local tool name or \"<mcp_server>/<tool>\" to low|medium|high."
        )
    tiers = dict(DEFAULT_TOOL_RISK_TIERS)
    for tool_name, tier_raw in raw.items():
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise PolicyLoadError("Every key in 'tool_risk_tiers' must be a non-empty string.")
        if not isinstance(tier_raw, str):
            raise PolicyLoadError(f"Risk tier for '{tool_name}' must be a string ('low', 'medium', or 'high').")
        try:
            tiers[tool_name.strip()] = RiskTier(tier_raw.strip().lower())
        except ValueError as exc:
            raise PolicyLoadError(
                f"Invalid risk tier '{tier_raw}' for tool '{tool_name}'; expected low, medium, or high."
            ) from exc
    return tiers


def _parse_scoped_rules(raw: Any) -> tuple[ScopedRule, ...]:
    if not isinstance(raw, list):
        raise PolicyLoadError("Policy field 'scoped_rules' must be a list of rule tables.")

    rules: list[ScopedRule] = []
    seen_ids: set[str] = set()

    for idx, entry in enumerate(raw):
        if not isinstance(entry, Mapping):
            raise PolicyLoadError(f"scoped_rules[{idx}] must be a table/object.")

        unknown = set(entry) - _ALLOWED_RULE_KEYS
        if unknown:
            raise PolicyLoadError(f"scoped_rules[{idx}] contains unknown key(s): {sorted(unknown)}")

        rule_id = entry.get("rule_id")
        tool_name = entry.get("tool_name")
        effect_raw = entry.get("effect")

        if not isinstance(rule_id, str) or not rule_id.strip():
            raise PolicyLoadError(f"scoped_rules[{idx}] requires a non-empty string 'rule_id'.")
        rule_id = rule_id.strip()
        if rule_id in seen_ids:
            raise PolicyLoadError(f"Duplicate rule_id '{rule_id}' in scoped_rules.")
        seen_ids.add(rule_id)

        if not isinstance(tool_name, str) or not tool_name.strip():
            raise PolicyLoadError(f"Rule '{rule_id}' requires a non-empty string 'tool_name'.")

        if not isinstance(effect_raw, str):
            raise PolicyLoadError(f"Rule '{rule_id}' requires string 'effect' (allow, require_approval, or deny).")
        try:
            effect = Decision(effect_raw.strip().lower())
        except ValueError as exc:
            raise PolicyLoadError(
                f"Rule '{rule_id}' has invalid effect '{effect_raw}'; expected allow, require_approval, or deny."
            ) from exc

        arg_equals_raw = entry.get("arg_equals", {})
        if not isinstance(arg_equals_raw, Mapping):
            raise PolicyLoadError(f"Rule '{rule_id}' field 'arg_equals' must be a table/object.")
        arg_equals: dict[str, tuple[Any, ...]] = {}
        for arg_key, allowed_values in arg_equals_raw.items():
            if not isinstance(arg_key, str) or not arg_key.strip():
                raise PolicyLoadError(f"Rule '{rule_id}' has an empty key in 'arg_equals'.")
            if not isinstance(allowed_values, list) or not allowed_values:
                raise PolicyLoadError(
                    f"Rule '{rule_id}' arg_equals['{arg_key}'] must be a non-empty list of exact allowed values."
                )
            arg_equals[arg_key] = tuple(allowed_values)

        programs_raw = entry.get("programs", [])
        if not isinstance(programs_raw, list) or not all(isinstance(p, str) and p.strip() for p in programs_raw):
            raise PolicyLoadError(f"Rule '{rule_id}' field 'programs' must be a list of non-empty strings.")
        programs = frozenset(p.strip().lower() for p in programs_raw)

        allow_when_tainted = entry.get("allow_when_tainted", False)
        if not isinstance(allow_when_tainted, bool):
            raise PolicyLoadError(f"Rule '{rule_id}' field 'allow_when_tainted' must be a boolean.")

        description = entry.get("description", "")
        if not isinstance(description, str):
            raise PolicyLoadError(f"Rule '{rule_id}' field 'description' must be a string.")

        mcp_server = entry.get("mcp_server")
        if mcp_server is not None and (not isinstance(mcp_server, str) or not mcp_server.strip()):
            raise PolicyLoadError(f"Rule '{rule_id}' field 'mcp_server' must be a non-empty string.")

        try:
            rules.append(
                ScopedRule(
                    rule_id=rule_id,
                    tool_name=tool_name.strip(),
                    effect=effect,
                    arg_equals=arg_equals,
                    programs=programs,
                    allow_when_tainted=allow_when_tainted,
                    description=description,
                    mcp_server=mcp_server.strip() if mcp_server else None,
                )
            )
        except ValueError as exc:
            raise PolicyLoadError(str(exc)) from exc

    return tuple(rules)


def parse_policy_dict(data: Mapping[str, Any]) -> PolicyConfig:
    """Strictly validate a parsed policy mapping and build a PolicyConfig."""
    if not isinstance(data, Mapping):
        raise PolicyLoadError("Policy root must be a table/object.")

    unknown = set(data) - _ALLOWED_TOP_LEVEL_KEYS
    if unknown:
        raise PolicyLoadError(f"Policy contains unknown top-level key(s): {sorted(unknown)}")

    if "schema_version" in data and data["schema_version"] != 1:
        raise PolicyLoadError(f"Unsupported policy schema_version '{data['schema_version']}'; expected 1.")

    allowed_mcp_servers: frozenset[str] | None = None
    if "allowed_mcp_servers" in data:
        allowed_mcp_servers = frozenset(_require_str_list(data, "allowed_mcp_servers"))

    trusted_mcp_servers = (
        frozenset(_require_str_list(data, "trusted_mcp_servers")) if "trusted_mcp_servers" in data else frozenset()
    )

    untrusted_content_tools = (
        frozenset(_require_str_list(data, "untrusted_content_tools"))
        if "untrusted_content_tools" in data
        else DEFAULT_UNTRUSTED_CONTENT_TOOLS
    )

    allowed_egress_domains = (
        frozenset(_require_str_list(data, "allowed_egress_domains"))
        if "allowed_egress_domains" in data
        else frozenset()
    )

    protected_paths = _require_str_list(data, "protected_paths") if "protected_paths" in data else ()
    tool_risk_tiers = (
        _parse_risk_tiers(data["tool_risk_tiers"]) if "tool_risk_tiers" in data else dict(DEFAULT_TOOL_RISK_TIERS)
    )
    scoped_rules = _parse_scoped_rules(data["scoped_rules"]) if "scoped_rules" in data else ()

    escalate = _require_threshold(data, "injection_escalate_threshold", 0.70)
    deny = _require_threshold(data, "injection_deny_threshold", 0.90)
    if escalate > deny:
        raise PolicyLoadError(
            f"injection_escalate_threshold ({escalate}) cannot exceed injection_deny_threshold ({deny})."
        )

    deny_on_dlp_secret = data.get("deny_on_dlp_secret", True)
    if not isinstance(deny_on_dlp_secret, bool):
        raise PolicyLoadError("Policy field 'deny_on_dlp_secret' must be a boolean.")

    return PolicyConfig(
        tool_risk_tiers=tool_risk_tiers,
        allowed_mcp_servers=allowed_mcp_servers,
        trusted_mcp_servers=trusted_mcp_servers,
        untrusted_content_tools=untrusted_content_tools,
        allowed_egress_domains=allowed_egress_domains,
        protected_paths=protected_paths,
        scoped_rules=scoped_rules,
        injection_escalate_threshold=escalate,
        injection_deny_threshold=deny,
        deny_on_dlp_secret=deny_on_dlp_secret,
    )


def load_policy_file(path: Path) -> PolicyConfig:
    """Load and strictly validate a TOML (.toml) or JSON (.json) policy file."""
    if not path.exists() or not path.is_file():
        raise PolicyLoadError(f"Policy file does not exist: {path}")

    raw_bytes = path.read_bytes()
    if len(raw_bytes) > MAX_POLICY_BYTES:
        raise PolicyLoadError(f"Policy file exceeds maximum allowed size ({MAX_POLICY_BYTES} bytes).")

    suffix = path.suffix.lower()
    try:
        if suffix == ".toml":
            parsed = tomllib.loads(raw_bytes.decode("utf-8"))
        elif suffix == ".json":
            parsed = json.loads(raw_bytes.decode("utf-8"))
        else:
            raise PolicyLoadError(f"Unsupported policy file extension '{suffix}'; use .toml or .json.")
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, json.JSONDecodeError) as exc:
        raise PolicyLoadError(f"Failed to parse policy file '{path.name}': {exc}") from exc

    return parse_policy_dict(parsed)
