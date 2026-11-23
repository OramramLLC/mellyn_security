"""
Strict JSON-RPC 2.0 wire schemas and AirlockPolicy models.

Invariants enforced (per AGENTS.md):
  - `ConfigDict(extra="forbid", strict=True, frozen=True)` on EVERY Pydantic model.
  - Zero `Any` on wire fields (`id`, `method`, `params`, `tool_name`, `result`, `error`).
  - Rejects boolean coercion for `int` IDs/codes, non-finite floats (`NaN`/`Inf`), and
    ambiguous response envelopes containing both `result` and `error`.
"""

from __future__ import annotations

import json
import math
import re
import tomllib
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mcp_airlock.core.normalize import JsonObject, JsonValue

_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


def _check_finite_json(value: JsonValue) -> JsonValue:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("Non-finite float values (NaN/Inf) are forbidden.")
    if isinstance(value, list):
        for item in value:
            _check_finite_json(item)
    elif isinstance(value, dict):
        for val in value.values():
            _check_finite_json(val)
    return value


def _reject_json_constant(constant: str) -> JsonValue:
    raise ValueError(f"Non-standard JSON constant is forbidden: {constant!r}")


class _StrictAirlockModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class JsonRpcRequest(_StrictAirlockModel):
    """Strict JSON-RPC 2.0 request frame (requires non-null, non-bool int|str id)."""

    jsonrpc: Literal["2.0"]
    id: int | str
    method: str = Field(min_length=1)
    params: JsonObject = Field(default_factory=dict)

    @field_validator("id")
    @classmethod
    def _validate_id(cls, v: int | str) -> int | str:
        if isinstance(v, bool):
            raise ValueError("JSON-RPC request id cannot be a boolean.")
        if isinstance(v, str) and not v:
            raise ValueError("JSON-RPC request string id cannot be empty.")
        return v

    @field_validator("method")
    @classmethod
    def _validate_method(cls, v: str) -> str:
        if _CONTROL_CHARS_RE.search(v):
            raise ValueError("JSON-RPC method cannot contain control characters.")
        return v

    @field_validator("params")
    @classmethod
    def _validate_params(cls, v: JsonObject) -> JsonObject:
        _check_finite_json(v)
        return v


class JsonRpcNotification(_StrictAirlockModel):
    """Strict JSON-RPC 2.0 notification frame (must omit `id`)."""

    jsonrpc: Literal["2.0"]
    method: str = Field(min_length=1)
    params: JsonObject = Field(default_factory=dict)

    @field_validator("method")
    @classmethod
    def _validate_method(cls, v: str) -> str:
        if _CONTROL_CHARS_RE.search(v):
            raise ValueError("JSON-RPC method cannot contain control characters.")
        return v

    @field_validator("params")
    @classmethod
    def _validate_params(cls, v: JsonObject) -> JsonObject:
        _check_finite_json(v)
        return v


class JsonRpcErrorObject(_StrictAirlockModel):
    """Strict JSON-RPC 2.0 error object."""

    code: int
    message: str
    data: JsonValue = None

    @field_validator("code")
    @classmethod
    def _validate_code(cls, v: int) -> int:
        if isinstance(v, bool):
            raise ValueError("JSON-RPC error code cannot be a boolean.")
        return v

    @field_validator("data")
    @classmethod
    def _validate_data(cls, v: JsonValue) -> JsonValue:
        return _check_finite_json(v)


class JsonRpcSuccessResponse(_StrictAirlockModel):
    """Strict JSON-RPC 2.0 success response (`result` only, non-null `id`)."""

    jsonrpc: Literal["2.0"]
    id: int | str
    result: JsonValue

    @field_validator("id")
    @classmethod
    def _validate_id(cls, v: int | str) -> int | str:
        if isinstance(v, bool):
            raise ValueError("JSON-RPC response id cannot be a boolean.")
        return v

    @field_validator("result")
    @classmethod
    def _validate_result(cls, v: JsonValue) -> JsonValue:
        return _check_finite_json(v)


class JsonRpcErrorResponse(_StrictAirlockModel):
    """Strict JSON-RPC 2.0 error response (`error` only)."""

    jsonrpc: Literal["2.0"]
    id: int | str | None
    error: JsonRpcErrorObject

    @field_validator("id")
    @classmethod
    def _validate_id(cls, v: int | str | None) -> int | str | None:
        if isinstance(v, bool):
            raise ValueError("JSON-RPC error response id cannot be a boolean.")
        return v


type JsonRpcMessage = JsonRpcRequest | JsonRpcNotification | JsonRpcSuccessResponse | JsonRpcErrorResponse


def parse_jsonrpc_message(raw: JsonObject) -> JsonRpcMessage:
    """Discriminate and validate a JSON-RPC 2.0 request, notification, success response, or error response."""
    has_method = "method" in raw
    has_result = "result" in raw
    has_error = "error" in raw

    if has_method:
        if has_result or has_error:
            raise ValueError("JSON-RPC request/notification cannot contain 'result' or 'error'.")
        if "id" in raw:
            return JsonRpcRequest.model_validate(raw)
        return JsonRpcNotification.model_validate(raw)

    if has_result and has_error:
        raise ValueError("JSON-RPC response cannot contain both 'result' and 'error'.")
    if has_result:
        return JsonRpcSuccessResponse.model_validate(raw)
    if has_error:
        return JsonRpcErrorResponse.model_validate(raw)
    raise ValueError("Unrecognized JSON-RPC 2.0 frame: missing 'method', 'result', or 'error'.")


def _reject_duplicate_keys(pairs: list[tuple[str, JsonValue]]) -> JsonObject:
    # Python keeps the last duplicate; another parser may keep the first. Either way the airlock could check one
    # value while the downstream server acts on the other, so duplicate keys are rejected outright.
    obj: JsonObject = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"Duplicate JSON object key is forbidden: {key!r}")
        obj[key] = value
    return obj


def parse_jsonrpc_bytes(data: bytes | str) -> JsonRpcMessage:
    """Strictly decode raw UTF-8 JSON bytes/text (no duplicate keys) and validate as a `JsonRpcMessage`."""
    text = data.decode("utf-8") if isinstance(data, bytes) else data
    parsed = json.loads(text, parse_constant=_reject_json_constant, object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(parsed, dict):
        raise ValueError("JSON-RPC frame must be a JSON object.")
    return parse_jsonrpc_message(parsed)


class ToolDefinition(_StrictAirlockModel):
    """MCP downstream tool manifest descriptor pinned by AgBOM (fields per the MCP 2025-06-18 `Tool` type)."""

    name: str = Field(min_length=1)
    title: str | None = None
    description: str = ""
    inputSchema: JsonObject = Field(default_factory=dict)
    outputSchema: JsonObject | None = None
    annotations: JsonObject | None = None
    meta: JsonObject | None = Field(default=None, alias="_meta")

    def wire_dict(self) -> JsonObject:
        """The definition as it appears on the wire (`_meta` alias, unset optional fields omitted)."""
        return cast(JsonObject, self.model_dump(mode="json", by_alias=True, exclude_none=True))

    @field_validator("inputSchema", "outputSchema", "annotations", "meta")
    @classmethod
    def _validate_json_fields(cls, v: JsonObject | None) -> JsonObject | None:
        if v is not None:
            _check_finite_json(v)
        return v


class ToolCallParams(_StrictAirlockModel):
    """Validated `tools/call` params envelope."""

    name: str = Field(min_length=1)
    arguments: JsonObject = Field(default_factory=dict)

    @field_validator("arguments")
    @classmethod
    def _validate_arguments(cls, v: JsonObject) -> JsonObject:
        _check_finite_json(v)
        return v


class ToolPolicyRule(_StrictAirlockModel):
    """Per-tool constraints enforced by `airlock.engine.evaluate_tool_call`."""

    name: str = Field(min_length=1)
    allowed: bool = True
    max_payload_bytes: int | None = Field(default=None, ge=1)
    # When set, any top-level argument not listed here (or in `path_arg_names`) is denied.
    allowed_arg_names: list[str] | None = None
    path_arg_names: list[str] = Field(default_factory=list)
    # Keys the engine would otherwise treat as paths by name (e.g. a translation `target`); `file:` URIs under
    # these keys are still checked.
    non_path_arg_names: list[str] = Field(default_factory=list)
    allowed_path_roots: list[str] = Field(default_factory=list)
    # On by default: guardrail paths (`.git/`, `.github/`, `AGENTS.md`, ...) are denied unless a rule opts out.
    block_guardrail_paths: bool = True
    arg_regex_rules: dict[str, str] = Field(default_factory=dict)
    arg_deny_regex_rules: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _path_and_non_path_names_are_disjoint(self) -> ToolPolicyRule:
        overlap = sorted(set(self.path_arg_names) & set(self.non_path_arg_names))
        if overlap:
            raise ValueError(f"Arguments cannot be in both path_arg_names and non_path_arg_names: {overlap}")
        return self

    @model_validator(mode="after")
    def _compile_regexes(self) -> ToolPolicyRule:
        for arg_name, pattern in self.arg_regex_rules.items():
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"Invalid arg_regex_rules pattern for {arg_name!r}: {exc}") from exc
        for arg_name, pattern in self.arg_deny_regex_rules.items():
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"Invalid arg_deny_regex_rules pattern for {arg_name!r}: {exc}") from exc
        return self


class AirlockPolicy(_StrictAirlockModel):
    """Strict, fail-closed policy governing AgBOM pins, tool allowlists, path bounds, and egress rules."""

    policy_id: str = Field(default="default", min_length=1)
    allowed_tools: list[str] = Field(default_factory=list)
    agbom_pins: dict[str, str] = Field(default_factory=dict)
    manifest_sha256: str | None = None
    max_payload_bytes: int = Field(default=65_536, ge=1)
    workspace_roots: list[str] = Field(default_factory=list)
    tool_rules: dict[str, ToolPolicyRule] = Field(default_factory=dict)
    canary_tokens: list[str] = Field(default_factory=list)
    blocked_patterns: list[str] = Field(default_factory=list)
    entropy_threshold: float = Field(default=4.0, gt=0.0, allow_inf_nan=False)
    min_entropy_length: int = Field(default=20, ge=8)

    @model_validator(mode="after")
    def _tool_rule_keys_match_names(self) -> AirlockPolicy:
        for key, rule in self.tool_rules.items():
            if rule.name != key:
                raise ValueError(f"tool_rules[{key!r}] has name {rule.name!r}; the key and name must match.")
        return self

    @field_validator("manifest_sha256")
    @classmethod
    def _validate_manifest_hash(cls, v: str | None) -> str | None:
        if v is not None and not _SHA256_HEX_RE.fullmatch(v):
            raise ValueError("manifest_sha256 must be a 64-character lowercase hex digest.")
        return v

    @field_validator("agbom_pins")
    @classmethod
    def _validate_pins(cls, v: dict[str, str]) -> dict[str, str]:
        for tool_name, digest in v.items():
            if not tool_name:
                raise ValueError("agbom_pins tool names cannot be empty.")
            if not _SHA256_HEX_RE.fullmatch(digest):
                raise ValueError(f"agbom_pins[{tool_name!r}] must be a 64-character lowercase hex digest.")
        return v

    @field_validator("blocked_patterns")
    @classmethod
    def _validate_blocked_patterns(cls, v: list[str]) -> list[str]:
        for pattern in v:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"Invalid blocked_patterns regex {pattern!r}: {exc}") from exc
        return v


def parse_airlock_policy_toml(toml_text: str) -> AirlockPolicy:
    """
    Strictly parse TOML policy text with the standard-library `tomllib`, without performing any file I/O.

    TOML (unlike YAML) rejects duplicate keys, so a policy cannot silently redefine `allowed_tools`.
    """
    parsed = tomllib.loads(toml_text)
    return AirlockPolicy.model_validate(parsed)
