"""
Pure Airlock policy enforcement engine.

Strict DAG & Invariants:
  - Imports ONLY from `mellyn.core` and `mellyn.egress` (+ stdlib / pydantic).
  - Performs no network, subprocess, stdout, or disk write I/O. Path checks call `Path.resolve(strict=False)`,
    which does read symlinks that already exist, so run the engine with the same filesystem view as the
    downstream server it guards.
  - Pins, artifact hashes, and size caps use the exact bytes that will be forwarded (`exact_json_bytes`).
    Unicode normalization is used only to widen matching (deny rules, canaries), never to make a value pass.
  - Defaults fail-closed (`verdict_allow=False`) on missing policy pins, schema errors,
    invisible Unicode smuggling, traversal escapes, regex violations, or canary/secret detection.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Sequence
from pathlib import Path
from typing import cast
from urllib.parse import unquote, urlparse

from pydantic import ValidationError

from mellyn.airlock.models import (
    AirlockPolicy,
    JsonRpcErrorResponse,
    JsonRpcRequest,
    JsonRpcSuccessResponse,
    ToolCallParams,
    ToolDefinition,
    ToolPolicyRule,
)
from mellyn.core.normalize import (
    JsonObject,
    JsonValue,
    canonical_json_bytes,
    exact_json_bytes,
    has_invisible_unicode,
    normalize_str,
    sha256_exact,
)
from mellyn.core.schemas import RedactionRecord, Verdict
from mellyn.egress.guards import WorkspacePathGuard, owned_file_entries
from mellyn.egress.scanner import EgressScanResult, scan_payload

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_URI_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")
_WINDOWS_DRIVE_URI_PATH_RE = re.compile(r"^/[A-Za-z]:/")

# Argument keys treated as filesystem paths at ANY nesting depth (compared case-insensitively with `_`/`-` removed),
# in addition to a rule's explicit `path_arg_names`. Any string value anywhere that is a `file:` URI is also checked.
_PATH_KEY_EXACT: frozenset[str] = frozenset(
    {"root", "src", "dst", "source", "sources", "target", "targets", "destination", "destinations"}
)
_PATH_KEY_SUFFIXES: tuple[str, ...] = (
    "path",
    "paths",
    "file",
    "files",
    "filename",
    "filenames",
    "dir",
    "dirs",
    "directory",
    "directories",
    "folder",
    "folders",
    "uri",
    "uris",
)


def _is_path_like_key(key: str) -> bool:
    folded = "".join(ch for ch in key.casefold() if ch.isalnum())
    return folded in _PATH_KEY_EXACT or folded.endswith(_PATH_KEY_SUFFIXES)


def _uri_scheme(value: str) -> str | None:
    """Return the casefolded URI scheme of `value`, or None. A single letter is a Windows drive (`C:`), not a scheme."""
    match = _URI_SCHEME_RE.match(value)
    if match is None or len(match.group(1)) == 1:
        return None
    return match.group(1).casefold()


def compute_tool_pin(tool: ToolDefinition) -> str:
    """Compute the AgBOM SHA-256 digest of a single `ToolDefinition` over its exact wire form."""
    return sha256_exact(tool.wire_dict())


def compute_manifest_pin(tools: Sequence[ToolDefinition]) -> str:
    """Compute the AgBOM SHA-256 digest of a complete `tools/list` manifest over its exact wire form."""
    payload: list[JsonValue] = [tool.wire_dict() for tool in tools]
    return sha256_exact(payload)


def _safe_artifact_sha256(obj: JsonValue) -> str:
    """Compute the exact SHA-256 safely; fall back to a repr digest if the input is not strict JSON."""
    try:
        return sha256_exact(obj)
    except (TypeError, ValueError):
        return hashlib.sha256(repr(obj).encode("utf-8", errors="replace")).hexdigest()


def verify_tools_list(tools: Sequence[ToolDefinition], policy: AirlockPolicy) -> Verdict:
    """
    Verify downstream MCP `tools/list` definitions against pinned SHA-256 AgBOM hashes.

    Fails closed (`verdict_allow=False`):
      - Invisible Unicode tag/zero-width/bidi characters anywhere in manifest -> `AAD_FIRE`.
      - Missing AgBOM pins (`agbom_pins` empty and `manifest_sha256 is None`) -> `BLOCK`.
      - Manifest hash mismatch, unpinned tool, or per-tool AgBOM pin mismatch -> `AAD_FIRE`.
    """
    raw_manifest: list[JsonValue] = [t.wire_dict() for t in tools]
    try:
        artifact_sha256 = sha256_exact(raw_manifest)
    except (TypeError, ValueError) as exc:
        return Verdict(
            verdict_allow=False,
            severity="AAD_FIRE",
            rule_id="airlock.manifest_canonicalization_error",
            reason=f"Tool manifest is not strict JSON: {exc}",
            artifact_sha256=_safe_artifact_sha256(raw_manifest),
        )

    if has_invisible_unicode(raw_manifest):
        return Verdict(
            verdict_allow=False,
            severity="AAD_FIRE",
            rule_id="airlock.invisible_unicode_injection",
            reason="Invisible Unicode format/tag characters detected in downstream tool definition.",
            artifact_sha256=artifact_sha256,
        )

    if not policy.agbom_pins and policy.manifest_sha256 is None:
        return Verdict(
            verdict_allow=False,
            severity="BLOCK",
            rule_id="airlock.missing_agbom_pin",
            reason="AirlockPolicy does not pin any AgBOM tool or manifest digests (fail-closed).",
            artifact_sha256=artifact_sha256,
        )

    if policy.manifest_sha256 is not None and artifact_sha256 != policy.manifest_sha256:
        return Verdict(
            verdict_allow=False,
            severity="AAD_FIRE",
            rule_id="airlock.agbom_manifest_mismatch",
            reason="Downstream tools/list manifest SHA-256 does not match pinned AgBOM digest.",
            artifact_sha256=artifact_sha256,
        )

    if policy.agbom_pins:
        for tool in tools:
            pinned_hash = policy.agbom_pins.get(tool.name)
            if pinned_hash is None:
                return Verdict(
                    verdict_allow=False,
                    severity="AAD_FIRE",
                    rule_id="airlock.agbom_unpinned_tool",
                    reason=f"Downstream tool '{tool.name}' has no pinned AgBOM digest.",
                    artifact_sha256=artifact_sha256,
                )
            actual_hash = compute_tool_pin(tool)
            if actual_hash != pinned_hash:
                return Verdict(
                    verdict_allow=False,
                    severity="AAD_FIRE",
                    rule_id="airlock.agbom_pin_mismatch",
                    reason=f"AgBOM SHA-256 mismatch for tool '{tool.name}' (possible rug pull).",
                    artifact_sha256=artifact_sha256,
                )

    return Verdict(
        verdict_allow=True,
        severity="ALLOW",
        rule_id="airlock.agbom_verified",
        reason="Downstream tool manifest matches pinned AgBOM SHA-256 digests.",
        artifact_sha256=artifact_sha256,
        redacted_payload=raw_manifest,
    )


def _has_trailing_space_or_dot_segment(normalized_posix: str) -> bool:
    """Return True if any non-dot component ends in whitespace or '.' (Win32 strips these on open)."""
    return any(part not in ("", ".", "..") and part != part.rstrip(" .") for part in normalized_posix.split("/"))


def _check_lexical_path_containment(
    raw_path: str,
    *,
    roots: Sequence[str],
    block_guardrail_paths: bool,
    owned_files: Sequence[tuple[Path, tuple[str, ...]]] = (),
) -> tuple[bool, str]:
    """
    Validate workspace path containment (`Path.resolve(strict=False)`) and secret-file rules across configured
    `roots`. `file:` URIs (any letter case, any slash count) are decoded to their path; other URI schemes are denied.
    """
    if not raw_path.strip():
        return False, "Empty path argument is forbidden."
    if raw_path != raw_path.strip():
        return False, "Path argument must not have leading or trailing whitespace."
    if _CONTROL_CHARS_RE.search(raw_path) or has_invisible_unicode(raw_path):
        return False, "Path argument contains control or invisible Unicode characters."
    if normalize_str(raw_path) != raw_path:
        return False, "Path argument is not in Unicode NFKC normal form."

    normalized_raw = raw_path.replace("\\", "/")
    if _has_trailing_space_or_dot_segment(normalized_raw):
        return False, "Path component must not end with a space or trailing dot."
    if normalized_raw.startswith("~"):
        return False, "Home-directory tilde paths are forbidden."

    scheme = _uri_scheme(normalized_raw)
    if scheme is not None:
        if scheme != "file":
            return False, f"URI scheme '{scheme}' is not a workspace file path."
        parsed = urlparse(normalized_raw)
        if parsed.netloc.casefold() not in ("", "localhost"):
            return False, "Remote file:// authority is forbidden."
        normalized_raw = unquote(parsed.path)
        if normalized_raw != normalized_raw.strip():
            return False, "Decoded file: URI path must not have leading or trailing whitespace."
        if _CONTROL_CHARS_RE.search(normalized_raw) or has_invisible_unicode(normalized_raw):
            return False, "Decoded file: URI path contains control or invisible Unicode characters."
        if normalize_str(normalized_raw) != normalized_raw:
            return False, "Decoded file: URI path is not in Unicode NFKC normal form."
        # Strip leading slash before Windows drive letters (`file:///C:/...`)
        if _WINDOWS_DRIVE_URI_PATH_RE.match(normalized_raw):
            normalized_raw = normalized_raw[1:]
        if not normalized_raw:
            return False, "file: URI has no path."
        normalized_raw = normalized_raw.replace("\\", "/")
        if _has_trailing_space_or_dot_segment(normalized_raw):
            return False, "Decoded file: URI path component must not end with a space or trailing dot."
        if normalized_raw.startswith("~"):
            return False, "Home-directory tilde paths are forbidden."

    candidate = Path(normalized_raw)
    matched_any_root = False
    last_guard_reason = "Path escapes configured workspace boundary."

    for root_str in roots:
        if not root_str.strip():
            continue
        root_path = Path(root_str).resolve(strict=False)
        try:
            resolved = (candidate if candidate.is_absolute() else root_path / candidate).resolve(strict=False)
        except (OSError, RuntimeError, ValueError):
            continue
        if not resolved.is_relative_to(root_path):
            continue
        matched_any_root = True
        guard = WorkspacePathGuard(root_path, owned_file_entries(root_path, owned_files))
        allowed, reason = guard.validate_path(str(resolved), is_write=block_guardrail_paths)
        if allowed:
            return True, "Path confined inside allowed workspace root."
        last_guard_reason = reason

    if not matched_any_root:
        return False, "Path escapes allowed workspace roots (traversal denied)."
    return False, last_guard_reason


def _gather_path_candidates(
    arguments: JsonObject,
    explicit_keys: frozenset[str],
    exempt_keys: frozenset[str] = frozenset(),
) -> tuple[list[tuple[str, str, bool]], str | None]:
    """
    Walk every argument at every depth and return `(location, value, explicit)` for each string to path-check,
    plus an error message if an explicitly declared path argument has the wrong type.

    `exempt_keys` (a rule's `non_path_arg_names`) opt a key out of the name-based path heuristic only; a `file:`
    URI under an exempt key is still checked.
    """
    found: list[tuple[str, str, bool]] = []

    def visit(value: JsonValue, location: str, key: str) -> str | None:
        explicit = key in explicit_keys
        if isinstance(value, str):
            if explicit or (key not in exempt_keys and _is_path_like_key(key)):
                found.append((location, value, explicit))
            elif _uri_scheme(normalize_str(value).strip()) == "file":
                found.append((location, value, True))
            return None
        if isinstance(value, list):
            if explicit and (not value or not all(isinstance(item, str) for item in value)):
                return f"Path list argument '{location}' must contain non-empty strings."
            for idx, item in enumerate(value):
                error = visit(item, f"{location}[{idx}]", key)
                if error is not None:
                    return error
            return None
        if isinstance(value, dict):
            if explicit:
                return f"Path argument '{location}' must be a string."
            for child_key, child in value.items():
                error = visit(child, f"{location}.{child_key}", child_key)
                if error is not None:
                    return error
            return None
        if explicit:
            return f"Path argument '{location}' must be a string."
        return None

    for top_key, top_value in arguments.items():
        error = visit(top_value, top_key, top_key)
        if error is not None:
            return found, error
    return found, None


def _evaluate_path_rules(
    arguments: JsonObject,
    *,
    tool_rule: ToolPolicyRule | None,
    policy: AirlockPolicy,
) -> tuple[bool, str]:
    roots = tool_rule.allowed_path_roots if (tool_rule and tool_rule.allowed_path_roots) else policy.workspace_roots
    explicit_keys = frozenset(tool_rule.path_arg_names) if tool_rule is not None else frozenset()
    exempt_keys = frozenset(tool_rule.non_path_arg_names) if tool_rule is not None else frozenset()
    candidates, error = _gather_path_candidates(arguments, explicit_keys, exempt_keys)
    if error is not None:
        return False, error
    if not candidates:
        return True, "No path arguments provided."
    if not roots:
        return False, "Path argument supplied without configured workspace_roots (fail-closed)."

    block_guardrails = tool_rule.block_guardrail_paths if tool_rule is not None else True
    for location, raw_value, explicit in candidates:
        if not explicit and raw_value == raw_value.strip():
            # A path-like key holding a non-file URI (`uri: https://...`) is not a filesystem path.
            scheme = _uri_scheme(normalize_str(raw_value).replace("\\", "/"))
            if scheme is not None and scheme != "file":
                continue
        ok, reason = _check_lexical_path_containment(
            raw_value,
            roots=roots,
            block_guardrail_paths=block_guardrails,
            owned_files=policy.owned_files,
        )
        if not ok:
            return False, f"Path rule failed on '{location}': {reason}"
    return True, "Path boundaries satisfied."


def _evaluate_argument_names(arguments: JsonObject, *, tool_rule: ToolPolicyRule | None) -> tuple[bool, str]:
    if tool_rule is None or tool_rule.allowed_arg_names is None:
        return True, "No argument-name allowlist configured."
    permitted = {*tool_rule.allowed_arg_names, *tool_rule.path_arg_names}
    undeclared = [key for key in arguments if key not in permitted]
    if undeclared:
        return False, f"{len(undeclared)} argument(s) not declared in allowed_arg_names."
    return True, "All arguments declared."


def _check_allow_regex_str(val: str, *, label: str, allow_pattern: str) -> str | None:
    if has_invisible_unicode(val):
        return f"Argument '{label}' contains invisible Unicode characters."
    # The exact value is what gets forwarded, so the allow-rule must match the exact value. Rejecting
    # non-NFKC input stops compatibility characters (e.g. full-width letters) matching after normalization.
    if normalize_str(val) != val:
        return f"Argument '{label}' is not in Unicode NFKC normal form."
    if re.fullmatch(allow_pattern, val) is None:
        return f"Argument '{label}' failed required regex constraint."
    return None


def _find_deny_regex_hit(node: JsonValue, *, location: str, deny_pattern: str) -> str | None:
    if isinstance(node, str):
        norm_val = normalize_str(node)
        if re.search(deny_pattern, node) is not None or re.search(deny_pattern, norm_val) is not None:
            return f"Argument '{location}' matched blocked regex constraint."
        return None
    if isinstance(node, list):
        for idx, item in enumerate(node):
            hit = _find_deny_regex_hit(item, location=f"{location}[{idx}]", deny_pattern=deny_pattern)
            if hit is not None:
                return hit
        return None
    if isinstance(node, dict):
        for child_key, child_val in node.items():
            norm_key = normalize_str(child_key)
            if re.search(deny_pattern, child_key) is not None or re.search(deny_pattern, norm_key) is not None:
                return f"Argument '{location}.{child_key}' key matched blocked regex constraint."
            hit = _find_deny_regex_hit(child_val, location=f"{location}.{child_key}", deny_pattern=deny_pattern)
            if hit is not None:
                return hit
        return None
    return None


def _evaluate_regex_rules(arguments: JsonObject, *, tool_rule: ToolPolicyRule | None) -> tuple[bool, str]:
    if tool_rule is None:
        return True, "No regex rules configured."
    for key, allow_pattern in tool_rule.arg_regex_rules.items():
        if key not in arguments:
            return False, f"Missing required argument '{key}' for regex policy rule."
        val = arguments[key]
        if isinstance(val, str):
            err = _check_allow_regex_str(val, label=key, allow_pattern=allow_pattern)
            if err is not None:
                return False, err
        elif isinstance(val, list):
            if not val:
                return False, f"Argument '{key}' list cannot be empty for regex policy validation."
            for idx, item in enumerate(val):
                if not isinstance(item, str):
                    return False, f"Argument '{key}[{idx}]' must be a string for regex policy validation."
                err = _check_allow_regex_str(item, label=f"{key}[{idx}]", allow_pattern=allow_pattern)
                if err is not None:
                    return False, err
        else:
            return False, f"Argument '{key}' must be a string or list of strings for regex policy validation."

    for key, deny_pattern in tool_rule.arg_deny_regex_rules.items():
        if key not in arguments:
            continue
        val = arguments[key]
        if not isinstance(val, str | list | dict):
            return False, f"Argument '{key}' must be a string, list, or object for deny regex inspection."
        hit = _find_deny_regex_hit(val, location=key, deny_pattern=deny_pattern)
        if hit is not None:
            return False, hit
    return True, "Regex rules satisfied."


MAX_RPC_ID_CHARS = 128
_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1


def rpc_id_problem(rpc_id: int | str | None) -> str | None:
    """
    Bound the JSON-RPC `id` so it cannot carry bulk data: strings up to `MAX_RPC_ID_CHARS` without control
    characters (an id lands in audit records and reports, where a newline could forge lines), integers within
    signed 64-bit. Returns a reason string when the id is out of bounds.
    """
    if isinstance(rpc_id, str) and len(rpc_id) > MAX_RPC_ID_CHARS:
        return f"JSON-RPC id is longer than {MAX_RPC_ID_CHARS} characters."
    if isinstance(rpc_id, str) and _CONTROL_CHARS_RE.search(rpc_id):
        return "JSON-RPC id contains control characters."
    if isinstance(rpc_id, int) and not _INT64_MIN <= rpc_id <= _INT64_MAX:
        return "JSON-RPC integer id is outside the signed 64-bit range."
    return None


MAX_OPAQUE_TOKEN_CHARS = 1024


def compute_instructions_pin(instructions: str) -> str:
    """SHA-256 of a server's `initialize` `instructions` text, exactly as sent (UTF-8, no normalization)."""
    return hashlib.sha256(instructions.encode("utf-8")).hexdigest()


def scan_opaque_token(value: str, policy: AirlockPolicy, *, field_path: str) -> EgressScanResult:
    """
    Scan an opaque protocol token (a JSON-RPC `id`, a pagination cursor) for canaries, known secret formats and
    blocked patterns.

    The high-entropy detector is switched off here (an infinite threshold never matches): such tokens are
    legitimately random, e.g. `secrets.token_urlsafe(16)` ids or base64 cursors, which it would flag. Callers bound
    the size separately (`rpc_id_problem`, `MAX_OPAQUE_TOKEN_CHARS`).
    """
    result = scan_payload(
        value,
        canary_tokens=policy.canary_tokens,
        blocked_patterns=policy.blocked_patterns,
        entropy_threshold=math.inf,
        min_entropy_length=policy.min_entropy_length,
    )
    remapped = [
        RedactionRecord(
            kind=rec.kind,
            rule_id=rec.rule_id,
            field_path=field_path if rec.field_path == "$" else rec.field_path,
            match_sha256=rec.match_sha256,
        )
        for rec in result.findings
    ]
    return EgressScanResult(
        artifact_sha256=result.artifact_sha256,
        clean=result.clean,
        canary_matched=result.canary_matched,
        secret_matched=result.secret_matched,
        high_entropy_matched=result.high_entropy_matched,
        blocked_pattern_matched=result.blocked_pattern_matched,
        findings=remapped,
        redacted_payload=result.redacted_payload,
    )


def scan_rpc_id(request_id: int | str | None, policy: AirlockPolicy) -> EgressScanResult | None:
    """Scan a string JSON-RPC `id` (see `scan_opaque_token`); integer and null ids carry no text to scan."""
    if not isinstance(request_id, str):
        return None
    return scan_opaque_token(request_id, policy, field_path="$.id")


def evaluate_tool_call(request: JsonRpcRequest, policy: AirlockPolicy) -> Verdict:
    """
    Pure fail-closed evaluation of an outbound MCP `tools/call` request:
      1. Computes `artifact_sha256` and the payload size over the exact bytes to be forwarded.
      2. Enforces the payload byte cap BEFORE any content scanning.
      3. Scans arguments with `egress.scanner` (planted canary -> `AAD_FIRE`).
      4. Enforces allowlisted tool name, invisible-Unicode rejection, declared argument names, workspace path
         containment, regex argument rules, and egress secret/blocked-pattern policies (`BLOCK`).
    """
    raw_req: JsonObject = cast(JsonObject, request.model_dump(mode="json"))
    try:
        raw_bytes = exact_json_bytes(raw_req)
    except (TypeError, ValueError) as exc:
        return Verdict(
            verdict_allow=False,
            severity="BLOCK",
            rule_id="airlock.request_canonicalization_error",
            reason=f"Request is not strict JSON: {exc}",
            artifact_sha256=_safe_artifact_sha256(raw_req),
        )
    artifact_sha256 = hashlib.sha256(raw_bytes).hexdigest()

    if request.method != "tools/call":
        return Verdict(
            verdict_allow=False,
            severity="BLOCK",
            rule_id="airlock.unsupported_method",
            reason=f"Expected method 'tools/call', got '{request.method}'.",
            artifact_sha256=artifact_sha256,
        )

    try:
        call_params = ToolCallParams.model_validate(request.params)
    except ValidationError as exc:
        return Verdict(
            verdict_allow=False,
            severity="BLOCK",
            rule_id="airlock.invalid_tool_call_params",
            reason=f"Invalid tools/call parameters ({exc.error_count()} validation error(s)).",
            artifact_sha256=artifact_sha256,
        )

    tool_rule = policy.tool_rules.get(call_params.name)
    max_bytes = (
        tool_rule.max_payload_bytes
        if (tool_rule is not None and tool_rule.max_payload_bytes is not None)
        else policy.max_payload_bytes
    )
    if len(raw_bytes) > max_bytes:
        return Verdict(
            verdict_allow=False,
            severity="BLOCK",
            rule_id="airlock.payload_too_large",
            reason=f"Request size {len(raw_bytes)} exceeds limit of {max_bytes} bytes.",
            artifact_sha256=artifact_sha256,
        )

    id_problem = rpc_id_problem(request.id)
    if id_problem is not None:
        return Verdict(
            verdict_allow=False,
            severity="BLOCK",
            rule_id="airlock.invalid_request_id",
            reason=id_problem,
            artifact_sha256=artifact_sha256,
        )

    try:
        canonical_json_bytes(raw_req)  # rejects keys that collide after NFKC normalization
    except (TypeError, ValueError) as exc:
        return Verdict(
            verdict_allow=False,
            severity="BLOCK",
            rule_id="airlock.request_canonicalization_error",
            reason=f"Request failed canonical normalization: {exc}",
            artifact_sha256=artifact_sha256,
        )

    scan = scan_payload(
        call_params.arguments,
        canary_tokens=policy.canary_tokens,
        blocked_patterns=policy.blocked_patterns,
        entropy_threshold=policy.entropy_threshold,
        min_entropy_length=policy.min_entropy_length,
    )
    id_scan = scan_rpc_id(request.id, policy)
    all_findings = [*(id_scan.findings if id_scan is not None else ()), *scan.findings]

    if scan.canary_matched or (id_scan is not None and id_scan.canary_matched):
        return Verdict(
            verdict_allow=False,
            severity="AAD_FIRE",
            rule_id="egress.canary_exfiltration",
            reason="Planted canary token detected in tool call request.",
            artifact_sha256=artifact_sha256,
            redactions=all_findings,
            redacted_payload=scan.redacted_payload,
        )

    def _block(rule_id: str, reason: str) -> Verdict:
        return Verdict(
            verdict_allow=False,
            severity="BLOCK",
            rule_id=rule_id,
            reason=reason,
            artifact_sha256=artifact_sha256,
            redactions=all_findings,
            redacted_payload=scan.redacted_payload,
        )

    if call_params.name not in policy.allowed_tools or (tool_rule is not None and not tool_rule.allowed):
        return _block("airlock.tool_not_allowed", f"Tool '{call_params.name}' is not allowlisted by AirlockPolicy.")

    names_ok, names_reason = _evaluate_argument_names(call_params.arguments, tool_rule=tool_rule)
    if not names_ok:
        return _block("airlock.undeclared_argument", names_reason)

    path_ok, path_reason = _evaluate_path_rules(call_params.arguments, tool_rule=tool_rule, policy=policy)
    if not path_ok:
        return _block("airlock.path_boundary_violation", path_reason)

    regex_ok, regex_reason = _evaluate_regex_rules(call_params.arguments, tool_rule=tool_rule)
    if not regex_ok:
        return _block("airlock.arg_regex_violation", regex_reason)

    # After the path and regex checks so they report their own, more specific reason first.
    if has_invisible_unicode(call_params.arguments):
        return _block(
            "airlock.invisible_unicode_in_arguments",
            "Tool call arguments contain invisible Unicode format/tag characters (smuggling channel).",
        )

    if isinstance(request.id, str) and has_invisible_unicode(request.id):
        return _block(
            "airlock.invisible_unicode_in_request_id",
            "JSON-RPC request id contains invisible Unicode format/tag characters.",
        )

    if not scan.clean or (id_scan is not None and not id_scan.clean):
        return _block(
            "egress.secret_or_blocked_pattern",
            "Egress scanner detected secret material or blocked pattern in tool call request.",
        )

    return Verdict(
        verdict_allow=True,
        severity="ALLOW",
        rule_id="airlock.tool_call_allowed",
        reason=f"Tool call '{call_params.name}' satisfied all airlock and egress checks.",
        artifact_sha256=artifact_sha256,
        redacted_payload=scan.redacted_payload,
    )


_RESOURCE_BLOB_PLACEHOLDER = "[RESOURCE_BLOB]"


def _split_resource_blobs(payload: JsonValue, policy: AirlockPolicy) -> tuple[JsonValue, list[EgressScanResult]]:
    """
    For a `resources/read` result, scan each `contents[i].blob` (base64 binary) as an opaque token and blank it out
    of the main scan. Binary data always looks high-entropy, so the entropy detector would block every image or
    archive; canaries (including base64-decoded forms), known secret formats and blocked patterns are still checked.
    """
    if not isinstance(payload, dict):
        return payload, []
    contents = payload.get("contents")
    if not isinstance(contents, list):
        return payload, []
    blob_scans: list[EgressScanResult] = []
    scanned_contents: list[JsonValue] = []
    for idx, item in enumerate(contents):
        if isinstance(item, dict) and isinstance(item.get("blob"), str):
            blob = cast(str, item["blob"])
            blob_scans.append(scan_opaque_token(blob, policy, field_path=f"$.contents[{idx}].blob"))
            scanned_contents.append({**item, "blob": _RESOURCE_BLOB_PLACEHOLDER})
        else:
            scanned_contents.append(item)
    return {**payload, "contents": scanned_contents}, blob_scans


def evaluate_tool_response(
    response: JsonRpcSuccessResponse | JsonRpcErrorResponse,
    policy: AirlockPolicy,
    *,
    resource_read: bool = False,
) -> Verdict:
    """
    Scan inbound downstream tool outputs through `egress.scanner` (canary -> `AAD_FIRE`, secrets -> `BLOCK`).

    With `resource_read=True` (a `resources/read` response), `contents[].blob` values are scanned without the
    high-entropy detector; see `_split_resource_blobs`.
    """
    raw_resp: JsonObject = cast(JsonObject, response.model_dump(mode="json"))
    try:
        raw_bytes = exact_json_bytes(raw_resp)
    except (TypeError, ValueError) as exc:
        return Verdict(
            verdict_allow=False,
            severity="BLOCK",
            rule_id="airlock.response_canonicalization_error",
            reason=f"Response is not strict JSON: {exc}",
            artifact_sha256=_safe_artifact_sha256(raw_resp),
        )
    artifact_sha256 = hashlib.sha256(raw_bytes).hexdigest()

    # Size cap before any scanning, so an oversized response cannot buy unbounded scanner time.
    if len(raw_bytes) > policy.max_payload_bytes:
        return Verdict(
            verdict_allow=False,
            severity="BLOCK",
            rule_id="airlock.response_too_large",
            reason=f"Response size {len(raw_bytes)} exceeds limit of {policy.max_payload_bytes} bytes.",
            artifact_sha256=artifact_sha256,
        )

    id_problem = rpc_id_problem(response.id)
    if id_problem is not None:
        return Verdict(
            verdict_allow=False,
            severity="BLOCK",
            rule_id="airlock.invalid_response_id",
            reason=id_problem,
            artifact_sha256=artifact_sha256,
        )

    try:
        canonical_json_bytes(raw_resp)  # reject keys that collide after NFKC normalization
    except (TypeError, ValueError) as exc:
        return Verdict(
            verdict_allow=False,
            severity="BLOCK",
            rule_id="airlock.response_canonicalization_error",
            reason=f"Response failed canonical normalization: {exc}",
            artifact_sha256=artifact_sha256,
        )

    payload: JsonValue = (
        response.result
        if isinstance(response, JsonRpcSuccessResponse)
        else cast(JsonObject, response.error.model_dump(mode="json"))
    )
    scan_target, blob_scans = (
        _split_resource_blobs(payload, policy)
        if (resource_read and isinstance(response, JsonRpcSuccessResponse))
        else (payload, [])
    )
    scan = scan_payload(
        scan_target,
        canary_tokens=policy.canary_tokens,
        blocked_patterns=policy.blocked_patterns,
        entropy_threshold=policy.entropy_threshold,
        min_entropy_length=policy.min_entropy_length,
    )
    id_scan = scan_rpc_id(response.id, policy)
    all_findings = [
        *(id_scan.findings if id_scan is not None else ()),
        *scan.findings,
        *(finding for blob_scan in blob_scans for finding in blob_scan.findings),
    ]
    blob_canary = any(blob_scan.canary_matched for blob_scan in blob_scans)
    blob_dirty = any(not blob_scan.clean for blob_scan in blob_scans)

    if scan.canary_matched or blob_canary or (id_scan is not None and id_scan.canary_matched):
        return Verdict(
            verdict_allow=False,
            severity="AAD_FIRE",
            rule_id="egress.response_canary_detected",
            reason="Planted canary token detected in inbound tool response.",
            artifact_sha256=artifact_sha256,
            redactions=all_findings,
            redacted_payload=scan.redacted_payload,
        )

    if has_invisible_unicode(payload) or (isinstance(response.id, str) and has_invisible_unicode(response.id)):
        return Verdict(
            verdict_allow=False,
            severity="BLOCK",
            rule_id="airlock.invisible_unicode_in_response",
            reason="Inbound tool response contains invisible Unicode format/tag characters (smuggling channel).",
            artifact_sha256=artifact_sha256,
            redactions=all_findings,
            redacted_payload=scan.redacted_payload,
        )

    if not scan.clean or blob_dirty or (id_scan is not None and not id_scan.clean):
        return Verdict(
            verdict_allow=False,
            severity="BLOCK",
            rule_id="egress.response_secret_or_blocked",
            reason="Egress scanner detected secret material or blocked pattern in inbound tool response.",
            artifact_sha256=artifact_sha256,
            redactions=all_findings,
            redacted_payload=scan.redacted_payload,
        )

    return Verdict(
        verdict_allow=True,
        severity="ALLOW",
        rule_id="airlock.response_allowed",
        reason="Inbound tool response cleared egress scanning.",
        artifact_sha256=artifact_sha256,
        redacted_payload=scan.redacted_payload,
    )


def evaluate_resource_read(request: JsonRpcRequest, policy: AirlockPolicy) -> Verdict:
    """
    Pure fail-closed evaluation of an outbound MCP `resources/read` request:
      1. Computes `artifact_sha256` and payload cap over exact wire bytes before content scanning.
      2. Scans `params` and `id` through `egress.scanner` (canary -> `AAD_FIRE`).
      3. Enforces `policy.allow_resources_read` and workspace confinement on `params.uri` (`file://` or relative).
    """
    raw_req: JsonObject = cast(JsonObject, request.model_dump(mode="json"))
    try:
        raw_bytes = exact_json_bytes(raw_req)
    except (TypeError, ValueError) as exc:
        return Verdict(
            verdict_allow=False,
            severity="BLOCK",
            rule_id="airlock.request_canonicalization_error",
            reason=f"Request is not strict JSON: {exc}",
            artifact_sha256=_safe_artifact_sha256(raw_req),
        )
    artifact_sha256 = hashlib.sha256(raw_bytes).hexdigest()

    if request.method != "resources/read":
        return Verdict(
            verdict_allow=False,
            severity="BLOCK",
            rule_id="airlock.unsupported_method",
            reason=f"Expected method 'resources/read', got '{request.method}'.",
            artifact_sha256=artifact_sha256,
        )

    if len(raw_bytes) > policy.max_payload_bytes:
        return Verdict(
            verdict_allow=False,
            severity="BLOCK",
            rule_id="airlock.payload_too_large",
            reason=f"Request size {len(raw_bytes)} exceeds limit of {policy.max_payload_bytes} bytes.",
            artifact_sha256=artifact_sha256,
        )

    id_problem = rpc_id_problem(request.id)
    if id_problem is not None:
        return Verdict(
            verdict_allow=False,
            severity="BLOCK",
            rule_id="airlock.invalid_request_id",
            reason=id_problem,
            artifact_sha256=artifact_sha256,
        )

    try:
        canonical_json_bytes(raw_req)
    except (TypeError, ValueError) as exc:
        return Verdict(
            verdict_allow=False,
            severity="BLOCK",
            rule_id="airlock.request_canonicalization_error",
            reason=f"Request failed canonical normalization: {exc}",
            artifact_sha256=artifact_sha256,
        )

    scan = scan_payload(
        request.params,
        canary_tokens=policy.canary_tokens,
        blocked_patterns=policy.blocked_patterns,
        entropy_threshold=policy.entropy_threshold,
        min_entropy_length=policy.min_entropy_length,
    )
    id_scan = scan_rpc_id(request.id, policy)
    all_findings = [*(id_scan.findings if id_scan is not None else ()), *scan.findings]

    if scan.canary_matched or (id_scan is not None and id_scan.canary_matched):
        return Verdict(
            verdict_allow=False,
            severity="AAD_FIRE",
            rule_id="egress.canary_exfiltration",
            reason="Planted canary token detected in resources/read request.",
            artifact_sha256=artifact_sha256,
            redactions=all_findings,
            redacted_payload=scan.redacted_payload,
        )

    def _block(rule_id: str, reason: str) -> Verdict:
        return Verdict(
            verdict_allow=False,
            severity="BLOCK",
            rule_id=rule_id,
            reason=reason,
            artifact_sha256=artifact_sha256,
            redactions=all_findings,
            redacted_payload=scan.redacted_payload,
        )

    if not policy.allow_resources_read:
        return _block(
            "airlock.method_not_allowed",
            "JSON-RPC method 'resources/read' is disabled (allow_resources_read = false).",
        )

    uri = request.params.get("uri")
    if not isinstance(uri, str) or not uri.strip():
        return _block(
            "airlock.invalid_resource_uri",
            "resources/read requires a non-empty string 'uri' parameter.",
        )

    if not policy.workspace_roots:
        return _block(
            "airlock.path_boundary_violation",
            "resources/read denied without configured workspace_roots (fail-closed).",
        )

    path_ok, path_reason = _check_lexical_path_containment(
        uri,
        roots=policy.workspace_roots,
        block_guardrail_paths=True,
        owned_files=policy.owned_files,
    )
    if not path_ok:
        return _block("airlock.path_boundary_violation", f"Resource URI blocked: {path_reason}")

    if has_invisible_unicode(request.params):
        return _block(
            "airlock.invisible_unicode_in_arguments",
            "resources/read parameters contain invisible Unicode format/tag characters.",
        )

    if isinstance(request.id, str) and has_invisible_unicode(request.id):
        return _block(
            "airlock.invisible_unicode_in_request_id",
            "JSON-RPC request id contains invisible Unicode format/tag characters.",
        )

    if not scan.clean or (id_scan is not None and not id_scan.clean):
        return _block(
            "egress.secret_or_blocked_pattern",
            "Egress scanner detected secret material or blocked pattern in resources/read request.",
        )

    return Verdict(
        verdict_allow=True,
        severity="ALLOW",
        rule_id="airlock.resource_read_allowed",
        reason="resources/read URI satisfied workspace confinement and egress checks.",
        artifact_sha256=artifact_sha256,
        redacted_payload=scan.redacted_payload,
    )
