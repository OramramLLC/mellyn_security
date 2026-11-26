"""
Quarantined AgBOM pinning CLI (`mellyn-pin`).

Spawns a target MCP server in a short-lived isolated subprocess (allowlisted env only, bounded framing, strict
timeout), runs `initialize` + `tools/list`, checks for invisible Unicode smuggling and non-NFKC anomalies, computes
exact `sha256_exact` AgBOM digests matching `airlock.engine.verify_tools_list`, and writes a fail-closed starter
TOML `AirlockPolicy` requiring explicit human approval before any tool is permitted.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import re
import sys
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mellyn.airlock.engine import compute_instructions_pin, compute_manifest_pin, compute_tool_pin
from mellyn.airlock.models import (
    AirlockPolicy,
    JsonRpcErrorResponse,
    JsonRpcNotification,
    JsonRpcRequest,
    JsonRpcSuccessResponse,
    ToolDefinition,
    parse_airlock_policy_toml,
    parse_jsonrpc_bytes,
)
from mellyn.airlock.proxy import (
    BoundedLineReader,
    _hard_kill_subprocess,
    build_minimal_subprocess_env,
    parse_allow_env_keys,
    spawn_contained_subprocess,
)
from mellyn.core.normalize import JsonObject, exact_json_bytes, has_invisible_unicode, normalize_value

MAX_PIN_PAGES = 20
MAX_PIN_FRAME_BYTES = 1_048_576
DEFAULT_PIN_TIMEOUT_SECONDS = 15.0
_BARE_TOML_KEY_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class PinInspectionError(RuntimeError):
    """Raised fail-closed when the target MCP server cannot be safely inspected or pinned."""


class PinInspectionResult(BaseModel):
    """Structured result from a quarantined `mellyn-pin` inspection session."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    tools: list[ToolDefinition] = Field(default_factory=list)
    tool_pins: dict[str, str] = Field(default_factory=dict)
    manifest_sha256: str
    instructions_sha256: str | None = None
    # True when tools/list needed more than one page. The proxy checks `manifest_sha256` against each page on its
    # own, so a whole-listing manifest pin would never match; per-tool pins are used instead.
    paginated: bool = False
    warnings: list[str] = Field(default_factory=list)


def _toml_key(key: str) -> str:
    return key if _BARE_TOML_KEY_RE.fullmatch(key) else json.dumps(key, ensure_ascii=False)


def _toml_str(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


async def _send_frame(proc: asyncio.subprocess.Process, payload: JsonObject) -> None:
    if proc.stdin is None:
        raise PinInspectionError("Downstream server stdin is unavailable.")
    proc.stdin.write(exact_json_bytes(payload) + b"\n")
    await proc.stdin.drain()


async def _read_matching_response(
    reader: BoundedLineReader,
    *,
    expected_id: int,
) -> JsonRpcSuccessResponse:
    while True:
        frame, oversized = await reader.read_frame()
        if oversized:
            raise PinInspectionError("Downstream server emitted oversized frame exceeding inspection limit.")
        if frame is None:
            raise PinInspectionError(f"Downstream server closed stdout before replying to id={expected_id}.")
        if not frame.strip():
            continue
        try:
            msg = parse_jsonrpc_bytes(frame)
        except (UnicodeDecodeError, ValueError, ValidationError) as exc:
            raise PinInspectionError(f"Downstream server emitted malformed JSON-RPC frame: {exc}") from exc

        if isinstance(msg, JsonRpcNotification | JsonRpcRequest):
            continue
        if isinstance(msg, JsonRpcErrorResponse):
            if msg.id == expected_id:
                raise PinInspectionError(
                    f"Downstream server returned JSON-RPC error {msg.error.code}: {msg.error.message}"
                )
            continue
        if msg.id != expected_id:
            raise PinInspectionError(f"Downstream server returned unexpected response id {msg.id!r}.")
        return msg


async def inspect_mcp_server(
    command: Sequence[str],
    *,
    allowed_env_keys: Sequence[str] | None = None,
    timeout_seconds: float = DEFAULT_PIN_TIMEOUT_SECONDS,
    max_frame_bytes: int = MAX_PIN_FRAME_BYTES,
) -> PinInspectionResult:
    """
    Spawn `command` inside an isolated stdio quarantine, perform `initialize` + paginated `tools/list`,
    reap the subprocess unconditionally, and return exact AgBOM pins + any Unicode smuggling warnings.
    """
    if not command:
        raise ValueError("Target command must not be empty.")
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be a finite positive number.")

    child_env = build_minimal_subprocess_env(allowed_keys=allowed_env_keys)
    # stderr is discarded: nothing reads it here, and an undrained pipe would stall a chatty server until timeout.
    proc, job = await spawn_contained_subprocess(command, env=child_env, stderr=asyncio.subprocess.DEVNULL)
    pages = 0
    try:
        if proc.stdout is None:
            raise PinInspectionError("Downstream server stdout is unavailable.")
        reader = BoundedLineReader(proc.stdout, max_bytes=max_frame_bytes)
        warnings: list[str] = []
        instructions_pin: str | None = None

        async with asyncio.timeout(timeout_seconds):
            await _send_frame(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "mellyn-pin", "version": "1.0.0"},
                    },
                },
            )
            init_resp = await _read_matching_response(reader, expected_id=1)
            if isinstance(init_resp.result, dict):
                raw_instr = init_resp.result.get("instructions")
                if isinstance(raw_instr, str):
                    if has_invisible_unicode(raw_instr):
                        # The proxy would block these instructions anyway; pinning them would only hide the problem.
                        raise PinInspectionError(
                            "Server initialize instructions contain invisible Unicode format/tag characters "
                            "(potential pre-poisoned server); refusing to pin."
                        )
                    if normalize_value(raw_instr) != raw_instr:
                        warnings.append(
                            "WARNING: Server initialize instructions contain non-NFKC compatibility characters."
                        )
                    instructions_pin = compute_instructions_pin(raw_instr)

            await _send_frame(
                proc,
                {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            )

            tools: list[ToolDefinition] = []
            seen_names: set[str] = set()
            seen_cursors: set[str] = set()
            cursor: str | None = None
            req_id = 2

            for _page in range(MAX_PIN_PAGES):
                params: JsonObject = {"cursor": cursor} if cursor is not None else {}
                await _send_frame(proc, {"jsonrpc": "2.0", "id": req_id, "method": "tools/list", "params": params})
                list_resp = await _read_matching_response(reader, expected_id=req_id)
                pages += 1
                req_id += 1

                if not isinstance(list_resp.result, dict):
                    raise PinInspectionError("tools/list result must be a JSON object.")
                raw_tools = list_resp.result.get("tools")
                if not isinstance(raw_tools, list):
                    raise PinInspectionError("tools/list result must contain a 'tools' list.")

                for raw_entry in raw_tools:
                    if not isinstance(raw_entry, dict):
                        raise PinInspectionError("Each tools/list entry must be a JSON object.")
                    try:
                        tool = ToolDefinition.model_validate(raw_entry)
                    except ValidationError as exc:
                        raise PinInspectionError(f"Invalid tool definition returned by server: {exc}") from exc
                    if tool.name in seen_names:
                        raise PinInspectionError(f"Duplicate tool definition '{tool.name}' returned by server.")
                    seen_names.add(tool.name)
                    wire = tool.wire_dict()
                    if has_invisible_unicode(wire):
                        # verify_tools_list fires AAD on these regardless of pins, so refuse instead of warning.
                        raise PinInspectionError(
                            f"Tool '{tool.name}' contains invisible Unicode format/tag characters "
                            "(potential pre-poisoned server); refusing to pin."
                        )
                    if normalize_value(wire) != wire:
                        warnings.append(
                            f"WARNING: Tool '{tool.name}' contains non-NFKC compatibility characters "
                            "(potential lookalike poisoning)."
                        )
                    tools.append(tool)

                next_cursor = list_resp.result.get("nextCursor")
                if next_cursor is None or next_cursor == "":
                    break
                if not isinstance(next_cursor, str) or next_cursor in seen_cursors:
                    raise PinInspectionError("Downstream server returned invalid or cyclic tools/list cursor.")
                seen_cursors.add(next_cursor)
                cursor = next_cursor
            else:
                raise PinInspectionError(f"Downstream server exceeded MAX_PIN_PAGES ({MAX_PIN_PAGES}).")

        pins = {tool.name: compute_tool_pin(tool) for tool in tools}
        manifest_sha = compute_manifest_pin(tools)
        return PinInspectionResult(
            tools=tools,
            tool_pins=pins,
            manifest_sha256=manifest_sha,
            paginated=pages > 1,
            instructions_sha256=instructions_pin,
            warnings=warnings,
        )
    except TimeoutError as exc:
        raise PinInspectionError(f"Quarantined inspection timed out after {timeout_seconds}s.") from exc
    finally:
        if proc.stdin is not None:
            try:
                proc.stdin.close()
            except OSError:
                pass
        await _hard_kill_subprocess(proc, job=job)
        if job is not None:
            job.close()


def render_starter_policy_toml(
    inspection: PinInspectionResult,
    *,
    policy_id: str = "pinned-server",
    max_payload_bytes: int = 65_536,
) -> str:
    """
    Render a fail-closed starter TOML `AirlockPolicy` requiring human review before any tool call is allowed.

    Validates the generated TOML back through `parse_airlock_policy_toml()` before returning.
    """
    lines: list[str] = [
        "# Generated by mellyn-pin (fail-closed AgBOM starter policy).",
        "# Human review required: inspect every pinned tool below, set `workspace_roots`,",
        "# add approved tool names to `allowed_tools`, and flip `[tool_rules.<name>].allowed = true`.",
        "",
        f"policy_id = {_toml_str(policy_id)}",
        "# Default-deny posture: no tools are allowed until explicitly reviewed and allowlisted.",
        "allowed_tools = []",
        f"max_payload_bytes = {max_payload_bytes}",
        "workspace_roots = []",
    ]
    if inspection.paginated:
        # The proxy checks manifest_sha256 against each tools/list page on its own, so a pin over the whole
        # paginated listing would never match; the per-tool [agbom_pins] below cover every page instead.
        lines.append("# manifest_sha256 omitted: this server paginates tools/list (per-tool pins apply).")
    else:
        lines.append(f"manifest_sha256 = {_toml_str(inspection.manifest_sha256)}")
    if inspection.instructions_sha256 is not None:
        lines.append(f"instructions_sha256 = {_toml_str(inspection.instructions_sha256)}")

    lines.extend(["", "[agbom_pins]"])
    for tool in inspection.tools:
        pin = inspection.tool_pins[tool.name]
        lines.append(f"{_toml_key(tool.name)} = {_toml_str(pin)}")

    for tool in inspection.tools:
        lines.extend(
            [
                "",
                f"[tool_rules.{_toml_key(tool.name)}]",
                f"name = {_toml_str(tool.name)}",
                "allowed = false",
                "# Review and restrict permitted argument names & regex constraints before enabling:",
                "allowed_arg_names = []",
                "arg_regex_rules = {}",
            ]
        )

    rendered = "\n".join(lines) + "\n"
    _validated: AirlockPolicy = parse_airlock_policy_toml(rendered)
    return rendered


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mellyn-pin",
        description="Inspect an MCP server in a quarantined stdio session and emit a fail-closed AgBOM TOML policy.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("airlock_policy.toml"),
        help="Destination path for the generated starter TOML policy (default: airlock_policy.toml).",
    )
    parser.add_argument(
        "--allow-env",
        default=None,
        help="Comma-separated extra environment variable names permitted inside the quarantined subprocess.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_PIN_TIMEOUT_SECONDS,
        help=f"Inspection timeout in seconds (default: {DEFAULT_PIN_TIMEOUT_SECONDS}).",
    )
    parser.add_argument(
        "--policy-id",
        default="pinned-server",
        help="policy_id value recorded in the generated TOML policy.",
    )
    parser.add_argument(
        "--max-payload-bytes",
        type=int,
        default=65_536,
        help="Default max_payload_bytes recorded in the starter policy (default: 65536).",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Target MCP server command to inspect (prefix with '--').",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `mellyn-pin`."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        sys.stderr.write("mellyn-pin: missing target MCP server command after '--'.\n")
        return 2
    if args.max_payload_bytes <= 0:
        sys.stderr.write("mellyn-pin: --max-payload-bytes must be positive.\n")
        return 2

    try:
        allowed_env = parse_allow_env_keys(args.allow_env)
        inspection = asyncio.run(
            inspect_mcp_server(
                command,
                allowed_env_keys=allowed_env,
                timeout_seconds=args.timeout,
            )
        )
    except (OSError, ValueError, PinInspectionError) as exc:
        sys.stderr.write(f"mellyn-pin: inspection failed: {exc}\n")
        return 2

    for warning in inspection.warnings:
        sys.stderr.write(f"[mellyn-pin] {warning}\n")

    try:
        toml_text = render_starter_policy_toml(
            inspection,
            policy_id=args.policy_id,
            max_payload_bytes=args.max_payload_bytes,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(toml_text, encoding="utf-8", newline="\n")
    except (OSError, ValueError, ValidationError) as exc:
        sys.stderr.write(f"mellyn-pin: failed to write policy '{args.output}': {exc}\n")
        return 2

    sys.stderr.write(
        f"[mellyn-pin] Pinned {len(inspection.tools)} tool(s) "
        f"(manifest_sha256={inspection.manifest_sha256}) -> {args.output}\n"
    )
    return 0


__all__ = [
    "DEFAULT_PIN_TIMEOUT_SECONDS",
    "MAX_PIN_FRAME_BYTES",
    "MAX_PIN_PAGES",
    "PinInspectionError",
    "PinInspectionResult",
    "inspect_mcp_server",
    "main",
    "render_starter_policy_toml",
]


if __name__ == "__main__":
    raise SystemExit(main())
