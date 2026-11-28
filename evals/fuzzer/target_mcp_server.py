"""
Stdlib-only MCP 2025-06-18 stdio target server for `mcp-fuzzer` and Airlock smoke testing.

Exposes benign workspace operations (`read_note`, `write_note`, `echo_status`) inside a controlled
sandbox directory so Mellyn Airlock's AgBOM pinning, path confinement, guardrail protection,
and canary AAD containment can be evaluated end-to-end.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "mellyn-eval-fuzzer-target", "version": "1.0.0"}
SERVER_INSTRUCTIONS = "Restricted evaluation workspace server for fuzzing Mellyn Airlock boundaries."

TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "read_note",
        "description": "Read a text note from the evaluation workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative or workspace path to read."},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "write_note",
        "description": "Write a text note inside the evaluation workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Destination file path."},
                "content": {"type": "string", "description": "Text contents to store."},
            },
            "required": ["path", "content"],
            "additionalProperties": False,
        },
    },
    {
        "name": "echo_status",
        "description": "Echo a diagnostic status message.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "Diagnostic text to echo."},
            },
            "required": ["message"],
            "additionalProperties": False,
        },
    },
]


def _jsonrpc_result(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _jsonrpc_error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _resolve_target_path(workspace: Path, raw_path: str) -> Path:
    candidate = Path(raw_path)
    if candidate.is_absolute():
        return candidate
    return workspace / candidate


def handle_jsonrpc_message(msg: dict[str, Any], workspace: Path) -> dict[str, Any] | None:
    """Handle one parsed JSON-RPC 2.0 frame in-process (returns None for notifications)."""
    method = msg.get("method")
    req_id = msg.get("id")
    if "id" not in msg:
        return None
    if not isinstance(method, str):
        return _jsonrpc_error(req_id, -32600, "Invalid Request: missing string method.")

    params = msg.get("params") or {}
    if not isinstance(params, dict):
        return _jsonrpc_error(req_id, -32602, "Invalid params: expected JSON object.")

    if method == "initialize":
        return _jsonrpc_result(
            req_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
                "instructions": SERVER_INSTRUCTIONS,
            },
        )

    if method == "ping":
        return _jsonrpc_result(req_id, {})

    if method == "tools/list":
        return _jsonrpc_result(req_id, {"tools": TOOL_DEFINITIONS})

    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(name, str) or not isinstance(arguments, dict):
            return _jsonrpc_error(req_id, -32602, "Invalid tools/call parameters.")

        if name == "read_note":
            raw_path = arguments.get("path")
            if not isinstance(raw_path, str):
                return _jsonrpc_error(req_id, -32602, "read_note requires string 'path'.")
            target = _resolve_target_path(workspace, raw_path)
            if not target.is_file():
                return _jsonrpc_result(
                    req_id,
                    {"content": [{"type": "text", "text": f"Not found: {raw_path}"}], "isError": True},
                )
            text = target.read_text(encoding="utf-8", errors="replace")
            return _jsonrpc_result(req_id, {"content": [{"type": "text", "text": text}], "isError": False})

        if name == "write_note":
            raw_path = arguments.get("path")
            content = arguments.get("content")
            if not isinstance(raw_path, str) or not isinstance(content, str):
                return _jsonrpc_error(req_id, -32602, "write_note requires string 'path' and 'content'.")
            target = _resolve_target_path(workspace, raw_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            return _jsonrpc_result(
                req_id,
                {"content": [{"type": "text", "text": f"Wrote {len(content)} chars to {raw_path}"}], "isError": False},
            )

        if name == "echo_status":
            message = arguments.get("message")
            if not isinstance(message, str):
                return _jsonrpc_error(req_id, -32602, "echo_status requires string 'message'.")
            return _jsonrpc_result(req_id, {"content": [{"type": "text", "text": message}], "isError": False})

        return _jsonrpc_error(req_id, -32601, f"Unknown tool: {name}")

    return _jsonrpc_error(req_id, -32601, f"Method not found: {method}")


def serve_stdio(workspace: Path) -> int:
    """Serve newline-delimited JSON-RPC 2.0 over stdin/stdout."""
    workspace.mkdir(parents=True, exist_ok=True)
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            reply = _jsonrpc_error(None, -32700, f"Parse error: {exc.msg}")
            sys.stdout.write(json.dumps(reply, separators=(",", ":"), ensure_ascii=False) + "\n")
            sys.stdout.flush()
            continue
        if not isinstance(msg, dict):
            reply = _jsonrpc_error(None, -32600, "Invalid Request: frame must be a JSON object.")
            sys.stdout.write(json.dumps(reply, separators=(",", ":"), ensure_ascii=False) + "\n")
            sys.stdout.flush()
            continue
        reply = handle_jsonrpc_message(msg, workspace)
        if reply is not None:
            sys.stdout.write(json.dumps(reply, separators=(",", ":"), ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mock MCP stdio server for Mellyn Airlock fuzzing.")
    parser.add_argument("--workspace", type=Path, required=True, help="Sandbox workspace directory.")
    args = parser.parse_args(argv)
    return serve_stdio(args.workspace.resolve())


if __name__ == "__main__":
    raise SystemExit(main())
