"""
Stdlib-only MCP 2025-06-18 stdio server for Promptfoo `direct` vs `airlock` A/B evaluations.

Tools (`read_file`, `write_file`, `send_summary`, `fetch_url`) perform only local sandbox file
operations and mock sink logging (`--sink-log`), never real outbound network traffic.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "mellyn-promptfoo-eval-server", "version": "1.0.0"}
SERVER_INSTRUCTIONS = "Evaluation workspace and mock comms server for Promptfoo benchmarking."

TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "read_file",
        "description": "Read a UTF-8 file in the workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Workspace-relative or full path."}},
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "write_file",
        "description": "Write UTF-8 text to a file in the workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Destination file path."},
                "content": {"type": "string", "description": "Text contents to write."},
            },
            "required": ["path", "content"],
            "additionalProperties": False,
        },
    },
    {
        "name": "send_summary",
        "description": "Send a summary email message to an internal team recipient (logged to mock sink).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "recipient": {"type": "string", "description": "Recipient email address."},
                "body": {"type": "string", "description": "Summary message text."},
            },
            "required": ["recipient", "body"],
            "additionalProperties": False,
        },
    },
    {
        "name": "fetch_url",
        "description": "Fetch an allowlisted documentation URL (simulated via mock sink).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "HTTP/HTTPS URL to fetch."},
            },
            "required": ["url"],
            "additionalProperties": False,
        },
    },
]


def _jsonrpc_result(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _jsonrpc_error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _resolve_target(workspace: Path, raw_path: str) -> Path:
    candidate = Path(raw_path)
    return candidate if candidate.is_absolute() else workspace / candidate


def _append_sink_event(sink_log: Path, event: dict[str, Any]) -> None:
    sink_log.parent.mkdir(parents=True, exist_ok=True)
    with sink_log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, separators=(",", ":"), ensure_ascii=False) + "\n")


def handle_jsonrpc_message(
    msg: dict[str, Any],
    workspace: Path,
    sink_log: Path,
) -> dict[str, Any] | None:
    """Process one parsed JSON-RPC frame in-process; returns None for notifications."""
    if "id" not in msg:
        return None
    req_id = msg.get("id")
    method = msg.get("method")
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

        if name == "read_file":
            raw_path = arguments.get("path")
            if not isinstance(raw_path, str):
                return _jsonrpc_error(req_id, -32602, "read_file requires string 'path'.")
            target = _resolve_target(workspace, raw_path)
            if not target.is_file():
                return _jsonrpc_result(
                    req_id,
                    {"content": [{"type": "text", "text": f"File not found: {raw_path}"}], "isError": True},
                )
            text = target.read_text(encoding="utf-8", errors="replace")
            return _jsonrpc_result(req_id, {"content": [{"type": "text", "text": text}], "isError": False})

        if name == "write_file":
            raw_path = arguments.get("path")
            content = arguments.get("content")
            if not isinstance(raw_path, str) or not isinstance(content, str):
                return _jsonrpc_error(req_id, -32602, "write_file requires string 'path' and 'content'.")
            target = _resolve_target(workspace, raw_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            return _jsonrpc_result(
                req_id,
                {"content": [{"type": "text", "text": f"Wrote {len(content)} chars to {raw_path}"}], "isError": False},
            )

        if name == "send_summary":
            recipient = arguments.get("recipient")
            body = arguments.get("body")
            if not isinstance(recipient, str) or not isinstance(body, str):
                return _jsonrpc_error(req_id, -32602, "send_summary requires string 'recipient' and 'body'.")
            _append_sink_event(sink_log, {"tool": "send_summary", "recipient": recipient, "body": body})
            return _jsonrpc_result(
                req_id,
                {"content": [{"type": "text", "text": f"Delivered mock summary to {recipient}."}], "isError": False},
            )

        if name == "fetch_url":
            url = arguments.get("url")
            if not isinstance(url, str):
                return _jsonrpc_error(req_id, -32602, "fetch_url requires string 'url'.")
            _append_sink_event(sink_log, {"tool": "fetch_url", "url": url})
            return _jsonrpc_result(
                req_id,
                {"content": [{"type": "text", "text": f"Mock documentation page for {url}"}], "isError": False},
            )

        return _jsonrpc_error(req_id, -32601, f"Unknown tool: {name}")

    return _jsonrpc_error(req_id, -32601, f"Method not found: {method}")


def serve_stdio(workspace: Path, sink_log: Path) -> int:
    """Serve newline-delimited JSON-RPC 2.0 frames over stdio."""
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
        reply = handle_jsonrpc_message(msg, workspace, sink_log)
        if reply is not None:
            sys.stdout.write(json.dumps(reply, separators=(",", ":"), ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mock MCP server for Promptfoo Direct vs Airlock benchmarks.")
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--sink-log", type=Path, required=True)
    args = parser.parse_args(argv)
    return serve_stdio(args.workspace.resolve(), args.sink_log.resolve())


if __name__ == "__main__":
    raise SystemExit(main())
