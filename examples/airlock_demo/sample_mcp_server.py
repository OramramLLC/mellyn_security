"""
Harmless in-memory MCP demo server for the Mellyn 5-minute walkthrough.

Security properties:
  - Standard library only (`json`, `sys`); zero filesystem access, zero network calls, zero subprocesses.
  - Exposes two tools so a reviewed policy can demonstrate both allow and deny enforcement:
      1. `read_status_note` (safe read-only lookup over static in-memory notes)
      2. `export_diagnostics` (sensitive stub tool intentionally left disabled by policy)
  - Never prints diagnostics to `stdout` (reserved exclusively for newline-delimited JSON-RPC 2.0 frames).
"""

from __future__ import annotations

import json
import sys
from typing import Any

NOTES: dict[str, str] = {
    "release-readiness": (
        "Release readiness note: AgBOM verification enabled, egress canary scanning active, "
        "and fail-closed policy enforcement verified."
    ),
    "oncall-checklist": (
        "On-call checklist: verify audit.jsonl integrity with mellyn-ir before clearing containment alerts."
    ),
}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "read_status_note",
        "description": "Read a harmless in-memory operational status note by slug ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "note_id": {
                    "type": "string",
                    "description": "Note slug (release-readiness or oncall-checklist).",
                }
            },
            "required": ["note_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "export_diagnostics",
        "description": "Export full runtime diagnostics bundle to an external endpoint (administrative).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "destination": {
                    "type": "string",
                    "description": "Destination endpoint URI.",
                }
            },
            "required": ["destination"],
            "additionalProperties": False,
        },
    },
]


def _send_frame(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _handle_request(msg: dict[str, Any]) -> dict[str, Any] | None:
    if "id" not in msg:
        # JSON-RPC 2.0 notification (e.g. notifications/initialized): no reply.
        return None

    req_id = msg["id"]
    method = msg.get("method")
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mellyn-demo-notes", "version": "1.0.0"},
            },
        }

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}

    if method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        if tool_name == "read_status_note":
            note_id = arguments.get("note_id")
            if isinstance(note_id, str) and note_id in NOTES:
                result: dict[str, Any] = {"content": [{"type": "text", "text": NOTES[note_id]}]}
            else:
                result = {
                    "isError": True,
                    "content": [{"type": "text", "text": f"Unknown note_id: {note_id!r}"}],
                }
            return {"jsonrpc": "2.0", "id": req_id, "result": result}

        if tool_name == "export_diagnostics":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": "Stub diagnostics payload (this call should be blocked by reviewed_policy.toml).",
                        }
                    ]
                },
            }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32602, "message": f"Unknown demo tool: {tool_name!r}"},
        }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method!r}"},
    }


def main() -> int:
    for raw_line in sys.stdin:
        stripped = raw_line.strip()
        if not stripped:
            continue
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            _send_frame(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error"},
                }
            )
            continue
        if not isinstance(parsed, dict):
            _send_frame(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32600, "message": "Invalid Request"},
                }
            )
            continue
        response = _handle_request(parsed)
        if response is not None:
            _send_frame(response)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
