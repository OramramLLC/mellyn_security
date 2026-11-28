"""Regression tests for strict MCP control-method parameter schemas inside `mellyn.airlock`."""

from __future__ import annotations

import asyncio
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

HAS_PYDANTIC = importlib.util.find_spec("pydantic") is not None


class _MemClientWriter:
    def __init__(self) -> None:
        self.frames: list[dict[str, Any]] = []

    def write(self, data: bytes) -> None:
        for line in data.decode("utf-8").splitlines():
            if line.strip():
                self.frames.append(json.loads(line))

    async def drain(self) -> None:
        return None


class _FakeDownstreamStdin:
    def __init__(self) -> None:
        self.forwarded: list[dict[str, Any]] = []

    def write(self, data: bytes) -> None:
        for line in data.decode("utf-8").splitlines():
            if line.strip():
                self.forwarded.append(json.loads(line))

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        return None


class _FakeDownstreamProc:
    def __init__(self) -> None:
        self.stdin = _FakeDownstreamStdin()
        self.pid = 424242
        self.returncode: int | None = None

    def kill(self) -> None:
        self.returncode = -9

    async def wait(self) -> int:
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


async def _send_frames_through_proxy(frames: list[dict[str, Any]], audit_path: Path, canary: str) -> dict[str, Any]:
    """Feed client frames to an in-process `AirlockProxy` with a fake downstream; return what reached each side."""
    from mellyn.airlock.models import AirlockPolicy
    from mellyn.airlock.proxy import AirlockProxy
    from mellyn.core.audit import AuditLedger

    policy = AirlockPolicy(allowed_tools=["echo"], canary_tokens=[canary])
    ledger = AuditLedger(audit_path, canary_tokens=(canary,))
    writer = _MemClientWriter()
    proc = _FakeDownstreamProc()
    proxy = AirlockProxy(
        command=["python", "-c", "pass"],
        policy=policy,
        ledger=ledger,
        client_reader=asyncio.StreamReader(),
        client_writer=writer,  # type: ignore[arg-type]
        err_stream=io.StringIO(),
    )
    proxy._proc = proc  # type: ignore[assignment]
    for frame in frames:
        if proxy.aad_fired:
            break
        await proxy._handle_client_frame((json.dumps(frame) + "\n").encode("utf-8"))
    return {
        "client_frames": writer.frames,
        "forwarded": proc.stdin.forwarded,
        "aad_fired": proxy.aad_fired,
    }


# MCP 2025-11-25 added `icons`, `websiteUrl` and `description` to `Implementation` (clientInfo).
_CLIENT_INFO_2025_11_25: dict[str, Any] = {
    "name": "modern-client",
    "version": "3.1.0",
    "title": "Modern Client",
    "description": "A client speaking MCP 2025-11-25.",
    "websiteUrl": "https://client.example.com",
    "icons": [
        {"src": "https://client.example.com/icon.png", "mimeType": "image/png", "sizes": ["48x48"], "theme": "light"},
        {"src": "data:image/png;base64,iVBORw0KGgo=", "sizes": ["any"]},
    ],
}


def _initialize_with(client_info: object) -> dict[str, Any]:
    return {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": client_info}


def _client(**extra: object) -> dict[str, Any]:
    return {"name": "c", "version": "1", **extra}


@unittest.skipUnless(HAS_PYDANTIC, "Requires pydantic installed in active venv.")
class TestAirlockControlParamValidation(unittest.TestCase):
    """Ensure allowlisted MCP control frames enforce strict schemas without weakening canary AAD."""

    def test_validate_control_params_accepts_spec_compliant_frames(self) -> None:
        from mellyn.airlock.models import validate_control_params

        valid_cases: tuple[tuple[str, dict[str, Any]], ...] = (
            ("initialize", {}),
            ("initialize", {"protocolVersion": "2025-06-18"}),
            (
                "initialize",
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "clientInfo": {"name": "mellyn-client", "version": "1.0.0"},
                },
            ),
            (
                "initialize",
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "client", "version": "2.0", "title": "Eval"},
                    "_meta": {"trace": "ok"},
                },
            ),
            ("ping", {}),
            ("ping", {"_meta": {"n": 1}}),
            ("tools/list", {}),
            ("tools/list", {"cursor": "cursor-page-2"}),
            ("resources/list", {"cursor": "res-page-2"}),
            ("notifications/initialized", {}),
            ("notifications/cancelled", {"requestId": 7}),
            ("notifications/cancelled", {"requestId": "req-7", "reason": "user abort"}),
            # MCP 2025-11-25
            ("initialize", _initialize_with(_CLIENT_INFO_2025_11_25)),
            ("initialize", _initialize_with(_client(icons=[]))),
            ("initialize", _initialize_with(_client(icons=[{"src": "HTTP://x.example/i"}]))),
            ("notifications/cancelled", {}),
            ("notifications/cancelled", {"reason": "task cancelled elsewhere"}),
        )
        for method, params in valid_cases:
            with self.subTest(method=method, params=params):
                self.assertIsNone(validate_control_params(method, params))

    def test_validate_control_params_rejects_malformed_or_extra_fields(self) -> None:
        from mellyn.airlock.models import validate_control_params

        invalid_cases: tuple[tuple[str, dict[str, Any]], ...] = (
            ("initialize", {"protocolVersion": None}),
            ("initialize", {"capabilities": None}),
            ("initialize", {"clientInfo": None}),
            ("initialize", {"capabilities": "bad"}),
            ("initialize", {"clientInfo": {"name": "only-name"}}),
            (
                "initialize",
                {
                    "protocolVersion": "../bad-version",
                    "capabilities": {},
                    "clientInfo": {"name": "c", "version": "1"},
                },
            ),
            (
                "initialize",
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "c\nbad", "version": "1"},
                },
            ),
            (
                "initialize",
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "c", "version": "1"},
                    "smuggledExtra": "x",
                },
            ),
            ("ping", {"extraField": "smuggled"}),
            ("tools/list", {"cursor": ""}),
            ("tools/list", {"cursor": "ok\nbad"}),
            ("tools/list", {"unexpected": 123}),
            ("resources/list", {"unexpected": True}),
            ("notifications/initialized", {"bogus": "val"}),
            ("notifications/cancelled", {"requestId": None}),
            ("notifications/cancelled", {"requestId": True}),
            ("notifications/cancelled", {"requestId": ""}),
            ("notifications/cancelled", {"requestId": 1, "reason": "bad\x00null"}),
            # MCP 2025-11-25 clientInfo fields are validated, and fields outside the spec are still refused.
            ("initialize", _initialize_with({**_CLIENT_INFO_2025_11_25, "smuggled": "x"})),
            ("initialize", _initialize_with(_client(icons=[{"src": "javascript:alert(1)"}]))),
            ("initialize", _initialize_with(_client(icons=[{"src": "file:///etc/passwd"}]))),
            ("initialize", _initialize_with(_client(icons=[{"src": ""}]))),
            ("initialize", _initialize_with(_client(icons=[{"src": "https://x\nInjected: 1"}]))),
            ("initialize", _initialize_with(_client(icons=[{"mimeType": "image/png"}]))),
            ("initialize", _initialize_with(_client(icons=[{"src": "https://x", "x": 1}]))),
            ("initialize", _initialize_with(_client(icons=[{"src": "https://x", "theme": "blue"}]))),
            ("initialize", _initialize_with(_client(icons=[{"src": "https://x", "sizes": ["4\n4"]}]))),
            ("initialize", _initialize_with(_client(icons=[{"src": "https://x", "sizes": ["9" * 33]}]))),
            ("initialize", _initialize_with(_client(icons=[{"src": "https://x"}] * 33))),
            ("initialize", _initialize_with(_client(icons={"src": "https://x"}))),
            ("initialize", _initialize_with(_client(websiteUrl="https://x\r\nInjected: 1"))),
            ("initialize", _initialize_with(_client(websiteUrl=""))),
            ("initialize", _initialize_with(_client(description="bad\x1bcontrol"))),
            ("initialize", _initialize_with(_client(description="d" * 4097))),
        )
        for method, params in invalid_cases:
            with self.subTest(method=method, params=params):
                err = validate_control_params(method, params)
                self.assertIsNotNone(err)
                self.assertIn(method, err or "")

    def test_proxy_enforces_control_param_schemas_and_canary_aad_precedence(self) -> None:
        from mellyn.airlock.proxy import JSONRPC_INVALID_PARAMS
        from mellyn.ir_lab.verify_chain import verify_chain

        canary = "MELLYN_CTRL_TEST_" + "CANARY_9911"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger_block = root / "control_block_audit.jsonl"
            res_block = asyncio.run(
                _send_frames_through_proxy(
                    [
                        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"bad": True}},
                        {"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {"unexpected": 1}},
                        {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {"extra": "no"}},
                        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {"extra": 1}},
                        {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": False}},
                        {"jsonrpc": "2.0", "id": 4, "method": "ping", "params": {}},
                    ],
                    ledger_block,
                    canary,
                )
            )
            self.assertFalse(res_block["aad_fired"])
            self.assertEqual([f["id"] for f in res_block["forwarded"]], [4])
            self.assertEqual(len(res_block["client_frames"]), 3)
            for err_frame in res_block["client_frames"]:
                self.assertEqual(err_frame["error"]["code"], JSONRPC_INVALID_PARAMS)
                self.assertEqual(err_frame["error"]["data"]["rule_id"], "airlock.invalid_control_params")

            chain_block = verify_chain(ledger_block)
            self.assertTrue(chain_block.valid)
            raw_block = ledger_block.read_text(encoding="utf-8")
            self.assertIn("airlock.invalid_control_params", raw_block)

            ledger_aad = root / "control_canary_audit.jsonl"
            res_aad = asyncio.run(
                _send_frames_through_proxy(
                    [
                        {"jsonrpc": "2.0", "id": 10, "method": "ping", "params": {"unexpected": canary}},
                    ],
                    ledger_aad,
                    canary,
                )
            )
            self.assertTrue(res_aad["aad_fired"])
            self.assertEqual(res_aad["forwarded"], [])
            chain_aad = verify_chain(ledger_aad)
            self.assertTrue(chain_aad.valid)
            raw_aad = ledger_aad.read_text(encoding="utf-8")
            self.assertNotIn(canary, raw_aad)
            self.assertIn("egress.canary_exfiltration", raw_aad)

    def test_proxy_forwards_mcp_2025_11_25_handshake_and_task_cancellation(self) -> None:
        from mellyn.airlock.proxy import JSONRPC_INVALID_PARAMS

        canary = "MELLYN_CTRL_TEST_" + "CANARY_9912"
        modern_init = _initialize_with(_CLIENT_INFO_2025_11_25)
        smuggled_init = _initialize_with({**_CLIENT_INFO_2025_11_25, "smuggled": "x"})
        with tempfile.TemporaryDirectory() as tmp:
            res = asyncio.run(
                _send_frames_through_proxy(
                    [
                        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": modern_init},
                        {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"reason": "task"}},
                        {"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": smuggled_init},
                    ],
                    Path(tmp) / "modern_audit.jsonl",
                    canary,
                )
            )
        self.assertFalse(res["aad_fired"])
        forwarded = res["forwarded"]
        self.assertEqual([f.get("method") for f in forwarded], ["initialize", "notifications/cancelled"])
        self.assertEqual(forwarded[0]["params"]["clientInfo"], _CLIENT_INFO_2025_11_25)
        self.assertEqual(len(res["client_frames"]), 1)
        self.assertEqual(res["client_frames"][0]["id"], 2)
        self.assertEqual(res["client_frames"][0]["error"]["code"], JSONRPC_INVALID_PARAMS)


if __name__ == "__main__":
    unittest.main()
