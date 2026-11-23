"""Real subprocess end-to-end tests for `mcp_airlock.airlock.proxy` and the AAD containment kill switch."""

from __future__ import annotations

import asyncio
import ctypes
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from mcp_airlock.airlock.engine import compute_tool_pin
from mcp_airlock.airlock.models import AirlockPolicy, ToolDefinition
from mcp_airlock.airlock.proxy import (
    AAD_EXIT_CODE,
    JSONRPC_AAD_CONTAINMENT_SEVERED,
    JSONRPC_POLICY_VIOLATION,
    JSONRPC_REQUEST_TIMEOUT,
    AirlockProxy,
)
from mcp_airlock.core.audit import AuditLedger, verify_ledger
from mcp_airlock.core.normalize import JsonObject

REPO_ROOT = Path(__file__).resolve().parents[2]
HOSTILE_SERVER = REPO_ROOT / "tests" / "fixtures" / "hostile_mcp_server.py"
CANARY = "CANARY_E2E_EXFIL_TRIPWIRE_8844"

PINNED_TOOLS = (
    ToolDefinition(
        name="read_file",
        description="Read a text file inside the workspace.",
        inputSchema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    ),
    ToolDefinition(
        name="get_env",
        description="Inspect process environment variables inside the MCP server.",
        inputSchema={"type": "object", "properties": {}},
    ),
)


def _pid_is_alive(pid: int) -> bool:
    """Cross-platform live-process check proving SIGKILL reaped the downstream child PID."""
    if sys.platform == "win32":
        kernel32 = ctypes.windll.kernel32
        process_query_limited = 0x1000
        still_active = 259
        handle = kernel32.OpenProcess(process_query_limited, False, pid)
        if not handle:
            return False
        try:
            exit_code = ctypes.c_ulong(0)
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return False
            return exit_code.value == still_active
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class _QueueClientWriter:
    """Real async byte-stream sink implementing `ClientWriter` for proxy E2E tests."""

    def __init__(self) -> None:
        self.raw_chunks: list[bytes] = []
        self._buf = bytearray()
        self.lines: asyncio.Queue[bytes] = asyncio.Queue()

    def write(self, data: bytes) -> None:
        self.raw_chunks.append(data)
        self._buf.extend(data)
        while b"\n" in self._buf:
            nl = self._buf.index(b"\n")
            line = bytes(self._buf[:nl])
            del self._buf[: nl + 1]
            self.lines.put_nowait(line)

    async def drain(self) -> None:
        await asyncio.sleep(0)

    def raw_bytes(self) -> bytes:
        return b"".join(self.raw_chunks)


class ProxyHarness(unittest.IsolatedAsyncioTestCase):
    """Shared setup and helpers for proxy E2E tests (no tests of its own, so importing it adds none)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.workspace = self.root / "ws"
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.audit_path = self.root / "audit.jsonl"
        self.exec_log = self.root / "exec.jsonl"

    def _build_policy(self, *, max_payload_bytes: int = 8192) -> AirlockPolicy:
        return AirlockPolicy(
            policy_id="e2e-airlock-test",
            allowed_tools=["read_file", "get_env"],
            agbom_pins={tool.name: compute_tool_pin(tool) for tool in PINNED_TOOLS},
            max_payload_bytes=max_payload_bytes,
            workspace_roots=[str(self.workspace)],
            canary_tokens=[CANARY],
            tool_rules={
                "read_file": {"name": "read_file", "path_arg_names": ["path"], "allowed_arg_names": ["path"]},
                "get_env": {"name": "get_env", "allowed_arg_names": []},
            },
        )

    def _spawn_harness(
        self,
        *,
        mode: str,
        policy: AirlockPolicy | None = None,
        request_timeout_seconds: float = 10.0,
        canary: str = "",
    ) -> tuple[AirlockProxy, asyncio.StreamReader, _QueueClientWriter, io.StringIO, AuditLedger]:
        pol = self._build_policy() if policy is None else policy
        ledger = AuditLedger(self.audit_path, canary_tokens=(CANARY,))
        client_reader = asyncio.StreamReader()
        client_writer = _QueueClientWriter()
        err_stream = io.StringIO()
        cmd = [
            sys.executable,
            str(HOSTILE_SERVER),
            "--mode",
            mode,
            "--exec-log",
            str(self.exec_log),
        ]
        if canary:
            cmd.extend(["--canary", canary])
        proxy = AirlockProxy(
            command=cmd,
            policy=pol,
            ledger=ledger,
            client_reader=client_reader,
            client_writer=client_writer,
            request_timeout_seconds=request_timeout_seconds,
            err_stream=err_stream,
        )
        return proxy, client_reader, client_writer, err_stream, ledger

    @staticmethod
    def _send(client_reader: asyncio.StreamReader, payload: JsonObject | bytes) -> None:
        raw = (
            payload
            if isinstance(payload, bytes)
            else (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
        )
        client_reader.feed_data(raw)

    @staticmethod
    async def _recv(client_writer: _QueueClientWriter, *, timeout: float = 5.0) -> dict[str, Any]:
        line = await asyncio.wait_for(client_writer.lines.get(), timeout=timeout)
        parsed = json.loads(line.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise AssertionError(f"Expected JSON object frame from proxy, got {type(parsed).__name__}")
        return parsed

    def _read_audit_rows(self) -> list[dict[str, Any]]:
        check = verify_ledger(self.audit_path)
        self.assertTrue(check.valid, check.reason)
        return [json.loads(line) for line in self.audit_path.read_text(encoding="utf-8").splitlines() if line]

    def _read_exec_rows(self) -> list[dict[str, Any]]:
        if not self.exec_log.exists():
            return []
        return [json.loads(line) for line in self.exec_log.read_text(encoding="utf-8").splitlines() if line]


class TestAirlockProxyEndToEnd(ProxyHarness):
    async def test_benign_pinned_session_succeeds_and_isolates_stderr(self) -> None:
        proxy, client_reader, client_writer, err_stream, _ = self._spawn_harness(mode="benign")
        proxy_task = asyncio.create_task(proxy.run())

        self._send(client_reader, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        init_resp = await self._recv(client_writer)
        self.assertEqual(init_resp["id"], 1)
        self.assertIn("result", init_resp)

        self._send(client_reader, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        self._send(client_reader, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        list_resp = await self._recv(client_writer)
        self.assertEqual([t["name"] for t in list_resp["result"]["tools"]], ["read_file", "get_env"])

        self._send(
            client_reader,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "notes/readme.md"}},
            },
        )
        call_resp = await self._recv(client_writer)
        self.assertEqual(call_resp["result"]["content"][0]["text"], "ok:notes/readme.md")

        client_reader.feed_eof()
        exit_code = await asyncio.wait_for(proxy_task, timeout=5.0)
        self.assertEqual(exit_code, 0)
        self.assertFalse(proxy.aad_fired)

        self.assertIn("hostile_mcp_server started mode=benign", err_stream.getvalue())
        self.assertNotIn(b"hostile_mcp_server started", client_writer.raw_bytes())

        rows = self._read_audit_rows()
        self.assertTrue(any(r["event"]["severity"] == "INFO" and r["event"]["action"] == "tools/call" for r in rows))
        self.assertEqual([r["tool"] for r in self._read_exec_rows()], ["read_file"])

    async def test_path_traversal_blocks_and_session_stays_alive(self) -> None:
        proxy, client_reader, client_writer, _, _ = self._spawn_harness(mode="benign")
        proxy_task = asyncio.create_task(proxy.run())

        self._send(client_reader, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        _ = await self._recv(client_writer)

        self._send(
            client_reader,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "../../etc/passwd"}},
            },
        )
        blocked = await self._recv(client_writer)
        self.assertEqual(blocked["id"], 2)
        self.assertEqual(blocked["error"]["code"], JSONRPC_POLICY_VIOLATION)
        self.assertEqual(self._read_exec_rows(), [])

        # Session must remain healthy for a valid subsequent call.
        self._send(
            client_reader,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "docs/ok.txt"}},
            },
        )
        allowed = await self._recv(client_writer)
        self.assertEqual(allowed["id"], 3)
        self.assertEqual(allowed["result"]["content"][0]["text"], "ok:docs/ok.txt")

        client_reader.feed_eof()
        self.assertEqual(await asyncio.wait_for(proxy_task, timeout=5.0), 0)
        self.assertEqual([r["arguments"]["path"] for r in self._read_exec_rows()], ["docs/ok.txt"])

        rows = self._read_audit_rows()
        self.assertTrue(any(r["event"]["severity"] == "BLOCK" and r["event"]["request_id"] == 2 for r in rows))
        self.assertTrue(any(r["event"]["severity"] == "INFO" and r["event"]["request_id"] == 3 for r in rows))

    async def test_mid_session_tools_list_rug_pull_triggers_aad_and_sigkill(self) -> None:
        for mode in ("rug_pull_char", "rug_pull_tag"):
            with self.subTest(mode=mode):
                if self.audit_path.exists():
                    self.audit_path.unlink()
                proxy, client_reader, client_writer, _, _ = self._spawn_harness(mode=mode)
                proxy_task = asyncio.create_task(proxy.run())

                self._send(client_reader, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
                first = await self._recv(client_writer)
                self.assertIn("result", first)

                pid = proxy.downstream_pid
                if pid is None:
                    self.fail("Expected live downstream PID after initial tools/list")
                self.assertTrue(_pid_is_alive(pid))

                # Second tools/list triggers downstream description mutation / Unicode Tag injection -> AAD_FIRE
                self._send(client_reader, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
                aad_frame = await self._recv(client_writer)
                self.assertEqual(aad_frame["id"], 2)
                self.assertEqual(aad_frame["error"]["code"], JSONRPC_AAD_CONTAINMENT_SEVERED)
                self.assertEqual(aad_frame["error"]["message"], "AAD_CONTAINMENT_SEVERED")

                exit_code = await asyncio.wait_for(proxy_task, timeout=5.0)
                self.assertEqual(exit_code, AAD_EXIT_CODE)
                self.assertTrue(proxy.aad_fired)
                self.assertIsNotNone(proxy.downstream_returncode)
                self.assertFalse(_pid_is_alive(pid))

                rows = self._read_audit_rows()
                self.assertTrue(any(r["event"]["severity"] == "AAD_FIRE" for r in rows))

    async def test_unsolicited_spoofed_rpc_id_triggers_aad_and_kills_child(self) -> None:
        proxy, client_reader, client_writer, _, _ = self._spawn_harness(mode="spoof_id")
        proxy_task = asyncio.create_task(proxy.run())

        self._send(client_reader, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        _ = await self._recv(client_writer)
        pid = proxy.downstream_pid
        if pid is None:
            self.fail("Expected live downstream PID")

        self._send(
            client_reader,
            {
                "jsonrpc": "2.0",
                "id": "real-call-2",
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "safe.txt"}},
            },
        )
        aad_frame = await self._recv(client_writer)
        self.assertEqual(aad_frame["id"], "real-call-2")
        self.assertEqual(aad_frame["error"]["code"], JSONRPC_AAD_CONTAINMENT_SEVERED)
        self.assertNotIn(b"spoofed-9999", client_writer.raw_bytes())

        self.assertEqual(await asyncio.wait_for(proxy_task, timeout=5.0), AAD_EXIT_CODE)
        self.assertFalse(_pid_is_alive(pid))
        rows = self._read_audit_rows()
        self.assertTrue(
            any(
                r["event"]["severity"] == "AAD_FIRE" and r["event"]["rule_id"] == "airlock.unsolicited_response_id"
                for r in rows
            )
        )

    async def test_outbound_and_inbound_canary_trigger_aad_with_redacted_audit(self) -> None:
        # 1. Outbound canary in tool-call arguments
        proxy_out, reader_out, writer_out, _, _ = self._spawn_harness(mode="benign")
        task_out = asyncio.create_task(proxy_out.run())

        self._send(reader_out, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        _ = await self._recv(writer_out)
        pid_out = proxy_out.downstream_pid
        if pid_out is None:
            self.fail("Expected live downstream PID")

        self._send(
            reader_out,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": f"notes/{CANARY}.txt"}},
            },
        )
        aad_out = await self._recv(writer_out)
        self.assertEqual(aad_out["id"], 2)
        self.assertEqual(aad_out["error"]["code"], JSONRPC_AAD_CONTAINMENT_SEVERED)
        self.assertEqual(await asyncio.wait_for(task_out, timeout=5.0), AAD_EXIT_CODE)
        self.assertFalse(_pid_is_alive(pid_out))
        self.assertEqual(self._read_exec_rows(), [])
        audit_text_out = self.audit_path.read_text(encoding="utf-8")
        self.assertNotIn(CANARY.casefold(), audit_text_out.casefold())
        self.assertTrue(verify_ledger(self.audit_path).valid)

        # 2. Inbound canary in downstream tool output
        self.audit_path.unlink()
        proxy_in, reader_in, writer_in, err_in, _ = self._spawn_harness(mode="canary_output", canary=CANARY)
        task_in = asyncio.create_task(proxy_in.run())

        self._send(reader_in, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        _ = await self._recv(writer_in)
        pid_in = proxy_in.downstream_pid
        if pid_in is None:
            self.fail("Expected live downstream PID")

        self._send(
            reader_in,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "notes/public.txt"}},
            },
        )
        aad_in = await self._recv(writer_in)
        self.assertEqual(aad_in["id"], 3)
        self.assertEqual(aad_in["error"]["code"], JSONRPC_AAD_CONTAINMENT_SEVERED)
        self.assertNotIn(CANARY.encode("utf-8"), writer_in.raw_bytes())
        self.assertNotIn(CANARY, err_in.getvalue())
        self.assertEqual(await asyncio.wait_for(task_in, timeout=5.0), AAD_EXIT_CODE)
        self.assertFalse(_pid_is_alive(pid_in))
        audit_text_in = self.audit_path.read_text(encoding="utf-8")
        self.assertNotIn(CANARY.casefold(), audit_text_in.casefold())
        rows_in = self._read_audit_rows()
        self.assertTrue(any(r["event"]["severity"] == "AAD_FIRE" for r in rows_in))

    async def test_ambient_host_secret_not_inherited_by_downstream_subprocess(self) -> None:
        sentinel = "test-secret"
        prior = os.environ.get("AWS_SECRET_ACCESS_KEY")
        os.environ["AWS_SECRET_ACCESS_KEY"] = sentinel

        def _restore() -> None:
            if prior is None:
                os.environ.pop("AWS_SECRET_ACCESS_KEY", None)
            else:
                os.environ["AWS_SECRET_ACCESS_KEY"] = prior

        self.addCleanup(_restore)

        proxy, client_reader, client_writer, _, _ = self._spawn_harness(mode="benign")
        proxy_task = asyncio.create_task(proxy.run())

        self._send(client_reader, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        _ = await self._recv(client_writer)

        self._send(
            client_reader,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "get_env", "arguments": {}}},
        )
        env_resp = await self._recv(client_writer)
        env_data = json.loads(env_resp["result"]["content"][0]["text"])
        self.assertFalse(env_data["has_aws_secret"])
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", env_data["env_keys"])
        self.assertIn("PATH", env_data["env_keys"])

        client_reader.feed_eof()
        self.assertEqual(await asyncio.wait_for(proxy_task, timeout=5.0), 0)

    async def test_bounded_framing_duplicate_id_timeout_and_garbage_stdout_isolation(self) -> None:
        # 1. Oversized single-line JSON bomb does not crash framing; session survives.
        small_policy = self._build_policy(max_payload_bytes=512)
        proxy, client_reader, client_writer, _, _ = self._spawn_harness(mode="garbage_stdout", policy=small_policy)
        proxy_task = asyncio.create_task(proxy.run())

        bomb = b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"' + (b"x" * 100_000) + b'"}}\n'
        self._send(client_reader, bomb)
        bomb_err = await self._recv(client_writer)
        self.assertIsNone(bomb_err["id"])
        self.assertEqual(bomb_err["error"]["code"], JSONRPC_POLICY_VIOLATION)

        # tools/call requires a verified tools/list in the session first.
        self._send(client_reader, {"jsonrpc": "2.0", "id": 10, "method": "tools/list", "params": {}})
        self.assertEqual((await self._recv(client_writer))["id"], 10)

        # Downstream garbage_stdout emits stray text before tools/call reply; must not reach client stdout.
        self._send(
            client_reader,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "ok.txt"}},
            },
        )
        call_resp = await self._recv(client_writer)
        self.assertEqual(call_resp["id"], 2)
        self.assertEqual(call_resp["result"]["content"][0]["text"], "ok:ok.txt")
        self.assertNotIn(b"DEBUG stray", client_writer.raw_bytes())

        client_reader.feed_eof()
        self.assertEqual(await asyncio.wait_for(proxy_task, timeout=5.0), 0)
        rows = self._read_audit_rows()
        self.assertTrue(any(r["event"]["rule_id"] == "airlock.server_malformed_frame" for r in rows))

        # 2. Duplicate active rpc_id rejected while hung call times out cleanly.
        self.audit_path.unlink()
        proxy_hang, reader_hang, writer_hang, _, _ = self._spawn_harness(mode="hang", request_timeout_seconds=0.3)
        task_hang = asyncio.create_task(proxy_hang.run())

        self._send(reader_hang, {"jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {}})
        self.assertEqual((await self._recv(writer_hang))["id"], "list-1")
        self._send(
            reader_hang,
            {
                "jsonrpc": "2.0",
                "id": "hung-1",
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "ok.txt"}},
            },
        )
        await asyncio.sleep(0.05)
        self._send(reader_hang, {"jsonrpc": "2.0", "id": "hung-1", "method": "ping", "params": {}})
        dup_err = await self._recv(writer_hang)
        self.assertEqual(dup_err["id"], "hung-1")
        self.assertEqual(dup_err["error"]["code"], JSONRPC_POLICY_VIOLATION)

        timeout_err = await self._recv(writer_hang, timeout=3.0)
        self.assertEqual(timeout_err["id"], "hung-1")
        self.assertEqual(timeout_err["error"]["code"], JSONRPC_REQUEST_TIMEOUT)

        reader_hang.feed_eof()
        self.assertEqual(await asyncio.wait_for(task_hang, timeout=5.0), 0)
        self.assertTrue(verify_ledger(self.audit_path).valid)


if __name__ == "__main__":
    unittest.main()
