"""
Regression tests for the CLI-tools review. Each pins a problem reproduced against the first version: a client that
stops reading blocking the kill switch, the downstream outliving a killed proxy, mellyn-pin policies firing AAD on
paginated servers, forgeable mellyn-ir Markdown, verifying one read of the ledger but reporting on another,
mellyn-bench passing with missed secrets, and non-finite timeouts.
"""

from __future__ import annotations

import asyncio
import io
import math
import os
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from pydantic import ValidationError

from mcp_airlock.airlock.engine import evaluate_tool_call
from mcp_airlock.airlock.models import JsonRpcRequest, ToolCallParams, parse_airlock_policy_toml
from mcp_airlock.airlock.pin_cli import inspect_mcp_server
from mcp_airlock.airlock.proxy import AAD_EXIT_CODE, AirlockProxy
from mcp_airlock.core.audit import AuditLedger, verify_ledger, verify_ledger_bytes
from mcp_airlock.core.schemas import ZoneEvent
from mcp_airlock.egress import bench
from mcp_airlock.ir_lab.reconstruct import reconstruct_incident, render_markdown

from .test_proxy_aad import CANARY, HOSTILE_SERVER, REPO_ROOT, ProxyHarness, _pid_is_alive


def _cli_env() -> dict[str, str]:
    env = {"PYTHONPATH": str(REPO_ROOT / "src"), "PYTHONUTF8": "1"}
    for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATH", "TMPDIR", "LANG"):
        if key in os.environ:
            env[key] = os.environ[key]
    return env


class _StallingWriter:
    """Client writer that stops being read (its drain never completes) once `stalled` is set."""

    def __init__(self) -> None:
        self.lines: asyncio.Queue[bytes] = asyncio.Queue()
        self.stalled = False
        self._buf = bytearray()

    def write(self, data: bytes) -> None:
        self._buf.extend(data)
        while b"\n" in self._buf:
            nl = self._buf.index(b"\n")
            self.lines.put_nowait(bytes(self._buf[:nl]))
            del self._buf[: nl + 1]

    async def drain(self) -> None:
        if self.stalled:
            await asyncio.Event().wait()


def _wait_until_dead(pid: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_is_alive(pid):
            return True
        time.sleep(0.1)
    return not _pid_is_alive(pid)


class TestStalledClientCannotDelayContainment(ProxyHarness):
    def _proxy(self, mode: str) -> tuple[AirlockProxy, asyncio.StreamReader, _StallingWriter]:
        reader, writer = asyncio.StreamReader(), _StallingWriter()
        proxy = AirlockProxy(
            command=[sys.executable, str(HOSTILE_SERVER), "--mode", mode],
            policy=self._build_policy(),
            ledger=AuditLedger(self.audit_path),
            client_reader=reader,
            client_writer=writer,
            err_stream=io.StringIO(),
            client_write_timeout_seconds=0.5,
        )
        return proxy, reader, writer

    async def _list_then_stall(self, reader: asyncio.StreamReader, writer: _StallingWriter) -> None:
        reader.feed_data(b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}\n')
        await asyncio.wait_for(writer.lines.get(), timeout=5.0)
        writer.stalled = True

    async def test_kill_switch_kills_before_notifying_a_stalled_client(self) -> None:
        proxy, reader, writer = self._proxy("spoof_id")
        task = asyncio.create_task(proxy.run())
        await self._list_then_stall(reader, writer)
        reader.feed_data(
            b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"a"}}}\n'
        )
        self.assertEqual(await asyncio.wait_for(task, timeout=8.0), AAD_EXIT_CODE)
        self.assertFalse(_pid_is_alive(proxy.downstream_pid or 0))

    async def test_a_client_that_stops_reading_ends_the_session(self) -> None:
        proxy, reader, writer = self._proxy("benign")
        task = asyncio.create_task(proxy.run())
        await self._list_then_stall(reader, writer)
        reader.feed_data(b'{"jsonrpc":"2.0","id":2,"method":"ping","params":{}}\n')
        await asyncio.wait_for(task, timeout=8.0)
        self.assertFalse(_pid_is_alive(proxy.downstream_pid or 0))
        rules = [row["event"]["rule_id"] for row in self._read_audit_rows()]
        self.assertIn("airlock.client_write_stalled", rules)


class _SlowDeliveryWriter:
    """Client writer whose frames are only delivered once a slow (but finite) drain completes."""

    def __init__(self, delay: float) -> None:
        self.lines: asyncio.Queue[bytes] = asyncio.Queue()
        self._delay = delay
        self._buf = bytearray()

    def write(self, data: bytes) -> None:
        self._buf.extend(data)

    async def drain(self) -> None:
        await asyncio.sleep(self._delay)
        while b"\n" in self._buf:
            nl = self._buf.index(b"\n")
            self.lines.put_nowait(bytes(self._buf[:nl]))
            del self._buf[: nl + 1]


class TestKillSwitchNotificationIsNotCancelled(ProxyHarness):
    async def test_client_gets_its_aad_error_when_the_kill_makes_the_server_pump_hit_eof(self) -> None:
        # Regression (seen on CI's Python 3.12): AAD from the CLIENT pump kills the downstream first; the server pump
        # then hits EOF and used to set the stop event, so run() cancelled the client pump before the -32099 reached
        # the client. A slow drain makes that interleaving deterministic.
        reader, writer = asyncio.StreamReader(), _SlowDeliveryWriter(delay=0.5)
        proxy = AirlockProxy(
            command=[sys.executable, str(HOSTILE_SERVER), "--mode", "benign"],
            policy=self._build_policy(),
            ledger=AuditLedger(self.audit_path),
            client_reader=reader,
            client_writer=writer,
            err_stream=io.StringIO(),
        )
        task = asyncio.create_task(proxy.run())
        self._send(reader, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        await asyncio.wait_for(writer.lines.get(), timeout=5.0)
        self._send(
            reader,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "x", "note": CANARY}},
            },
        )
        self.assertEqual(await asyncio.wait_for(task, timeout=8.0), AAD_EXIT_CODE)
        aad_error = await asyncio.wait_for(writer.lines.get(), timeout=1.0)
        self.assertIn(b'"code":-32099', aad_error)
        self.assertFalse(_pid_is_alive(proxy.downstream_pid or 0))


class TestDownstreamCannotOutliveTheProxy(unittest.TestCase):
    def _start_cli(self, tmp: Path) -> tuple[subprocess.Popen[bytes], int]:
        policy = tmp / "p.toml"
        policy.write_text("", encoding="utf-8")
        pid_file = tmp / "server.pid"
        proc = subprocess.Popen(  # noqa: S603 - explicit argv, no shell
            [
                sys.executable,
                "-m",
                "mcp_airlock.airlock.proxy",
                "--policy",
                str(policy),
                "--audit-log",
                str(tmp / "audit.jsonl"),
                "--",
                sys.executable,
                str(HOSTILE_SERVER),
                "--mode",
                "orphan",
                "--pid-file",
                str(pid_file),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_cli_env(),
        )
        deadline = time.monotonic() + 15.0
        while not (pid_file.exists() and pid_file.read_text(encoding="utf-8").strip()):
            if time.monotonic() > deadline or proc.poll() is not None:
                proc.kill()
                self.fail("downstream server did not start")
            time.sleep(0.05)
        return proc, int(pid_file.read_text(encoding="utf-8"))

    @unittest.skipUnless(sys.platform == "win32" or sys.platform.startswith("linux"), "needs Job Objects or prctl")
    def test_killing_the_proxy_also_ends_the_downstream(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc, server_pid = self._start_cli(Path(tmp))
            try:
                proc.kill()  # SIGKILL / TerminateProcess: no handler runs in the proxy
                proc.communicate(timeout=10)
                self.assertTrue(_wait_until_dead(server_pid), "downstream outlived the killed proxy")
            finally:
                if _pid_is_alive(server_pid):
                    os.kill(server_pid, signal.SIGTERM)

    @unittest.skipIf(sys.platform == "win32", "POSIX signals")
    def test_sigterm_runs_the_normal_shutdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc, server_pid = self._start_cli(Path(tmp))
            try:
                proc.send_signal(signal.SIGTERM)
                proc.communicate(timeout=10)
                self.assertTrue(_wait_until_dead(server_pid), "downstream outlived a SIGTERMed proxy")
            finally:
                if _pid_is_alive(server_pid):
                    os.kill(server_pid, signal.SIGKILL)


class TestPinPaginatedServer(ProxyHarness):
    async def test_policy_from_a_paginated_server_works_in_the_proxy(self) -> None:
        inspection = await inspect_mcp_server([sys.executable, str(HOSTILE_SERVER), "--mode", "paginate"])
        self.assertTrue(inspection.paginated)
        from mcp_airlock.airlock.pin_cli import render_starter_policy_toml

        text = render_starter_policy_toml(inspection)
        self.assertNotIn("manifest_sha256", tomllib.loads(text))
        text = text.replace("allowed_tools = []", 'allowed_tools = ["read_file", "get_env"]')
        policy = parse_airlock_policy_toml(text)
        proxy, reader, writer, _, _ = self._spawn_harness(mode="paginate", policy=policy)
        task = asyncio.create_task(proxy.run())
        self._send(reader, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        page = await self._recv(writer)
        self.assertIn("result", page, page)
        reader.feed_eof()
        self.assertEqual(await asyncio.wait_for(task, timeout=5.0), 0)


def _event(idx: int, *, request_id: int | str | None = None, tool: str | None = None) -> ZoneEvent:
    return ZoneEvent(
        event_id=f"e{idx}",
        timestamp_utc="2026-11-23T00:00:00Z",
        zone="airlock",
        action="tools/call",
        verdict_allow=False,
        severity="AAD_FIRE",
        rule_id="egress.canary_exfiltration",
        reason="Reason with | pipe and [link](http://x) and <b>html</b>",
        artifact_sha256="0" * 64,
        request_id=request_id,
        tool_name=tool,
        metadata={"session_id": "s1"},
    )


class TestIncidentReportIntegrity(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "audit.jsonl"

    def test_ledger_text_cannot_forge_report_rows_or_markup(self) -> None:
        forged = "x |\n| 99 | 2026-01-01T00:00:00Z | airlock | tools/call | ALLOW | BENIGN | 1 | - |"
        AuditLedger(self.path).record(_event(0, request_id=forged, tool="t|`<i>"))
        markdown = render_markdown(reconstruct_incident(self.path))
        rows = [ln for ln in markdown.splitlines() if ln.startswith("| ") and not ln.startswith("| Seq")]
        rows = [ln for ln in rows if "---" not in ln]
        self.assertEqual(len(rows), 1, markdown)
        self.assertNotIn("<b>", markdown)
        self.assertNotIn("[link](", markdown)  # the escaped form \[link\]( cannot render as a link
        self.assertIn("NOT checked", markdown)  # no anchor supplied

    def test_proxy_side_rejects_control_characters_in_ids_and_tool_names(self) -> None:
        request = JsonRpcRequest(jsonrpc="2.0", id="a\nb", method="tools/call", params={"name": "t"})
        self.assertEqual(evaluate_tool_call(request, self._policy()).rule_id, "airlock.invalid_request_id")
        with self.assertRaises(ValidationError):
            ToolCallParams.model_validate({"name": "t\n| fake"})

    def _policy(self) -> Any:
        return parse_airlock_policy_toml('allowed_tools = ["t"]\n')

    def test_report_is_built_from_the_single_verified_read(self) -> None:
        ledger = AuditLedger(self.path)
        for idx in range(3):
            ledger.record(_event(idx, request_id=idx))
        self.assertEqual(verify_ledger_bytes(self.path.read_bytes()), verify_ledger(self.path))
        real_read_bytes = Path.read_bytes
        calls: list[Path] = []

        def counting_read_bytes(path: Path) -> bytes:
            calls.append(path)
            return real_read_bytes(path)

        with mock.patch.object(Path, "read_bytes", counting_read_bytes):
            report = reconstruct_incident(self.path)
        self.assertEqual(report.total_events, 3)
        self.assertEqual(len(calls), 1)


class TestBenchAndTimeouts(unittest.TestCase):
    def test_bench_fails_when_a_secret_is_missed(self) -> None:
        real_scan = bench.scan_payload

        def scan_missing_aws(payload: Any, **kwargs: Any) -> Any:
            if isinstance(payload, dict) and "aws" in payload:
                return real_scan("nothing to see here", **kwargs)
            return real_scan(payload, **kwargs)

        out = io.StringIO()
        with mock.patch.object(bench, "scan_payload", scan_missing_aws), mock.patch("sys.stdout", out):
            self.assertEqual(bench.main(["--iterations", "1"]), 1)
        self.assertIn("(FAIL)", out.getvalue())

    def test_timeouts_must_be_finite_and_positive(self) -> None:
        async def build(timeout: float) -> None:
            AirlockProxy(
                command=["x"],
                policy=parse_airlock_policy_toml(""),
                ledger=AuditLedger(Path(tempfile.mkdtemp()) / "a.jsonl"),
                client_reader=asyncio.StreamReader(),
                client_writer=_StallingWriter(),
                request_timeout_seconds=timeout,
            )

        for bad in (math.nan, math.inf, 0.0):
            with self.subTest(timeout=bad), self.assertRaises(ValueError):
                asyncio.run(build(bad))
            with self.subTest(pin_timeout=bad), self.assertRaises(ValueError):
                asyncio.run(inspect_mcp_server(["x"], timeout_seconds=bad))

        res = subprocess.run(  # noqa: S603 - explicit argv, no shell
            [
                sys.executable,
                "-m",
                "mcp_airlock.airlock.proxy",
                "--policy",
                "p",
                "--audit-log",
                "a",
                "--timeout",
                "nan",
                "--",
                "x",
            ],
            capture_output=True,
            text=True,
            env=_cli_env(),
            timeout=30,
        )
        self.assertEqual(res.returncode, 2, res.stderr)
        self.assertIn("--timeout", res.stderr)
