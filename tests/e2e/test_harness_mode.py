"""E2E tests for harness `observe` mode, redacted payload custody, anti-oracle masking, resources, and cursors."""

from __future__ import annotations

import asyncio
import io
import json
import sys
import unittest
from typing import Any

from pydantic import ValidationError

from mellyn.airlock.engine import compute_tool_pin
from mellyn.airlock.models import AirlockPolicy, parse_airlock_policy_toml
from mellyn.airlock.proxy import (
    AAD_EXIT_CODE,
    JSONRPC_POLICY_VIOLATION,
    MAX_RECORDED_REDACTED_PAYLOAD_BYTES,
    AirlockProxy,
    _build_cli_parser,
)
from mellyn.core.audit import AuditLedger, verify_ledger
from mellyn.ir_lab.reconstruct import reconstruct_incident
from tests.e2e.test_full_killchain import CLI_MODULES, _run_cli
from tests.e2e.test_proxy_aad import (
    CANARY,
    HOSTILE_SERVER,
    PINNED_TOOLS,
    ProxyHarness,
    _pid_is_alive,
    _QueueClientWriter,
)

_RESOURCE_AND_PAGE_SERVER = """
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _send(payload: dict) -> None:
    line = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\\n"
    sys.stdout.buffer.write(line)
    sys.stdout.buffer.flush()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tools-json", required=True)
    parser.add_argument("--exec-log", type=Path, required=True)
    parser.add_argument("--canary", default="")
    args = parser.parse_args()
    tools = json.loads(args.tools_json)
    unpaginated_calls = 0

    while True:
        raw = sys.stdin.buffer.readline()
        if not raw:
            return 0
        text = raw.decode("utf-8", errors="replace").strip()
        if not text:
            continue
        msg = json.loads(text)
        method = msg.get("method")
        if not isinstance(method, str) or "id" not in msg:
            continue
        req_id = msg["id"]
        params = msg.get("params") or {}

        with args.exec_log.open("a", encoding="utf-8", newline="\\n") as fh:
            fh.write(json.dumps({"method": method, "params": params}) + "\\n")

        if method == "initialize":
            _send({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}, "resources": {}},
                    "serverInfo": {"name": "resource-page-server", "version": "1.0"},
                },
            })
        elif method == "tools/list":
            cursor = params.get("cursor")
            if cursor == "cycle-1-p2":
                _send({"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools[1:]}})
            elif cursor == "cycle-2-p2":
                _send({"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools[1:]}})
            else:
                unpaginated_calls += 1
                next_cur = "cycle-1-p2" if unpaginated_calls == 1 else "cycle-2-p2"
                _send({"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools[:1], "nextCursor": next_cur}})
        elif method == "resources/list":
            _send({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"resources": [{"uri": "notes.txt", "name": "notes"}]},
            })
        elif method == "resources/read":
            uri = str(params.get("uri", ""))
            body = f"leaked:{args.canary}" if "leak-canary" in uri else f"resource-content:{uri}"
            _send({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"contents": [{"uri": uri, "mimeType": "text/plain", "text": body}]},
            })
        else:
            _send({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method '{method}' not found."},
            })


if __name__ == "__main__":
    raise SystemExit(main())
"""


class TestHarnessModeAndProtocolControls(ProxyHarness):
    def _read_audit_rows(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def _read_exec_rows(self) -> list[dict[str, Any]]:
        if not self.exec_log.exists():
            return []
        return [json.loads(line) for line in self.exec_log.read_text(encoding="utf-8").splitlines() if line.strip()]

    def test_defaults_and_toml_downgrade_rejection(self) -> None:
        parser = _build_cli_parser()
        parsed = parser.parse_args(["--policy", "p.toml", "--audit-log", "a.jsonl", "--", "python", "-V"])
        self.assertEqual(parsed.mode, "enforce")
        self.assertFalse(parsed.record_redacted_payloads)
        self.assertFalse(parsed.opaque_policy_errors)

        for bad_line in (
            'mode = "observe"\n',
            "record_redacted_payloads = true\n",
            "opaque_policy_errors = true\n",
        ):
            with self.subTest(toml_line=bad_line.strip()), self.assertRaises(ValidationError):
                parse_airlock_policy_toml(bad_line)

    async def test_observe_mode_multi_turn_killchain_and_redacted_payload_telemetry(self) -> None:
        policy = AirlockPolicy(
            policy_id="observe-e2e-test",
            allow_observe_mode=True,  # observe mode now needs the policy's consent as well as the launch flag
            allowed_tools=["read_file", "get_env"],
            agbom_pins={tool.name: compute_tool_pin(tool) for tool in PINNED_TOOLS},
            max_payload_bytes=8192,
            workspace_roots=[str(self.workspace)],
            canary_tokens=[CANARY],
            tool_rules={
                "read_file": {"name": "read_file", "path_arg_names": ["path"], "allowed_arg_names": ["path", "note"]},
                "get_env": {"name": "get_env", "allowed_arg_names": []},
            },
        )
        ledger = AuditLedger(self.audit_path, canary_tokens=(CANARY,))
        client_reader = asyncio.StreamReader()
        client_writer = _QueueClientWriter()
        err_stream = io.StringIO()
        proxy = AirlockProxy(
            command=[
                sys.executable,
                str(HOSTILE_SERVER),
                "--mode",
                "rug_pull_char",
                "--exec-log",
                str(self.exec_log),
            ],
            policy=policy,
            ledger=ledger,
            client_reader=client_reader,
            client_writer=client_writer,
            err_stream=err_stream,
            mode="observe",
            record_redacted_payloads=True,
        )
        self.assertEqual(proxy.mode, "observe")
        task = asyncio.create_task(proxy.run())

        self._send(client_reader, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        init_resp = await self._recv(client_writer)
        self.assertIn("result", init_resp)
        downstream_pid = proxy.downstream_pid
        self.assertIsNotNone(downstream_pid)

        self._send(client_reader, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        list1 = await self._recv(client_writer)
        self.assertEqual(len(list1["result"]["tools"]), 2)

        # Turn 1: path traversal -> recorded as BLOCK, but forwarded in observe mode without killing downstream
        self._send(
            client_reader,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "../../etc/passwd"}},
            },
        )
        trav_resp = await self._recv(client_writer)
        self.assertEqual(trav_resp["result"]["content"][0]["text"], "ok:../../etc/passwd")
        if downstream_pid is not None:
            self.assertTrue(_pid_is_alive(downstream_pid))

        # Turn 2: hex-encoded outbound canary -> recorded as AAD_FIRE, forwarded without kill or -32099
        hex_canary = CANARY.encode("utf-8").hex()
        self._send(
            client_reader,
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "ok.txt", "note": hex_canary}},
            },
        )
        canary_resp = await self._recv(client_writer)
        self.assertEqual(canary_resp["result"]["content"][0]["text"], "ok:ok.txt")
        self.assertFalse(proxy.aad_fired)
        if downstream_pid is not None:
            self.assertTrue(_pid_is_alive(downstream_pid))

        # Turn 3: 2nd tools/list rug-pull -> recorded as AAD_FIRE, forwarded without kill
        self._send(client_reader, {"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {}})
        list2 = await self._recv(client_writer)
        self.assertTrue(list2["result"]["tools"][0]["description"].endswith("!"))

        # Turn 4: clean follow-up call still succeeds in the same session
        self._send(
            client_reader,
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "clean.txt"}},
            },
        )
        clean_resp = await self._recv(client_writer)
        self.assertEqual(clean_resp["result"]["content"][0]["text"], "ok:clean.txt")

        client_reader.feed_eof()
        exit_code = await asyncio.wait_for(task, timeout=5.0)
        self.assertEqual(exit_code, 0)
        self.assertFalse(proxy.aad_fired)

        self.assertTrue(verify_ledger(self.audit_path).valid)
        audit_text = self.audit_path.read_text(encoding="utf-8")
        self.assertNotIn(CANARY.casefold(), audit_text.casefold())
        self.assertNotIn(hex_canary, audit_text.casefold())

        rows = self._read_audit_rows()
        canary_events = [
            row["event"]
            for row in rows
            if row["event"]["rule_id"] == "egress.canary_exfiltration" and row["event"]["request_id"] == 4
        ]
        self.assertEqual(len(canary_events), 1)
        canary_meta = canary_events[0]["metadata"]
        self.assertEqual(canary_meta["enforcement_mode"], "observe")
        self.assertTrue(canary_meta["would_block"])
        self.assertTrue(canary_meta["would_terminate"])
        self.assertEqual(canary_meta["redacted_payload"], {"note": "[REDACTED_CANARY]", "path": "ok.txt"})

        # mellyn-ir --json reports OBSERVED_VIOLATIONS with accurate counts
        ir_proc = _run_cli(CLI_MODULES["mellyn-ir"], [str(self.audit_path), "--json"])
        self.assertEqual(ir_proc.returncode, 0, ir_proc.stderr)
        report_json = json.loads(ir_proc.stdout)
        self.assertTrue(report_json["chain_valid"])
        self.assertEqual(report_json["status"], "OBSERVED_VIOLATIONS")
        self.assertEqual(report_json["observed_aad_count"], 2)
        self.assertEqual(report_json["observed_block_count"], 1)
        self.assertEqual(report_json["unconfirmed_aad_triggers"], 0)
        self.assertIsNone(report_json["terminal_event"])

        report_obj = reconstruct_incident(self.audit_path)
        self.assertEqual(report_obj.status, "OBSERVED_VIOLATIONS")

    async def test_record_redacted_payloads_truncation_and_zero_custody_default(self) -> None:
        base_policy = self._build_policy(max_payload_bytes=32_768)
        rule = base_policy.tool_rules["read_file"].model_copy(update={"allowed_arg_names": ["path", "note"]})
        policy = base_policy.model_copy(update={"tool_rules": {**base_policy.tool_rules, "read_file": rule}})

        # Default: record_redacted_payloads=False -> zero payload stored
        proxy_default, reader1, writer1, _, _ = self._spawn_harness(mode="benign", policy=policy)
        t1 = asyncio.create_task(proxy_default.run())
        self._send(reader1, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        await self._recv(writer1)
        self._send(
            reader1,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "ok.txt", "note": "plain"}},
            },
        )
        await self._recv(writer1)
        reader1.feed_eof()
        self.assertEqual(await asyncio.wait_for(t1, timeout=5.0), 0)
        self.assertTrue(all("redacted_payload" not in r["event"]["metadata"] for r in self._read_audit_rows()))

        # Opt-in record_redacted_payloads=True with oversized (>16 KiB) payload -> truncation marker
        audit_trunc = self.root / "audit_trunc.jsonl"
        ledger2 = AuditLedger(audit_trunc, canary_tokens=(CANARY,))
        reader2 = asyncio.StreamReader()
        writer2 = _QueueClientWriter()
        proxy_trunc = AirlockProxy(
            command=[sys.executable, str(HOSTILE_SERVER), "--mode", "benign"],
            policy=policy,
            ledger=ledger2,
            client_reader=reader2,
            client_writer=writer2,
            err_stream=io.StringIO(),
            record_redacted_payloads=True,
        )
        t2 = asyncio.create_task(proxy_trunc.run())
        self._send(reader2, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        await self._recv(writer2)
        big_note = "n" * (MAX_RECORDED_REDACTED_PAYLOAD_BYTES + 256)
        self._send(
            reader2,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "ok.txt", "note": big_note}},
            },
        )
        await self._recv(writer2)
        reader2.feed_eof()
        self.assertEqual(await asyncio.wait_for(t2, timeout=5.0), 0)

        rows2 = [json.loads(line) for line in audit_trunc.read_text(encoding="utf-8").splitlines() if line.strip()]
        call_ev = [r["event"] for r in rows2 if r["event"]["rule_id"] == "airlock.tool_call_allowed"][0]
        self.assertEqual(call_ev["metadata"]["redacted_payload"], "[TRUNCATED_REDACTED_PAYLOAD]")
        self.assertGreater(call_ev["metadata"]["redacted_payload_bytes"], MAX_RECORDED_REDACTED_PAYLOAD_BYTES)

    async def test_opaque_policy_errors_masks_wire_details_but_keeps_audit_details(self) -> None:
        policy = self._build_policy()
        ledger = AuditLedger(self.audit_path, canary_tokens=(CANARY,))
        reader = asyncio.StreamReader()
        writer = _QueueClientWriter()
        proxy = AirlockProxy(
            command=[sys.executable, str(HOSTILE_SERVER), "--mode", "benign", "--exec-log", str(self.exec_log)],
            policy=policy,
            ledger=ledger,
            client_reader=reader,
            client_writer=writer,
            err_stream=io.StringIO(),
            opaque_policy_errors=True,
        )
        task = asyncio.create_task(proxy.run())
        self._send(reader, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        await self._recv(writer)

        self._send(
            reader,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "../../etc/passwd"}},
            },
        )
        err_resp = await self._recv(writer)
        self.assertEqual(err_resp["error"]["code"], JSONRPC_POLICY_VIOLATION)
        self.assertEqual(err_resp["error"]["message"], "Policy violation: request denied.")
        self.assertNotIn("data", err_resp["error"])
        self.assertNotIn("path_boundary_violation", json.dumps(err_resp))

        reader.feed_eof()
        self.assertEqual(await asyncio.wait_for(task, timeout=5.0), 0)

        block_rows = [
            r["event"]
            for r in self._read_audit_rows()
            if r["event"]["request_id"] == 2 and r["event"]["severity"] == "BLOCK"
        ]
        self.assertEqual(len(block_rows), 1)
        self.assertEqual(block_rows[0]["rule_id"], "airlock.path_boundary_violation")
        self.assertIn("Path rule failed", block_rows[0]["reason"])
        self.assertEqual(self._read_exec_rows(), [])

    async def test_resources_confinement_and_stale_cursor_reset(self) -> None:
        server_script = self.root / "resource_page_server.py"
        server_script.write_text(_RESOURCE_AND_PAGE_SERVER, encoding="utf-8")
        (self.workspace / "notes.txt").write_text("safe workspace resource\n", encoding="utf-8")
        (self.workspace / ".env").write_text("SECRET=1\n", encoding="utf-8")

        tools_json = json.dumps([t.wire_dict() for t in PINNED_TOOLS])

        # Part A: allow_resources_read=False (default) denies resources/list and resources/read
        pol_default = self._build_policy()
        self.assertFalse(pol_default.allow_resources_read)
        reader_a = asyncio.StreamReader()
        writer_a = _QueueClientWriter()
        proxy_a = AirlockProxy(
            command=[
                sys.executable,
                str(server_script),
                "--tools-json",
                tools_json,
                "--exec-log",
                str(self.exec_log),
            ],
            policy=pol_default,
            ledger=AuditLedger(self.root / "audit_a.jsonl", canary_tokens=(CANARY,)),
            client_reader=reader_a,
            client_writer=writer_a,
            err_stream=io.StringIO(),
        )
        task_a = asyncio.create_task(proxy_a.run())
        self._send(reader_a, {"jsonrpc": "2.0", "id": 1, "method": "resources/list", "params": {}})
        r_list_denied = await self._recv(writer_a)
        self.assertEqual(r_list_denied["error"]["code"], JSONRPC_POLICY_VIOLATION)
        self._send(
            reader_a,
            {"jsonrpc": "2.0", "id": 2, "method": "resources/read", "params": {"uri": "notes.txt"}},
        )
        r_read_denied = await self._recv(writer_a)
        self.assertEqual(r_read_denied["error"]["code"], JSONRPC_POLICY_VIOLATION)
        reader_a.feed_eof()
        self.assertEqual(await asyncio.wait_for(task_a, timeout=5.0), 0)
        self.assertEqual(self._read_exec_rows(), [])

        # Part B: allow_resources_read=True permits in-workspace reads, blocks /etc/passwd & .env, resets cursor
        pol_res = pol_default.model_copy(update={"allow_resources_read": True})
        exec_log_b = self.root / "exec_b.jsonl"
        audit_b = self.root / "audit_b.jsonl"
        reader_b = asyncio.StreamReader()
        writer_b = _QueueClientWriter()
        proxy_b = AirlockProxy(
            command=[
                sys.executable,
                str(server_script),
                "--tools-json",
                tools_json,
                "--exec-log",
                str(exec_log_b),
                "--canary",
                CANARY,
            ],
            policy=pol_res,
            ledger=AuditLedger(audit_b, canary_tokens=(CANARY,)),
            client_reader=reader_b,
            client_writer=writer_b,
            err_stream=io.StringIO(),
        )
        task_b = asyncio.create_task(proxy_b.run())

        self._send(reader_b, {"jsonrpc": "2.0", "id": 10, "method": "resources/list", "params": {}})
        res_list = await self._recv(writer_b)
        self.assertIn("resources", res_list["result"])

        allowed_uri = (self.workspace / "notes.txt").as_uri()
        self._send(
            reader_b,
            {"jsonrpc": "2.0", "id": 11, "method": "resources/read", "params": {"uri": allowed_uri}},
        )
        res_ok = await self._recv(writer_b)
        self.assertIn("resource-content:", res_ok["result"]["contents"][0]["text"])

        env_uri = (self.workspace / ".env").as_uri()
        for bad_id, bad_uri in (
            (12, "file:///etc/passwd"),
            (13, env_uri),
            (14, "https://example.com/secret"),
        ):
            self._send(
                reader_b,
                {"jsonrpc": "2.0", "id": bad_id, "method": "resources/read", "params": {"uri": bad_uri}},
            )
            bad_resp = await self._recv(writer_b)
            self.assertEqual(bad_resp["error"]["code"], JSONRPC_POLICY_VIOLATION)
            self.assertEqual(bad_resp["error"]["data"]["rule_id"], "airlock.path_boundary_violation")

        # Stale cursor reset check across two listing cycles:
        self._send(reader_b, {"jsonrpc": "2.0", "id": 20, "method": "tools/list", "params": {}})
        page1 = await self._recv(writer_b)
        self.assertEqual(page1["result"]["nextCursor"], "cycle-1-p2")

        # Start fresh unpaginated tools/list -> cycle 1 cursor must be invalidated
        self._send(reader_b, {"jsonrpc": "2.0", "id": 21, "method": "tools/list", "params": {}})
        page_new = await self._recv(writer_b)
        self.assertEqual(page_new["result"]["nextCursor"], "cycle-2-p2")

        # Replay stale cursor from cycle 1 -> blocked cleanly
        self._send(
            reader_b,
            {"jsonrpc": "2.0", "id": 22, "method": "tools/list", "params": {"cursor": "cycle-1-p2"}},
        )
        stale_resp = await self._recv(writer_b)
        self.assertEqual(stale_resp["error"]["code"], JSONRPC_POLICY_VIOLATION)
        self.assertIn("unknown tools/list cursor", stale_resp["error"]["message"])

        # Current cycle cursor still works
        self._send(
            reader_b,
            {"jsonrpc": "2.0", "id": 23, "method": "tools/list", "params": {"cursor": "cycle-2-p2"}},
        )
        page_c2_end = await self._recv(writer_b)
        self.assertEqual(page_c2_end["result"]["tools"][0]["name"], "get_env")

        # Inbound canary on resources/read -> fires AAD_FIRE
        canary_trigger_uri = (self.workspace / "leak-canary.txt").as_uri()
        self._send(
            reader_b,
            {"jsonrpc": "2.0", "id": 24, "method": "resources/read", "params": {"uri": canary_trigger_uri}},
        )
        aad_resp = await self._recv(writer_b)
        self.assertEqual(aad_resp["error"]["code"], -32099)
        self.assertEqual(await asyncio.wait_for(task_b, timeout=5.0), AAD_EXIT_CODE)
        self.assertTrue(verify_ledger(audit_b).valid)


if __name__ == "__main__":
    unittest.main()
