"""
Regression tests for PR 6 runtime controls:
  - M6: Bounded stdio framing, bounded downstream inbox, and write deadlines
  - M7: Bounded session taint history and standalone taint audit records
  - M8: Hashed untrusted caller audit identities and non-echoing denial reasons
  - KISS #3: Canonical JSON value unification
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
for p in (REPO_ROOT, SRC_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from mellyn import (  # noqa: E402
    AuditLogger,
    Authorizer,
    Decision,
    PolicyConfig,
    RiskTier,
    ScopedRule,
    TaintSource,
    ToolCallRequest,
)
from mellyn.mcp_gateway import (  # noqa: E402
    DOWNSTREAM_ERROR,
    JSONRPC_INVALID_REQUEST,
    MCPGateway,
    StdioDownstream,
    _BoundedInbox,
    iter_bounded_frames,
    run_stdio_proxy,
)
from mellyn.models import canonical_json, canonical_json_value  # noqa: E402
from tests.fakes import FakeDownstream  # noqa: E402


def _healthy_peer(name: str) -> FakeDownstream:
    return FakeDownstream(
        name,
        [{"name": "ping", "inputSchema": {"type": "object"}}],
        call_response={"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "pong"}]}},
    )


class TestBoundedFramingInboxAndWriteDeadline(unittest.TestCase):
    """M6: Oversized frames, flooded inboxes, and stalled child stdin pipes stay bounded and isolated."""

    def test_iter_bounded_frames_handles_multibyte_utf8_overflow_and_recovers(self) -> None:
        # 12 4-byte emoji = 48 UTF-8 bytes (> max_line_bytes=32), split across internal chunk boundaries,
        # followed immediately by a valid 27-byte JSON-RPC frame.
        oversized_line = ("🚀" * 12 + "\n").encode("utf-8")
        recovery_line = b'{"jsonrpc":"2.0","id":2}\n'
        self.assertGreater(len(oversized_line), 32)
        self.assertLessEqual(len(recovery_line), 32)

        stream = io.BytesIO(oversized_line + recovery_line)
        frames = list(iter_bounded_frames(stream, max_line_bytes=32))
        self.assertEqual(len(frames), 2)
        self.assertEqual(frames[0], (None, True))
        self.assertEqual(frames[1], (b'{"jsonrpc":"2.0","id":2}', False))

    def test_run_stdio_proxy_rejects_oversized_multibyte_frame_and_serves_recovery_frame(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy = PolicyConfig(allowed_mcp_servers=frozenset({"peer"}), trusted_mcp_servers=frozenset({"peer"}))
            gateway = MCPGateway(
                authorizer=Authorizer(workspace_root=Path(tmp), policy_config=policy),
                servers={"peer": _healthy_peer("peer")},
            )
            oversized = "🚀" * 16 + "\n"
            valid_ping = '{"jsonrpc":"2.0","id":7,"method":"ping"}\n'
            raw_bytes = io.BytesIO((oversized + valid_ping).encode("utf-8"))
            client_in = io.TextIOWrapper(raw_bytes, encoding="utf-8")
            client_out = io.StringIO()

            rc = run_stdio_proxy(gateway=gateway, client_in=client_in, client_out=client_out, max_line_bytes=48)
            self.assertEqual(rc, 0)

            replies = [json.loads(line) for line in client_out.getvalue().splitlines()]
            self.assertEqual(len(replies), 2)
            self.assertEqual(replies[0]["error"]["code"], JSONRPC_INVALID_REQUEST)
            self.assertEqual(replies[1], {"jsonrpc": "2.0", "id": 7, "result": {}})

    def test_bounded_inbox_caps_queued_messages_and_bytes(self) -> None:
        inbox = _BoundedInbox(max_messages=2, max_bytes=120)
        inbox.put({"id": 1}, 50)
        inbox.put({"id": 2}, 50)

        third_put_done = threading.Event()

        def _producer() -> None:
            inbox.put({"id": 3}, 50)
            third_put_done.set()

        t = threading.Thread(target=_producer, daemon=True)
        t.start()
        # Producer must block while 2 messages / 100+50 bytes exceed the cap.
        self.assertFalse(third_put_done.wait(timeout=0.05))
        self.assertLessEqual(inbox.qsize, 2)
        self.assertLessEqual(inbox.queued_bytes, 120)

        first = inbox.get(deadline=time.monotonic() + 1.0)
        self.assertEqual(first, {"id": 1})
        self.assertTrue(third_put_done.wait(timeout=1.0))
        self.assertLessEqual(inbox.qsize, 2)
        self.assertLessEqual(inbox.queued_bytes, 120)
        inbox.close()

    def test_stdio_downstream_with_max_inbox_messages_two_never_exceeds_bound(self) -> None:
        # Build a StdioDownstream backed by an in-memory pipe stream producing 5 unmatched replies + 1 matching reply.
        server = StdioDownstream.__new__(StdioDownstream)
        server.name = "bounded"
        server.on_notification = lambda _s, _m: None
        server._max_line_bytes = 256
        server._inbox = _BoundedInbox(max_messages=2, max_bytes=4096)
        server._write_lock = threading.Lock()
        server._custom_writer = lambda _payload: None
        server._writer_thread = None
        server._closed = False
        server.proc = mock.Mock()
        lines = [json.dumps({"jsonrpc": "2.0", "id": f"stale-{i}", "result": {}}) + "\n" for i in range(5)]
        lines.append(json.dumps({"jsonrpc": "2.0", "id": "mellyn-1", "result": {"ok": True}}) + "\n")
        server.proc.stdout = io.BytesIO("".join(lines).encode("utf-8"))
        import itertools

        server._ids = itertools.count(1)
        reader = threading.Thread(target=server._read_loop, daemon=True)
        server._reader = reader
        reader.start()

        time.sleep(0.05)
        self.assertLessEqual(len(server._inbox._items), 2)

        reply = server.request("ping", {}, timeout=2.0)
        self.assertEqual(reply["result"], {"ok": True})
        reader.join(timeout=1.0)
        server.close()

    def test_stalled_writer_times_out_aborts_child_and_leaves_peer_server_healthy(self) -> None:
        from mellyn import ToolCapability

        release_writer = threading.Event()
        self.addCleanup(release_writer.set)

        def _hanging_writer(_payload: bytes) -> None:
            release_writer.wait(timeout=5.0)

        stalled = StdioDownstream.__new__(StdioDownstream)
        stalled.name = "stalled"
        stalled.on_notification = lambda _s, _m: None
        stalled._max_line_bytes = 1024
        stalled._inbox = _BoundedInbox(max_messages=4, max_bytes=4096)
        stalled._write_lock = threading.Lock()
        stalled._custom_writer = _hanging_writer
        stalled._writer_thread = None
        stalled._closed = False
        stalled.proc = mock.Mock()
        stalled.proc.stdin = mock.Mock()
        import itertools

        stalled._ids = itertools.count(1)

        with tempfile.TemporaryDirectory() as tmp:
            policy = PolicyConfig(
                allowed_mcp_servers=frozenset({"stalled", "healthy"}),
                trusted_mcp_servers=frozenset({"healthy"}),
                tool_risk_tiers={"stalled/hang": RiskTier.LOW, "healthy/ping": RiskTier.LOW},
                tool_capabilities={
                    "stalled/hang": ToolCapability(pure=True),
                    "healthy/ping": ToolCapability(pure=True),
                },
            )
            authorizer = Authorizer(workspace_root=Path(tmp), policy_config=policy)

            # Verify direct request deadline enforcement first
            start = time.monotonic()
            direct_reply = stalled.request("tools/call", {"name": "hang", "arguments": {}}, timeout=0.12)
            elapsed = time.monotonic() - start
            self.assertLess(elapsed, 1.5)
            self.assertEqual(direct_reply["error"]["code"], DOWNSTREAM_ERROR)
            stalled.proc.terminate.assert_called_once()
            # stdin must NOT be closed underneath a live stuck writer thread (avoids stream lock deadlock)
            stalled.proc.stdin.close.assert_not_called()

            # Now verify gateway dispatch isolates the dead server from a healthy peer server
            gateway = MCPGateway(
                authorizer=authorizer,
                servers={"stalled": stalled, "healthy": _healthy_peer("healthy")},
            )
            gateway.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})

            stalled_call = gateway.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "stalled__hang", "arguments": {}},
                }
            )
            self.assertIsNotNone(stalled_call)
            if stalled_call is not None:
                self.assertEqual(stalled_call["error"]["code"], DOWNSTREAM_ERROR)
            # Local downstream errors must NOT taint the shared session
            self.assertFalse(authorizer.is_tainted(gateway.session_id))

            healthy_call = gateway.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "healthy__ping", "arguments": {}},
                }
            )
            self.assertIsNotNone(healthy_call)
            if healthy_call is not None:
                self.assertEqual(healthy_call["result"]["content"][0]["text"], "pong")


class TestBoundedTaintHistoryAndStandaloneAuditEvents(unittest.TestCase):
    """M7: Session taint state stays bounded while every taint origin is durably audited immediately."""

    def test_taint_sample_is_bounded_and_final_origin_persists_without_authorize_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sink = io.StringIO()
            authorizer = Authorizer(
                workspace_root=Path(tmp),
                audit_logger=AuditLogger(sink=sink),
                max_taint_sample=2,
            )
            sid = authorizer.create_session()
            authorizer.mark_tainted(sid, TaintSource(source_type="mcp_metadata", origin="untrusted-a/issue-1"))
            authorizer.mark_tainted(sid, TaintSource(source_type="mcp_metadata", origin="untrusted-b/issue-2"))
            authorizer.mark_tainted(sid, TaintSource(source_type="mcp_metadata", origin="untrusted-c/issue-3"))
            # Session ends immediately here without any subsequent authorize() call!

            self.assertTrue(authorizer.is_tainted(sid))
            self.assertEqual(authorizer.get_taint_count(sid), 3)
            self.assertEqual(
                [s.origin for s in authorizer.get_taint_sources(sid)],
                ["untrusted-b/issue-2", "untrusted-c/issue-3"],
            )

            records = [json.loads(line) for line in sink.getvalue().splitlines()]
            self.assertEqual(len(records), 3)
            self.assertTrue(all(r["event_type"] == "taint" and r["decision"] == "tainted" for r in records))
            self.assertEqual(records[-1]["taint_count"], 3)
            self.assertEqual(len(records[-1]["taint_sources"]), 2)
            self.assertIn("untrusted-c/issue-3", records[-1]["taint_sources"][-1])
            self.assertIn("untrusted-c/issue-3", records[-1]["reasons"][0])

            # Verify a subsequent authorization event also emits bounded taint_sources + full taint_count
            authorizer.authorize(
                ToolCallRequest(session_id=sid, tool_name="workspace_read", arguments={"path": "a.txt"})
            )
            all_records = [json.loads(line) for line in sink.getvalue().splitlines()]
            auth_event = all_records[-1]
            self.assertEqual(auth_event["event_type"], "authorization")
            self.assertEqual(auth_event["taint_count"], 3)
            self.assertEqual(len(auth_event["taint_sources"]), 2)


class TestHashedUntrustedAuditIdentities(unittest.TestCase):
    """M8: Arbitrary caller-supplied session/tool/server/URL/path strings never appear raw in audit logs."""

    def test_canary_identities_are_hashed_deterministically_and_never_echoed_in_reasons(self) -> None:
        canary_ses = "canary_ses_alpha"
        canary_tool = "canary_tool_beta"
        canary_srv = "canary_srv_gamma"
        canary_url = "https://canary-host-delta.invalid/secret-path-epsilon"
        canary_path = "../canary_traversal_zeta"

        with tempfile.TemporaryDirectory() as tmp:
            sink = io.StringIO()
            policy = PolicyConfig(
                allowed_mcp_servers=frozenset({"local-workspace"}),
                trusted_mcp_servers=frozenset({"local-workspace"}),
                allowed_egress_domains=frozenset({"docs.python.org"}),
                tool_risk_tiers={
                    "local-workspace/workspace_read": RiskTier.LOW,
                    "http_get": RiskTier.LOW,
                },
            )
            authorizer = Authorizer(
                workspace_root=Path(tmp),
                policy_config=policy,
                audit_logger=AuditLogger(sink=sink),
            )
            valid_sid = authorizer.create_session()

            # 1. Unknown session + unknown tool + unknown server (twice, for correlation check)
            for _ in range(2):
                res = authorizer.authorize(
                    ToolCallRequest(session_id=canary_ses, tool_name=canary_tool, arguments={}, mcp_server=canary_srv)
                )
                self.assertEqual(res.decision, Decision.DENY)

            # 2. Known session + unknown tool + unapproved server (twice)
            for _ in range(2):
                res = authorizer.authorize(
                    ToolCallRequest(session_id=valid_sid, tool_name=canary_tool, arguments={}, mcp_server=canary_srv)
                )
                self.assertEqual(res.decision, Decision.DENY)

            # 3. Known session + canary URL and canary traversal path
            authorizer.authorize(
                ToolCallRequest(session_id=valid_sid, tool_name="http_get", arguments={"url": canary_url})
            )
            authorizer.authorize(
                ToolCallRequest(
                    session_id=valid_sid,
                    tool_name="workspace_read",
                    arguments={"path": canary_path},
                    mcp_server="local-workspace",
                )
            )

            raw_audit = sink.getvalue()
            for canary in (
                canary_ses,
                canary_tool,
                canary_srv,
                "canary-host-delta",
                "secret-path-epsilon",
                "canary_traversal_zeta",
            ):
                with self.subTest(canary=canary):
                    self.assertNotIn(canary, raw_audit)

            events = [json.loads(line) for line in raw_audit.splitlines()]
            # Repeated calls with the same unknown identifiers correlate via identical digests
            self.assertTrue(events[0]["session_id"].startswith("unknown_ses:"))
            self.assertEqual(events[0]["session_id"], events[1]["session_id"])
            self.assertTrue(events[0]["tool_name"].startswith("untrusted_tool:"))
            self.assertEqual(events[0]["tool_name"], events[2]["tool_name"])
            self.assertTrue(events[0]["mcp_server"].startswith("untrusted_srv:"))
            self.assertEqual(events[0]["mcp_server"], events[2]["mcp_server"])

            # Known server-issued sessions and configured tools/servers remain readable in cleartext
            self.assertEqual(events[2]["session_id"], valid_sid)
            self.assertEqual(events[-1]["tool_name"], "workspace_read")
            self.assertEqual(events[-1]["mcp_server"], "local-workspace")


class TestCanonicalJsonAndFloodDeadline(unittest.TestCase):
    """KISS #3 and end-to-end notification flood deadline enforcement."""

    def test_canonical_json_normalizes_negative_zero_and_preserves_strict_types(self) -> None:
        self.assertEqual(canonical_json({"x": -0.0}), '{"x":0.0}')
        self.assertEqual(canonical_json({"x": -0.0}), canonical_json({"x": 0.0}))
        self.assertEqual(canonical_json_value((-0.0, [True, 1])), "[0.0,[true,1]]")

        rule = ScopedRule(
            rule_id="float-zero-rule",
            tool_name="calc",
            mcp_server="local-workspace",
            effect=Decision.ALLOW,
            arg_equals={"x": (0.0,), "flag": (True,)},
        )
        req = lambda args: ToolCallRequest("ses_1", "calc", args, mcp_server="local-workspace")  # noqa: E731
        self.assertTrue(rule.matches(req({"x": -0.0, "flag": True})))
        self.assertFalse(rule.matches(req({"x": 0, "flag": True})))
        self.assertFalse(rule.matches(req({"x": False, "flag": True})))
        self.assertFalse(rule.matches(req({"x": 0.0, "flag": 1})))

        for non_finite in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=non_finite), self.assertRaises(ValueError):
                canonical_json_value(non_finite)

    def test_notification_flood_cannot_hold_a_request_past_its_deadline(self) -> None:
        flooding_server = """
import json, sys
sys.stdin.readline()  # wait for the gateway's request, then never answer it: flood notifications instead
line = json.dumps({"jsonrpc": "2.0", "method": "notifications/progress", "params": {}}) + "\\n"
while True:
    sys.stdout.write(line)
    sys.stdout.flush()
"""
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "flood.py"
            script.write_text(flooding_server, encoding="utf-8")
            server = StdioDownstream(
                "flood",
                [sys.executable, "-I", str(script)],
                on_notification=lambda _server, _msg: time.sleep(0.001),
            )
            result: dict[str, Any] = {}
            worker = threading.Thread(
                target=lambda: result.update(reply=server.request("tools/list", {}, timeout=0.5)), daemon=True
            )
            started = time.monotonic()
            try:
                worker.start()
                worker.join(timeout=15)
                self.assertFalse(worker.is_alive(), "request() was still running 15s after a 0.5s deadline")
                self.assertLess(time.monotonic() - started, 10)
                self.assertIn("timed out", result["reply"]["error"]["message"])
            finally:
                server.proc.kill()
                server.proc.wait(timeout=10)
                server.close()


if __name__ == "__main__":
    unittest.main()
