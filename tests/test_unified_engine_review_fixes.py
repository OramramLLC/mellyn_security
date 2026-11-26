"""Regression tests for review fixes to the merged gateway scanner, observe mode, and AAD containment."""

from __future__ import annotations

import base64
import importlib.util
import os
import secrets
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
for _import_dir in (REPO_ROOT, REPO_ROOT / "src"):
    if str(_import_dir) not in sys.path:
        sys.path.insert(0, str(_import_dir))

from mellyn.audit import AuditLogger  # noqa: E402
from mellyn.authorizer import Authorizer  # noqa: E402
from mellyn.mcp_gateway import (  # noqa: E402
    MELLYN_AAD_CONTAINED,
    MELLYN_POLICY_DENIED,
    MCPGateway,
    resolve_gateway_mode,
)
from mellyn.scanner import ScannerConfig, canary_present_in_text, scan_value  # noqa: E402
from mellyn.unified_config import load_policy_any, parse_unified_dict, render_unified_config  # noqa: E402
from tests.test_unified_engine import _FakeDownstream  # noqa: E402

HAS_PYDANTIC = importlib.util.find_spec("pydantic") is not None or os.environ.get("MELLYN_REQUIRE_API_TESTS") == "1"
FS_TOOLS = [{"name": n, "description": "fs", "inputSchema": {}} for n in ("read_file", "write_file")]


def _nest(value: Any, depth: int) -> Any:
    for _ in range(depth):
        value = [value]
    return value


class _GatewayCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self._tmpdir.name)
        (self.root / "notes.md").write_text("notes\n", encoding="utf-8")
        self.canary = "MELLYN-" + secrets.token_urlsafe(16)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def gateway(
        self,
        servers: dict[str, _FakeDownstream],
        *,
        mode: str = "enforce",
        protected: tuple[str, ...] = (),
    ) -> tuple[MCPGateway, AuditLogger]:
        # The filesystem preset gives `local-workspace` its read/write tiers; other servers default to HIGH.
        cfg = parse_unified_dict(
            tomllib.loads(render_unified_config(["mcp-filesystem"])),
            base_dir=self.root,
            config_path=self.root / "mellyn.toml",
        )
        import dataclasses

        names = list(servers)
        policy = dataclasses.replace(
            cfg.policy,
            allowed_mcp_servers=frozenset({*(cfg.policy.allowed_mcp_servers or ()), *names}),
            trusted_mcp_servers=frozenset({*cfg.policy.trusted_mcp_servers, *names}),
            server_presets={**cfg.policy.server_presets, **{n: "mcp-filesystem" for n in names}},
            protected_paths=(*cfg.policy.protected_paths, *protected),
        )
        audit = AuditLogger(canary_tokens=(self.canary,))
        authorizer = Authorizer(
            workspace_root=self.root, policy_config=policy, audit_logger=audit, session_ttl_seconds=None
        )
        gw = MCPGateway(
            authorizer=authorizer,
            servers=servers,
            scanner_config=ScannerConfig(canary_tokens=(self.canary,)),
            mode=mode,  # type: ignore[arg-type]
            allow_observe_mode=mode == "observe",
        )
        return gw, audit

    @staticmethod
    def call(gw: MCPGateway, rid: int, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        msg = {"jsonrpc": "2.0", "id": rid, "method": "tools/call", "params": {"name": tool, "arguments": args}}
        return gw.handle_message(msg) or {}

    @staticmethod
    def list_tools(gw: MCPGateway, rid: int = 0) -> dict[str, Any]:
        return gw.handle_message({"jsonrpc": "2.0", "id": rid, "method": "tools/list", "params": {}}) or {}


class TestObserveModeNeverRelaxesDeny(_GatewayCase):
    def test_denied_calls_stay_blocked_in_observe_mode(self) -> None:
        srv = _FakeDownstream("local-workspace", tools=FS_TOOLS)
        gw, audit = self.gateway({"local-workspace": srv}, mode="observe", protected=("mellyn.toml", "audit.jsonl"))
        self.list_tools(gw)
        # Before the fix, each of these was forwarded, so an observe session could rewrite the gateway's own config.
        for target in ("mellyn.toml", "audit.jsonl", ".env"):
            with self.subTest(target=target):
                before = len(srv.calls)
                reply = self.call(gw, 1, "local-workspace__write_file", {"path": target, "content": "attacker"})
                self.assertEqual(reply["error"]["code"], MELLYN_POLICY_DENIED)
                self.assertEqual(len(srv.calls), before)
        self.assertTrue(all(e.decision == "deny" for e in audit.events if e.event_type != "containment"))

    def test_approval_required_calls_run_in_observe_mode_and_are_logged(self) -> None:
        srv = _FakeDownstream("beta", tools=FS_TOOLS)  # not in the preset, so its tools default to HIGH
        gw, audit = self.gateway({"beta": srv}, mode="observe")
        self.list_tools(gw)
        reply = self.call(gw, 1, "beta__read_file", {"path": "notes.md"})
        self.assertIn("result", reply)
        observed = [e for e in audit.events if e.decision == "observed_require_approval"]
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0].policy_id, "gateway.observe")

    def test_observe_mode_needs_the_command_line_flag(self) -> None:
        # Config alone, even with observe permitted, runs in enforce.
        self.assertEqual(resolve_gateway_mode(None, config_mode="observe", allow_observe_mode=True), "enforce")
        self.assertEqual(resolve_gateway_mode("observe", config_mode="enforce", allow_observe_mode=True), "observe")
        with self.assertRaises(ValueError):
            resolve_gateway_mode("observe", config_mode="observe", allow_observe_mode=False)
        with self.assertRaises(ValueError):
            resolve_gateway_mode("relaxed", config_mode="enforce", allow_observe_mode=True)


class TestScannerDepth(_GatewayCase):
    def test_deep_nesting_is_scanned_and_blocked(self) -> None:
        cfg = ScannerConfig(canary_tokens=(self.canary,))
        # Before the fix, anything past 64 levels was skipped: the canary was never seen.
        deep_canary = scan_value({"a": _nest(self.canary, 70)}, cfg)
        self.assertTrue(deep_canary.canary_matched)
        deep_benign = scan_value({"a": _nest("hello", 70)}, cfg)
        self.assertFalse(deep_benign.clean)
        self.assertIn("nesting-too-deep", {f.rule_id for f in deep_benign.findings})
        self.assertTrue(scan_value({"a": _nest("hello", 10)}, cfg).clean)

    def test_deep_request_and_response_never_pass_the_gateway(self) -> None:
        srv = _FakeDownstream("local-workspace", tools=FS_TOOLS)
        gw, _ = self.gateway({"local-workspace": srv})
        self.list_tools(gw)
        reply = self.call(gw, 1, "local-workspace__read_file", {"path": "notes.md", "meta": _nest(self.canary, 70)})
        self.assertEqual(reply["error"]["code"], MELLYN_AAD_CONTAINED)
        self.assertNotIn("tools/call", [m for m, _ in srv.calls])

        leaky = _FakeDownstream("local-workspace", tools=FS_TOOLS, tool_result={"content": _nest(self.canary, 70)})
        gw2, _ = self.gateway({"local-workspace": leaky})
        self.list_tools(gw2)
        reply2 = self.call(gw2, 1, "local-workspace__read_file", {"path": "notes.md"})
        self.assertEqual(reply2["error"]["code"], MELLYN_AAD_CONTAINED)
        self.assertNotIn("result", reply2)


class TestAadSeversTheWholeSession(_GatewayCase):
    def test_canary_on_one_server_stops_every_server_and_every_later_call(self) -> None:
        first = _FakeDownstream("local-workspace", tools=FS_TOOLS)
        second = _FakeDownstream("beta", tools=FS_TOOLS)
        gw, _ = self.gateway({"local-workspace": first, "beta": second})
        self.list_tools(gw)
        reply = self.call(gw, 1, "local-workspace__read_file", {"path": "notes.md", "q": self.canary})
        self.assertEqual(reply["error"]["code"], MELLYN_AAD_CONTAINED)
        self.assertTrue(first.killed)
        self.assertTrue(second.killed)

        calls_before = len(second.calls)
        for method, params in (
            ("tools/call", {"name": "beta__read_file", "arguments": {"path": "notes.md"}}),
            ("tools/list", {}),
            ("resources/list", {}),
            ("resources/read", {"uri": "file:///x"}),
        ):
            with self.subTest(method=method):
                r = gw.handle_message({"jsonrpc": "2.0", "id": 5, "method": method, "params": params}) or {}
                self.assertEqual(r["error"]["code"], MELLYN_AAD_CONTAINED)
        self.assertEqual(len(second.calls), calls_before)


class TestListingsAreScanned(_GatewayCase):
    def test_canary_or_secret_in_a_tool_description_never_reaches_the_agent(self) -> None:
        poisoned = [{"name": "read_file", "description": f"helper {self.canary}", "inputSchema": {}}]
        srv = _FakeDownstream("local-workspace", tools=poisoned)
        gw, _ = self.gateway({"local-workspace": srv})
        reply = self.list_tools(gw)
        self.assertEqual(reply["error"]["code"], MELLYN_AAD_CONTAINED)
        self.assertTrue(srv.killed)

        token = "".join(["gh", "p_", "SynthTestValue0123456789abcd"])
        leaky = [{"name": "read_file", "description": f"use {token}", "inputSchema": {}}]
        gw2, _ = self.gateway({"local-workspace": _FakeDownstream("local-workspace", tools=leaky)})
        reply2 = self.list_tools(gw2)
        self.assertEqual(reply2["error"]["code"], MELLYN_POLICY_DENIED)
        self.assertNotIn(token, str(reply2))

    def test_clean_listing_is_unchanged(self) -> None:
        gw, _ = self.gateway({"local-workspace": _FakeDownstream("local-workspace", tools=FS_TOOLS)})
        names = {t["name"] for t in self.list_tools(gw)["result"]["tools"]}
        self.assertEqual(names, {"local-workspace__read_file", "local-workspace__write_file"})


class TestAuditReasonsCarryNoMatchFingerprint(_GatewayCase):
    def test_containment_reason_has_rule_ids_but_no_hash_of_the_match(self) -> None:
        import hashlib

        gw, audit = self.gateway({"local-workspace": _FakeDownstream("local-workspace", tools=FS_TOOLS)})
        self.list_tools(gw)
        self.call(gw, 1, "local-workspace__read_file", {"path": "notes.md", self.canary: "key-split"})
        reason = next(e for e in audit.events if e.event_type == "containment").reasons[0]
        digest = hashlib.sha256(self.canary.encode()).hexdigest()
        self.assertIn("canary:", reason)
        self.assertNotIn(digest[:12], reason)
        self.assertNotIn("sha256=", reason)
        self.assertNotIn(self.canary, reason)


class TestUnifiedConfigLoadsInTheAuthorizer(unittest.TestCase):
    def test_policy_loader_accepts_a_v2_mellyn_toml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mellyn.toml"
            path.write_text(render_unified_config(["github"]), encoding="utf-8")
            policy = load_policy_any(path)
            self.assertIn("github", policy.allowed_mcp_servers or ())

    @unittest.skipUnless(importlib.util.find_spec("fastapi") is not None, "fastapi is not installed")
    def test_authorizer_starts_on_the_config_init_unified_writes(self) -> None:
        from mellyn.api import create_app_from_env
        from mellyn.init_cmd import init_workspace, parse_dotenv

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            res = init_workspace(root / "site", presets=("github",), workspace_root=root, unified=True)
            env = parse_dotenv(res.env_path)
            if res.mellyn_config_path is None:
                self.fail("init_workspace(unified=True) should write mellyn.toml")
            env.update({"MELLYN_POLICY_PATH": str(res.mellyn_config_path), "MELLYN_WORKSPACE_ROOT": str(root)})
            # Before the fix this raised PolicyLoadError on the [runtime]/[scanner]/[servers] sections.
            with mock.patch.dict(os.environ, env, clear=True):
                self.assertIsNotNone(create_app_from_env())


@unittest.skipUnless(HAS_PYDANTIC, "comparing against mellyn.core.audit needs pydantic")
class TestScannerParityWithAirlock(unittest.TestCase):
    """The gateway scanner is a port of the Airlock's detection. Until they share one copy, keep them in step."""

    def test_both_scanners_agree_on_every_encoding_and_split(self) -> None:
        from mellyn.core.audit import canary_present, canary_present_in_json

        canary = "MELLYN-" + secrets.token_urlsafe(16)
        raw = canary.encode()
        third = len(canary) // 3
        pieces = [canary[:third], canary[third : 2 * third], canary[2 * third :]]
        texts = {
            "plain": canary,
            "x escapes": "".join(f"\\x{b:02x}" for b in raw),
            "u escapes": "".join(f"\\u{b:04x}" for b in raw),
            "decimal list": ", ".join(str(b) for b in raw),
            "double base64": base64.b64encode(base64.b64encode(raw)).decode(),
            "base64 of hex": base64.b64encode(raw.hex().encode()).decode(),
            "reversed": canary[::-1],
            "unrelated prose": "quarterly report: revenue grew in every region",
            "random base64": base64.b64encode(secrets.token_bytes(600)).decode(),
        }
        for label, text in texts.items():
            with self.subTest(text=label):
                self.assertEqual(canary_present_in_text(text, canary), canary_present(text, canary))
        payloads: dict[str, Any] = {
            "interleaved": {"p1": pieces[0], "n": "x", "p2": pieces[1], "m": 3, "p3": pieces[2]},
            "reordered": [pieces[2], pieces[0], pieces[1]],
            "padded": ["x" * 200_000, *pieces],
            "keys": {pieces[0]: 1, "k": 2, pieces[1]: 3, pieces[2]: 4},
            "clean": {"a": "hello", "b": ["world", 3]},
        }
        cfg = ScannerConfig(canary_tokens=(canary,))
        for label, payload in payloads.items():
            with self.subTest(payload=label):
                self.assertEqual(scan_value(payload, cfg).canary_matched, canary_present_in_json(payload, canary))


if __name__ == "__main__":
    unittest.main()
