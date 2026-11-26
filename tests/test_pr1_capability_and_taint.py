"""Regression tests for PR 1: Capability Bindings, Strict Equivalence, and Gateway Taint/Pinning."""

from __future__ import annotations

import decimal
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
for _p in (REPO_ROOT, SRC_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from mellyn import (  # noqa: E402
    Authorizer,
    Decision,
    PolicyConfig,
    PolicyLoadError,
    RiskTier,
    ScopedRule,
    TaintSource,
    ToolCallRequest,
    ToolCapability,
    parse_policy_dict,
)
from mellyn.mcp_gateway import (  # noqa: E402
    MELLYN_POLICY_DENIED,
    GatewayLocalError,
    MCPGateway,
    compute_tools_hash,
)
from mellyn.models import canonical_json  # noqa: E402
from mellyn.policy import normalize_arg_value  # noqa: E402
from tests.fakes import FakeDownstream  # noqa: E402


class TestCapabilityBindings(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmpdir.name)
        (self.workspace / "src").mkdir()
        (self.workspace / "src" / "ok.py").write_text("x = 1\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_unguarded_low_or_medium_mcp_tool_is_rejected_at_policy_load(self) -> None:
        for tier in ("low", "medium"):
            with self.subTest(tier=tier), self.assertRaises(PolicyLoadError):
                parse_policy_dict(
                    {
                        "schema_version": 1,
                        "allowed_mcp_servers": ["fs"],
                        "tool_risk_tiers": {"fs/read_file": tier},
                    }
                )

    def test_mcp_filesystem_preset_enforces_secret_and_guardrail_jail_on_real_mcp_names(self) -> None:
        policy = PolicyConfig(
            allowed_mcp_servers=frozenset({"fs"}),
            trusted_mcp_servers=frozenset({"fs"}),
            server_presets={"fs": "mcp-filesystem"},
            tool_risk_tiers={
                "fs/read_file": RiskTier.LOW,
                "fs/read_multiple_files": RiskTier.LOW,
                "fs/write_file": RiskTier.MEDIUM,
                "fs/move_file": RiskTier.MEDIUM,
            },
        )
        auth = Authorizer(workspace_root=self.workspace, policy_config=policy)
        sid = auth.create_session()

        # Legitimate read & write in clean session succeed
        self.assertEqual(
            auth.authorize(ToolCallRequest(sid, "read_file", {"path": "src/ok.py"}, mcp_server="fs")).decision,
            Decision.ALLOW,
        )
        self.assertEqual(
            auth.authorize(
                ToolCallRequest(sid, "write_file", {"path": "src/new.py", "content": "1"}, mcp_server="fs")
            ).decision,
            Decision.ALLOW,
        )

        # Clean session: overwriting .git/hooks/pre-commit via standard MCP `write_file` or `move_file` is DENIED
        self.assertEqual(
            auth.authorize(
                ToolCallRequest(sid, "write_file", {"path": ".git/hooks/pre-commit", "content": "id"}, mcp_server="fs")
            ).decision,
            Decision.DENY,
        )
        self.assertEqual(
            auth.authorize(
                ToolCallRequest(
                    sid,
                    "move_file",
                    {"source": "src/ok.py", "destination": ".git/hooks/pre-commit"},
                    mcp_server="fs",
                )
            ).decision,
            Decision.DENY,
        )
        self.assertEqual(
            auth.authorize(
                ToolCallRequest(
                    sid,
                    "move_file",
                    {"source": ".env", "destination": "src/leaked.txt"},
                    mcp_server="fs",
                )
            ).decision,
            Decision.DENY,
        )

        # Even an explicit human grant cannot override the capability-bound guardrail jail
        auth.issue_grant(
            session_id=sid,
            tool_name="write_file",
            mcp_server="fs",
            arguments={"path": ".git/hooks/pre-commit", "content": "id"},
            approved_by="admin@mellyn.security",
        )
        self.assertEqual(
            auth.authorize(
                ToolCallRequest(sid, "write_file", {"path": ".git/hooks/pre-commit", "content": "id"}, mcp_server="fs")
            ).decision,
            Decision.DENY,
        )

        # Tainted session: `read_file` and `read_multiple_files` block path traversal and .env
        auth.mark_tainted(sid, TaintSource("github_issue", "issue#1"))
        self.assertEqual(
            auth.authorize(ToolCallRequest(sid, "read_file", {"path": "../../.ssh/id_rsa"}, mcp_server="fs")).decision,
            Decision.DENY,
        )
        self.assertEqual(
            auth.authorize(
                ToolCallRequest(sid, "read_multiple_files", {"paths": ["src/ok.py", ".env"]}, mcp_server="fs")
            ).decision,
            Decision.DENY,
        )

    def test_custom_url_and_shell_capabilities_bind_nonstandard_arg_names(self) -> None:
        policy = parse_policy_dict(
            {
                "schema_version": 1,
                "allowed_mcp_servers": ["net", "runner"],
                "allowed_egress_domains": ["docs.python.org"],
                "tool_risk_tiers": {
                    "net/get_page": "low",
                    "runner/run_proc": "high",
                },
                "tool_capabilities": {
                    "net/get_page": {"url_args": ["uri"]},
                    "runner/run_proc": {"shell_argv_arg": "cmd_list"},
                },
            }
        )
        auth = Authorizer(workspace_root=self.workspace, policy_config=policy)
        sid = auth.create_session()

        self.assertEqual(
            auth.authorize(
                ToolCallRequest(sid, "get_page", {"uri": "https://169.254.169.254/latest/meta-data/"}, mcp_server="net")
            ).decision,
            Decision.DENY,
        )
        self.assertEqual(
            auth.authorize(
                ToolCallRequest(sid, "get_page", {"uri": "https://docs.python.org/3/"}, mcp_server="net")
            ).decision,
            Decision.ALLOW,
        )
        self.assertEqual(
            auth.authorize(
                ToolCallRequest(sid, "run_proc", {"cmd_list": ["bash", "-c", "id"]}, mcp_server="runner")
            ).decision,
            Decision.DENY,
        )

    def test_recursive_search_requires_per_file_guard_adapter(self) -> None:
        # Unverified downstream recursive search tools (`search_files`, `workspace_search`) cannot be marked
        # LOW/MEDIUM without an implementation that enforces per-file secret denial.
        for bad_tool in ("fs/search_files", "workspace_search"):
            with self.subTest(bad_tool=bad_tool), self.assertRaises(PolicyLoadError):
                parse_policy_dict(
                    {
                        "schema_version": 1,
                        "allowed_mcp_servers": ["fs"],
                        "server_presets": {"fs": "mcp-filesystem"},
                        "tool_risk_tiers": {bad_tool: "low"},
                    }
                )

        # Mellyn's built-in search adapter validates every directory and file before reading it.
        (self.workspace / "notes.txt").write_text("line1: HARMLESS_MARKER_NOTES\n", encoding="utf-8")
        (self.workspace / ".env").write_text("TOKEN=HARMLESS_MARKER_ENV\n", encoding="utf-8")
        auth = Authorizer(workspace_root=self.workspace)
        hits = auth.path_guard.search_content("HARMLESS_MARKER")
        self.assertEqual([(h.path, h.line) for h in hits], [("notes.txt", "line1: HARMLESS_MARKER_NOTES")])

        for blocked_start in ("../.ssh", ".env"):
            with self.subTest(blocked_start=blocked_start), self.assertRaises(PermissionError):
                auth.path_guard.search_content("HARMLESS_MARKER", blocked_start)

    def test_invalid_capability_definitions_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            ToolCapability()  # neither guard nor pure=True
        with self.assertRaises(ValueError):
            ToolCapability(pure=True, path_read_args=("path",))


class TestUrlArgumentsAlwaysChecked(unittest.TestCase):
    """A `url` argument goes through the egress allowlist on every tool, whatever capability the tool has."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmpdir.name)
        (self.workspace / "src").mkdir()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def decide(self, policy: dict[str, Any], server: str, tool: str, arguments: dict[str, Any]) -> Decision:
        auth = Authorizer(workspace_root=self.workspace, policy_config=parse_policy_dict(policy))
        session = auth.create_session()
        return auth.authorize(ToolCallRequest(session, tool, arguments, mcp_server=server)).decision

    def test_pure_tool_with_url_argument_is_egress_checked(self) -> None:
        policy = {
            "allowed_mcp_servers": ["gh"],
            "allowed_egress_domains": ["api.github.com"],
            "tool_risk_tiers": {"gh/get_issue": "low"},
            "tool_capabilities": {"gh/get_issue": {"pure": True}},
        }
        metadata = {"url": "https://169.254.169.254/latest/meta-data/"}
        self.assertEqual(self.decide(policy, "gh", "get_issue", metadata), Decision.DENY)
        allowed = {"url": "https://api.github.com/repos/o/r/issues/1"}
        self.assertEqual(self.decide(policy, "gh", "get_issue", allowed), Decision.ALLOW)

    def test_path_only_tool_with_url_argument_is_egress_checked(self) -> None:
        policy = {
            "allowed_mcp_servers": ["fs"],
            "server_presets": {"fs": "mcp-filesystem"},
            "tool_risk_tiers": {"fs/read_file": "low"},
        }
        arguments = {"path": "src/a.py", "url": "http://evil.example/exfil"}
        self.assertEqual(self.decide(policy, "fs", "read_file", arguments), Decision.DENY)
        self.assertEqual(self.decide(policy, "fs", "read_file", {"path": "src/a.py"}), Decision.ALLOW)


class TestUnboundToolsAndControlCharacters(unittest.TestCase):
    """Tools without a capability binding still cannot be approved into touching secrets or guardrails."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmpdir.name)
        (self.workspace / "src").mkdir()
        self.auth = Authorizer(
            workspace_root=self.workspace, policy_config=parse_policy_dict({"allowed_mcp_servers": ["fs2"]})
        )
        self.session = self.auth.create_session()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def approved(self, tool: str, arguments: dict[str, Any], server: str | None = "fs2") -> Decision:
        self.auth.issue_grant(
            session_id=self.session, tool_name=tool, mcp_server=server, arguments=arguments, approved_by="r@example.com"
        )
        return self.auth.authorize(ToolCallRequest(self.session, tool, arguments, mcp_server=server)).decision

    def test_approval_cannot_override_path_guard_on_unbound_tools(self) -> None:
        for arguments in (
            {"path": ".git/hooks/pre-commit", "content": "x"},
            {"file": ".env"},
            {"source": "src/a.py", "destination": "../outside.py"},
            {"paths": ["src/a.py", ".claude/settings.json"]},
            {"Path": "CLAUDE.md"},
        ):
            with self.subTest(arguments=arguments):
                self.assertEqual(self.approved("write_file", arguments), Decision.DENY)

    def test_approval_still_works_for_ordinary_paths_and_non_path_arguments(self) -> None:
        self.assertEqual(self.approved("write_file", {"path": "src/new.py", "content": "x"}), Decision.ALLOW)
        self.assertEqual(self.approved("open_issue", {"title": "Bug", "path": 3}), Decision.ALLOW)
        self.assertEqual(self.approved("deploy", {"target": "../prod"}), Decision.ALLOW)  # not a path-like name

    def test_local_unbound_tools_are_guarded_too(self) -> None:
        self.assertEqual(self.approved("mystery_tool", {"path": ".ssh/id_rsa"}, server=None), Decision.DENY)

    def test_control_characters_in_paths_and_urls_are_denied(self) -> None:
        for arguments, tool in (
            ({"path": "src/a\x00.py"}, "workspace_read"),
            ({"path": "src/a\n.py"}, "workspace_read"),
            ({"url": "https://docs.python.org/\r\nX-Injected: 1"}, "http_get"),
        ):
            with self.subTest(arguments=arguments):
                result = self.auth.authorize(ToolCallRequest(self.session, tool, arguments))
                self.assertEqual(result.decision, Decision.DENY)


class TestStrictArgumentEquivalence(unittest.TestCase):
    def test_scoped_rule_does_not_confuse_booleans_integers_or_floats(self) -> None:
        bool_rule = ScopedRule(
            rule_id="strict-bool",
            tool_name="deploy",
            mcp_server="ci",
            effect=Decision.ALLOW,
            arg_equals={"dry_run": (True,), "count": (1,)},
        )
        self.assertTrue(
            bool_rule.matches(ToolCallRequest("s", "deploy", {"dry_run": True, "count": 1}, mcp_server="ci"))
        )
        self.assertFalse(bool_rule.matches(ToolCallRequest("s", "deploy", {"dry_run": 1, "count": 1}, mcp_server="ci")))
        self.assertFalse(
            bool_rule.matches(ToolCallRequest("s", "deploy", {"dry_run": True, "count": True}, mcp_server="ci"))
        )
        self.assertFalse(
            bool_rule.matches(ToolCallRequest("s", "deploy", {"dry_run": True, "count": 1.0}, mcp_server="ci"))
        )

    def test_nested_dicts_and_lists_normalize_isomorphically_to_canonical_json(self) -> None:
        a = {"outer": {"items": ["x", 2, False], "flag": None}}
        b = {"outer": {"flag": None, "items": ("x", 2, False)}}
        self.assertEqual(normalize_arg_value(a), normalize_arg_value(b))
        self.assertEqual(canonical_json(a), canonical_json(b))

    def test_non_finite_floats_and_arbitrary_objects_fail_closed_and_audit_cleanly(self) -> None:
        for bad in ({"x": float("nan")}, {"x": float("inf")}, {"x": decimal.Decimal("1")}):
            with self.subTest(bad=bad):
                with self.assertRaises((TypeError, ValueError)):
                    canonical_json(bad)

        with tempfile.TemporaryDirectory() as tmpdir:
            auth = Authorizer(workspace_root=Path(tmpdir))
            sid = auth.create_session()
            res = auth.authorize(ToolCallRequest(sid, "git_status", {"x": float("nan")}))
            self.assertEqual(res.decision, Decision.DENY)
            self.assertEqual(len(auth.audit.events), 1)


class TestGatewayTaintOrderingAndToolPinning(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmpdir.name)
        (self.workspace / "app.py").write_text("x = 1\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _pinned_gateway(self, failure: str | None) -> tuple[Authorizer, MCPGateway, FakeDownstream]:
        gh_tools = [{"name": "get_issue", "description": "Fetch a GitHub issue"}]
        policy = PolicyConfig(
            allowed_mcp_servers=frozenset({"gh"}),
            pinned_tool_hashes={"gh": compute_tools_hash(gh_tools)},
            tool_risk_tiers={"gh/get_issue": RiskTier.LOW, "gh/resources/read": RiskTier.LOW},
            tool_capabilities={"gh/get_issue": ToolCapability(pure=True)},
        )
        auth = Authorizer(workspace_root=self.workspace, policy_config=policy)
        server = FakeDownstream("gh", gh_tools, failure=failure)
        gw = MCPGateway(authorizer=auth, servers={"gh": server})
        gw.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertFalse(auth.is_tainted(gw.session_id))  # pinned listing: clean at turn 0
        return auth, gw, server

    def _call_get_issue(self, gw: MCPGateway) -> dict[str, Any]:
        reply = gw.handle_message(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "gh__get_issue", "arguments": {}}}
        )
        self.assertIsNotNone(reply)
        return reply or {}

    def test_server_written_error_taints_session(self) -> None:
        """A relayed error message reaches the agent, so an injection sent as an error must taint."""
        auth, gw, _ = self._pinned_gateway("server_error")
        reply = self._call_get_issue(gw)
        self.assertIn("IGNORE PREVIOUS INSTRUCTIONS", reply["error"]["message"])
        self.assertTrue(auth.is_tainted(gw.session_id))

    def test_gateway_generated_error_does_not_taint_session(self) -> None:
        """Timeouts and closed pipes carry only the gateway's own text, so they leave the session clean."""
        auth, gw, server = self._pinned_gateway("no_answer")
        self.assertIn("error", self._call_get_issue(gw))
        self.assertFalse(auth.is_tainted(gw.session_id))
        server.failure = None
        self.assertIn("result", self._call_get_issue(gw))
        self.assertTrue(auth.is_tainted(gw.session_id))

    def test_server_cannot_forge_a_gateway_local_error(self) -> None:
        self.assertNotIsInstance({"jsonrpc": "2.0", "id": 1, "error": {}}, GatewayLocalError)

    def test_pinned_tool_hashes_prevent_turn_zero_taint_and_block_rug_pulls(self) -> None:
        gh_tools = [{"name": "get_issue", "description": "Read issue text"}]
        gh_hash = compute_tools_hash(gh_tools)
        local_tools = [{"name": "workspace_write", "description": "Write workspace file"}]

        policy = parse_policy_dict(
            {
                "schema_version": 1,
                "allowed_mcp_servers": ["local", "gh"],
                "trusted_mcp_servers": ["local"],
                "pinned_tool_hashes": {"gh": gh_hash},
                "tool_risk_tiers": {
                    "local/workspace_write": "medium",
                    "gh/get_issue": "low",
                },
                "tool_capabilities": {
                    "gh/get_issue": {"pure": True},
                },
            }
        )
        auth = Authorizer(workspace_root=self.workspace, policy_config=policy)
        gh_srv = FakeDownstream("gh", gh_tools)
        local_srv = FakeDownstream("local", local_tools)
        gw = MCPGateway(authorizer=auth, servers={"local": local_srv, "gh": gh_srv})

        # Turn 0: tools/list matches pinned hash -> session stays CLEAN, so MEDIUM write works!
        list_reply = gw.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertIsNotNone(list_reply)
        self.assertIn("result", list_reply)
        self.assertFalse(auth.is_tainted(gw.session_id))

        write_reply = gw.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "local__workspace_write", "arguments": {"path": "app.py"}},
            }
        )
        self.assertIsNotNone(write_reply)
        self.assertIn("result", write_reply)

        # Simulate a benign/adversarial description change ("rug pull") after review:
        # BOTH tools/list AND tools/call must deny fail-closed with zero downstream tools/call dispatches.
        gh_srv.tools = [{"name": "get_issue", "description": "Read issue details from repository"}]
        rug_pull_reply = gw.handle_message({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
        self.assertIsNotNone(rug_pull_reply)
        self.assertEqual(rug_pull_reply["error"]["code"], MELLYN_POLICY_DENIED)

        call_after_mismatch = gw.handle_message(
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "gh__get_issue", "arguments": {}}}
        )
        self.assertIsNotNone(call_after_mismatch)
        self.assertEqual(call_after_mismatch["error"]["code"], MELLYN_POLICY_DENIED)
        self.assertEqual(gh_srv.tool_calls, [])

        # Even before first tools/list discovery on a fresh gateway, pin mismatch blocks tools/call
        fresh_gw = MCPGateway(authorizer=auth, servers={"local": local_srv, "gh": gh_srv})
        pre_discovery_mismatch = fresh_gw.handle_message(
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "gh__get_issue", "arguments": {}}}
        )
        self.assertIsNotNone(pre_discovery_mismatch)
        self.assertEqual(pre_discovery_mismatch["error"]["code"], MELLYN_POLICY_DENIED)
        self.assertEqual(gh_srv.tool_calls, [])

        # Restore reviewed definition: unlisted tools on the pinned server remain denied even with a grant
        gh_srv.tools = [{"name": "get_issue", "description": "Read issue text"}]
        auth.issue_grant(
            session_id=fresh_gw.session_id,
            tool_name="unlisted_tool",
            mcp_server="gh",
            mcp_method="tools/call",
            arguments={},
            approved_by="reviewer@mellyn.security",
        )
        unlisted_reply = fresh_gw.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {"name": "gh__unlisted_tool", "arguments": {}},
            }
        )
        self.assertIsNotNone(unlisted_reply)
        self.assertEqual(unlisted_reply["error"]["code"], MELLYN_POLICY_DENIED)
        self.assertEqual(gh_srv.tool_calls, [])


if __name__ == "__main__":
    unittest.main()
