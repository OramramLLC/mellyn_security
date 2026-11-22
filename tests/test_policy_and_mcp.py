"""Unit tests for the fail-closed policy loader, gateway config, approval channel and MCP JSON-RPC gateway."""

from __future__ import annotations

import io
import json
import os
import secrets
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"
FAKE_SERVER = Path(__file__).resolve().parent / "fixtures" / "fake_mcp_server.py"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from mellyn import (  # noqa: E402
    Authorizer,
    CredentialConfig,
    Decision,
    PolicyLoadError,
    RiskTier,
    Role,
    ToolCallRequest,
    load_policy_file,
    parse_policy_dict,
)
from mellyn.approvals import ApprovalHTTPServer, PendingApprovals  # noqa: E402
from mellyn.approve import validate_approval_url  # noqa: E402
from mellyn.audit import AuditLogger  # noqa: E402
from mellyn.credentials import key_digest  # noqa: E402
from mellyn.gateway_config import load_gateway_config  # noqa: E402
from mellyn.mcp_gateway import (  # noqa: E402
    JSONRPC_INVALID_PARAMS,
    JSONRPC_METHOD_NOT_FOUND,
    JSONRPC_PARSE_ERROR,
    MELLYN_APPROVAL_REQUIRED,
    MELLYN_POLICY_DENIED,
    MCPGateway,
    StdioDownstream,
    initialize_downstream,
    run_stdio_proxy,
)

EXAMPLE_POLICY = REPO_ROOT / "config" / "mellyn-policy.example.toml"


class TestPolicyLoader(unittest.TestCase):
    def test_example_toml_policy_loads_cleanly(self) -> None:
        config = load_policy_file(EXAMPLE_POLICY)
        self.assertEqual(config.allowed_mcp_servers, frozenset({"local-workspace", "github-readonly"}))
        self.assertEqual(config.trusted_mcp_servers, frozenset({"local-workspace"}))
        self.assertIn("docs.python.org", config.allowed_egress_domains)
        self.assertEqual(config.protected_paths, ())  # generic example: no repository-specific paths
        self.assertEqual(config.tool_risk_tiers["local-workspace/workspace_read"], RiskTier.LOW)
        self.assertEqual(len(config.scoped_rules), 2)
        self.assertEqual(config.scoped_rules[0].rule_id, "allow-unit-tests-when-tainted")
        self.assertEqual(config.scoped_rules[0].mcp_server, "local-workspace")
        self.assertEqual(config.scoped_rules[1].effect, Decision.DENY)

    def test_json_policy_loads_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "allowed_mcp_servers": ["local-workspace"],
                        "allowed_egress_domains": ["api.github.com"],
                        "injection_escalate_threshold": 0.65,
                        "injection_deny_threshold": 0.85,
                    }
                ),
                encoding="utf-8",
            )
            config = load_policy_file(path)
            self.assertEqual(config.allowed_mcp_servers, frozenset({"local-workspace"}))
            self.assertEqual(config.injection_escalate_threshold, 0.65)
            self.assertEqual(config.injection_deny_threshold, 0.85)

    def test_unknown_keys_and_typos_fail_closed(self) -> None:
        with self.assertRaises(PolicyLoadError):
            parse_policy_dict({"allow_egress_domain": ["docs.python.org"]})
        with self.assertRaises(PolicyLoadError):
            parse_policy_dict(
                {
                    "scoped_rules": [
                        {
                            "rule_id": "bad-prefix-key",
                            "tool_name": "shell_exec",
                            "effect": "allow",
                            "arg_prefixes": {"command": ["pytest"]},
                        }
                    ]
                }
            )

    def test_duplicate_rule_ids_and_invalid_thresholds_fail_closed(self) -> None:
        with self.assertRaises(PolicyLoadError):
            parse_policy_dict(
                {
                    "scoped_rules": [
                        {"rule_id": "dup", "tool_name": "shell_exec", "effect": "deny", "programs": ["rm"]},
                        {"rule_id": "dup", "tool_name": "shell_exec", "effect": "deny", "programs": ["curl"]},
                    ]
                }
            )
        for bad in (
            {"injection_escalate_threshold": 0.95, "injection_deny_threshold": 0.70},
            {"injection_deny_threshold": 1.5},
            {"schema_version": 2},
        ):
            with self.subTest(bad=bad), self.assertRaises(PolicyLoadError):
                parse_policy_dict(bad)

    def test_allow_rule_keyed_on_program_name_fails_closed(self) -> None:
        with self.assertRaises(PolicyLoadError):
            parse_policy_dict(
                {
                    "scoped_rules": [
                        {"rule_id": "git", "tool_name": "shell_exec", "effect": "allow", "programs": ["git"]}
                    ]
                }
            )

    def test_rule_mcp_server_must_be_a_non_empty_string(self) -> None:
        for bad in ("", 3):
            with self.subTest(bad=bad), self.assertRaises(PolicyLoadError):
                parse_policy_dict(
                    {"scoped_rules": [{"rule_id": "r", "tool_name": "t", "effect": "deny", "mcp_server": bad}]}
                )

    def test_missing_or_unsupported_extension_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            bad_ext = Path(tmpdir) / "policy.yaml"
            bad_ext.write_text("schema_version: 1\n", encoding="utf-8")
            with self.assertRaises(PolicyLoadError):
                load_policy_file(bad_ext)
            with self.assertRaises(PolicyLoadError):
                load_policy_file(Path(tmpdir) / "nonexistent.toml")


class TestGatewayConfig(unittest.TestCase):
    def write(self, text: str) -> Path:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        path = Path(self._tmp.name) / "gateway.toml"
        path.write_text(text, encoding="utf-8")
        return path

    def test_example_gateway_config_loads(self) -> None:
        config = load_gateway_config(REPO_ROOT / "config" / "mellyn-gateway.example.toml")
        self.assertEqual([s.name for s in config.servers], ["local-workspace", "github-readonly"])
        self.assertEqual(config.policy_path, EXAMPLE_POLICY.resolve())

    def test_invalid_gateway_configs_fail_closed(self) -> None:
        server = '[[servers]]\nname = "{name}"\ncommand = {command}\n'
        cases = {
            "underscore in name": server.format(name="bad_name", command='["srv"]'),
            "double hyphen": server.format(name="a--b", command='["srv"]'),
            "shell interpreter": server.format(name="a", command='["bash", "-c", "srv"]'),
            "command string": server.format(name="a", command='"srv --flag"'),
            "duplicate": server.format(name="a", command='["srv"]') + server.format(name="a", command='["srv"]'),
            "unknown server key": '[[servers]]\nname = "a"\ncommand = ["srv"]\nenv = {}\n',
            "no servers": "",
        }
        for label, servers in cases.items():
            with self.subTest(label), self.assertRaises(PolicyLoadError):
                load_gateway_config(self.write(f'schema_version = 1\npolicy = "p.toml"\n{servers}'))
        with self.assertRaises(PolicyLoadError):
            load_gateway_config(self.write('policy = "p.toml"\n' + server.format(name="a", command='["srv"]')))


class FakeDownstream:
    """In-memory downstream server: records requests and answers with canned results."""

    def __init__(self, name: str, tools: list[str], resources: list[str] | None = None) -> None:
        self.name = name
        self.tools = tools
        self.resources = resources or []
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def request(self, method: str, params: dict[str, Any], timeout: float = 60.0) -> dict[str, Any]:
        self.calls.append((method, params))
        if method == "tools/list":
            result: Any = {"tools": [{"name": t, "description": f"{t} from {self.name}"} for t in self.tools]}
        elif method == "resources/list":
            result = {"resources": [{"uri": uri, "name": uri} for uri in self.resources]}
        else:
            result = {"served_by": self.name, "method": method, "params": params}
        return {"jsonrpc": "2.0", "id": "x", "result": result}

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        self.calls.append((method, params or {}))

    def close(self) -> None:
        pass


class GatewayTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmpdir.name)
        (self.workspace / "src").mkdir()
        (self.workspace / "src" / "main.py").write_text("print('mellyn')\n", encoding="utf-8")
        self.authorizer = Authorizer(workspace_root=self.workspace, policy_config=load_policy_file(EXAMPLE_POLICY))
        self.approvals = PendingApprovals(self.authorizer)
        self.local = FakeDownstream(
            "local-workspace",
            ["workspace_read", "workspace_write", "shell_exec"],
            resources=[(self.workspace / "src" / "main.py").as_uri(), "shared://x"],
        )
        self.github = FakeDownstream("github-readonly", ["get_issue", "workspace_read"], resources=["shared://x"])
        self.client_notifications: list[dict[str, Any]] = []
        self.gateway = MCPGateway(
            authorizer=self.authorizer,
            servers={"local-workspace": self.local, "github-readonly": self.github},
            approvals=self.approvals,
            notify_client=self.client_notifications.append,
        )
        self._ids = iter(range(1, 1000))

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def send(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        reply = self.gateway.handle_message(
            {"jsonrpc": "2.0", "id": next(self._ids), "method": method, "params": params or {}}
        )
        self.assertIsNotNone(reply)
        return reply  # type: ignore[return-value]

    def call(self, tool: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        return self.send("tools/call", {"name": tool, "arguments": arguments or {}})

    def forwarded(self, server: FakeDownstream, method: str) -> list[dict[str, Any]]:
        return [params for m, params in server.calls if m == method]


class TestGatewayProtocol(GatewayTestCase):
    def test_gateway_answers_initialize_itself(self) -> None:
        reply = self.send("initialize", {"protocolVersion": "2025-03-26"})
        self.assertEqual(reply["result"]["protocolVersion"], "2025-03-26")
        self.assertNotIn("instructions", reply["result"])
        self.assertEqual(self.local.calls + self.github.calls, [])

    def test_unknown_methods_and_prompts_fail_closed(self) -> None:
        self.assertEqual(self.send("admin/exec")["error"]["code"], JSONRPC_METHOD_NOT_FOUND)
        self.assertEqual(self.send("prompts/get", {"name": "x"})["error"]["code"], JSONRPC_METHOD_NOT_FOUND)
        self.assertEqual(self.send("prompts/list")["result"], {"prompts": []})

    def test_notifications_get_no_reply_and_execute_nothing(self) -> None:
        message = {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "local-workspace__shell_exec"}}
        self.assertIsNone(self.gateway.handle_message(message))
        self.assertEqual(self.local.calls, [])

    def test_tool_names_are_namespaced_by_server(self) -> None:
        names = [t["name"] for t in self.send("tools/list")["result"]["tools"]]
        self.assertIn("local-workspace__workspace_read", names)
        self.assertIn("github-readonly__workspace_read", names)

    def test_call_is_routed_and_rebuilt_from_validated_fields(self) -> None:
        reply = self.call("local-workspace__workspace_read", {"path": "src/main.py"})
        self.assertEqual(reply["result"]["served_by"], "local-workspace")
        self.assertEqual(
            self.forwarded(self.local, "tools/call"), [{"name": "workspace_read", "arguments": {"path": "src/main.py"}}]
        )
        self.assertEqual(self.forwarded(self.github, "tools/call"), [])

    def test_malformed_tool_names_are_rejected(self) -> None:
        for name in ("workspace_read", "unknown-server__x", "local-workspace__", "local-workspace__\n"):
            with self.subTest(name=name):
                self.assertEqual(self.call(name)["error"]["code"], JSONRPC_INVALID_PARAMS)

    def test_oversized_arguments_rejected(self) -> None:
        reply = self.call("local-workspace__workspace_write", {"path": "src/x.py", "content": "x" * 70000})
        self.assertEqual(reply["error"]["code"], JSONRPC_INVALID_PARAMS)
        self.assertEqual(self.forwarded(self.local, "tools/call"), [])

    def test_only_list_changed_notifications_reach_the_client(self) -> None:
        self.gateway.on_downstream_notification("github-readonly", {"method": "notifications/message", "params": {}})
        self.gateway.on_downstream_notification("github-readonly", {"method": "notifications/tools/list_changed"})
        self.assertEqual(self.client_notifications, [{"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}])


class TestGatewaySecurity(GatewayTestCase):
    def test_listing_an_untrusted_servers_tools_taints_the_session(self) -> None:
        self.assertFalse(self.authorizer.is_tainted(self.gateway.session_id))
        self.send("tools/list")
        self.assertTrue(self.authorizer.is_tainted(self.gateway.session_id))

    def test_trusted_servers_alone_do_not_taint(self) -> None:
        gateway = MCPGateway(authorizer=self.authorizer, servers={"local-workspace": self.local})
        gateway.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertFalse(self.authorizer.is_tainted(gateway.session_id))

    def test_taint_from_one_server_applies_to_calls_on_another(self) -> None:
        self.assertIn("result", self.call("local-workspace__workspace_write", {"path": "src/x.py"}))
        self.assertIn("result", self.call("github-readonly__get_issue", {"n": 1}))  # untrusted result -> taint
        reply = self.call("local-workspace__workspace_write", {"path": "src/x.py"})
        self.assertEqual(reply["error"]["code"], MELLYN_APPROVAL_REQUIRED)

    def test_server_cannot_borrow_a_low_tier_by_tool_name(self) -> None:
        reply = self.call("github-readonly__workspace_read", {"path": "src/main.py"})
        self.assertEqual(reply["error"]["code"], MELLYN_APPROVAL_REQUIRED)

    def test_denied_call_never_reaches_downstream_and_hides_reasons(self) -> None:
        reply = self.call("local-workspace__shell_exec", {"argv": ["rm", "-rf", "src"]})
        self.assertEqual(reply["error"]["code"], MELLYN_POLICY_DENIED)
        self.assertNotIn("reasons", reply["error"]["data"])
        self.assertEqual(self.forwarded(self.local, "tools/call"), [])

    def test_approval_flow_allows_the_exact_call_once(self) -> None:
        arguments = {"argv": ["python", "-m", "build"]}
        held = self.call("local-workspace__shell_exec", arguments)
        self.assertEqual(held["error"]["code"], MELLYN_APPROVAL_REQUIRED)
        approval_id = held["error"]["data"]["approval_id"]
        again = self.call("local-workspace__shell_exec", arguments)
        self.assertEqual(again["error"]["data"]["approval_id"], approval_id)  # identical calls share one entry
        self.assertEqual([p.approval_id for p in self.approvals.list()], [approval_id])

        self.approvals.approve(approval_id, approved_by="reviewer@example.com")
        self.assertIn("result", self.call("local-workspace__shell_exec", arguments))
        self.assertEqual(self.call("local-workspace__shell_exec", arguments)["error"]["code"], MELLYN_APPROVAL_REQUIRED)
        self.assertEqual(len(self.forwarded(self.local, "tools/call")), 1)

    def test_without_an_approval_channel_held_calls_are_denied(self) -> None:
        gateway = MCPGateway(authorizer=self.authorizer, servers={"local-workspace": self.local})
        reply = gateway.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "local-workspace__shell_exec", "arguments": {"argv": ["make"]}},
            }
        )
        self.assertEqual(reply["error"]["code"], MELLYN_POLICY_DENIED)

    def test_resource_reads_are_routed_authorized_and_audited(self) -> None:
        listed = [r["uri"] for r in self.send("resources/list")["result"]["resources"]]
        main_uri = (self.workspace / "src" / "main.py").as_uri()
        self.assertEqual(listed, [main_uri])  # "shared://x" is claimed by two servers, so it is dropped
        before = len(self.authorizer.audit.events)
        self.assertIn("result", self.send("resources/read", {"uri": main_uri}))
        self.assertEqual(len(self.authorizer.audit.events), before + 1)
        for uri in ("shared://x", "file:///never-listed"):
            with self.subTest(uri=uri):
                self.assertEqual(self.send("resources/read", {"uri": uri})["error"]["code"], JSONRPC_INVALID_PARAMS)

    def test_resource_read_of_a_secret_file_is_denied(self) -> None:
        (self.workspace / ".env").write_text("X=1\n", encoding="utf-8")
        secret_uri = (self.workspace / ".env").as_uri()
        self.local.resources.append(secret_uri)
        self.send("resources/list")
        self.assertEqual(self.send("resources/read", {"uri": secret_uri})["error"]["code"], MELLYN_POLICY_DENIED)
        self.assertEqual(self.forwarded(self.local, "resources/read"), [])


class TestStdioProxy(GatewayTestCase):
    def test_malformed_json_gets_a_parse_error(self) -> None:
        client_in = io.StringIO('this is not json\n\n{"jsonrpc":"2.0","id":7,"method":"ping"}\n')
        client_out = io.StringIO()
        run_stdio_proxy(gateway=self.gateway, client_in=client_in, client_out=client_out)
        replies = [json.loads(line) for line in client_out.getvalue().splitlines()]
        self.assertEqual(replies[0]["error"]["code"], JSONRPC_PARSE_ERROR)
        self.assertEqual(replies[1], {"jsonrpc": "2.0", "id": 7, "result": {}})


class TestStdioDownstream(unittest.TestCase):
    def test_replies_are_matched_by_id_despite_interleaved_messages(self) -> None:
        notes: list[dict[str, Any]] = []
        server = StdioDownstream(
            "fake",
            [sys.executable, str(FAKE_SERVER)],
            on_notification=lambda _s, m: notes.append(m),
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(server.close)
        initialize_downstream(server, timeout=20)
        first = server.request("tools/call", {"name": "read_note", "arguments": {}}, timeout=20)
        second = server.request("tools/call", {"name": "read_note", "arguments": {}}, timeout=20)
        ping = server.request("ping", {}, timeout=20)
        self.assertIn("called read_note", first["result"]["content"][0]["text"])
        self.assertIn("sampling_refused=True", second["result"]["content"][0]["text"])
        self.assertEqual(ping["result"], {})
        self.assertEqual([n["method"] for n in notes], ["notifications/message", "notifications/message"])

    def test_closed_server_returns_an_error_instead_of_hanging(self) -> None:
        server = StdioDownstream("gone", [sys.executable, "-c", "pass"], stderr=subprocess.DEVNULL)
        self.addCleanup(server.close)
        self.assertIn("error", server.request("ping", {}, timeout=20))


class TestGatewayEndToEnd(unittest.TestCase):
    """Runs `python -m mellyn.mcp_gateway` as a real process in front of the fake server."""

    def test_full_gateway_process(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "policy.toml").write_text(
                'schema_version = 1\nallowed_mcp_servers = ["fake", "files"]\ntrusted_mcp_servers = ["files"]\n'
                '[tool_risk_tiers]\n"fake/read_note" = "low"\n"files/workspace_write" = "medium"\n'
                '[tool_capabilities."fake/read_note"]\npure = true\n',
                encoding="utf-8",
            )
            server = json.dumps([sys.executable, str(FAKE_SERVER)])
            (workspace / "gateway.toml").write_text(
                f'schema_version = 1\npolicy = "policy.toml"\n'
                f'[[servers]]\nname = "fake"\ncommand = {server}\n'
                f'[[servers]]\nname = "files"\ncommand = {server}\n',
                encoding="utf-8",
            )
            messages = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "fake__read_note"}},
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": "files__workspace_write", "arguments": {"path": "gateway.toml"}},
                },
                {"jsonrpc": "2.0", "id": 5, "method": "ping"},
            ]
            env = {k: v for k, v in os.environ.items() if not k.startswith("MELLYN_")}
            env["PYTHONPATH"] = str(BACKEND_DIR)
            proc = subprocess.run(  # noqa: S603 - fixed argv, test only
                [
                    sys.executable,
                    "-m",
                    "mellyn.mcp_gateway",
                    "--config",
                    str(workspace / "gateway.toml"),
                    "--workspace",
                    str(workspace),
                    "--audit-log",
                    str(workspace / "audit.jsonl"),
                ],
                input="".join(json.dumps(m) + "\n" for m in messages),
                capture_output=True,
                text=True,
                env=env,
                timeout=60,
                check=False,
            )
            replies = {r["id"]: r for r in map(json.loads, proc.stdout.splitlines()) if "id" in r}
            self.assertEqual(sorted(replies), [1, 2, 3, 4, 5], proc.stderr)
            self.assertNotIn("instructions", replies[1]["result"])
            self.assertIn("fake__read_note", [t["name"] for t in replies[2]["result"]["tools"]])
            self.assertIn("called read_note", replies[3]["result"]["content"][0]["text"])
            self.assertEqual(replies[4]["error"]["code"], MELLYN_POLICY_DENIED)  # its own config is protected
            self.assertEqual(replies[5]["result"], {})
            audit = (workspace / "audit.jsonl").read_text(encoding="utf-8")
            self.assertEqual(len(audit.splitlines()), 2)
            self.assertNotIn("aud_forged", audit)  # the server's stderr cannot write into the audit log
            self.assertIn("aud_forged", proc.stderr)


class TestApprovalServer(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        pepper = secrets.token_urlsafe(32)
        self.approver_key = secrets.token_urlsafe(32)
        credentials = CredentialConfig.from_env(
            {"MELLYN_API_KEY_PEPPER": pepper, "MELLYN_APPROVER_KEY_DIGEST": key_digest(self.approver_key, pepper)},
            roles=frozenset({Role.APPROVER}),
        )
        self.authorizer = Authorizer(
            workspace_root=Path(self._tmpdir.name), policy_config=load_policy_file(EXAMPLE_POLICY)
        )
        self.approvals = PendingApprovals(self.authorizer)
        self.server = ApprovalHTTPServer(self.approvals, credentials)
        self.server.start_in_background()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        local = FakeDownstream("local-workspace", ["shell_exec"])
        self.gateway = MCPGateway(
            authorizer=self.authorizer, servers={"local-workspace": local}, approvals=self.approvals
        )

    def http(self, method: str, path: str, key: str | None, body: dict[str, Any] | None = None) -> tuple[int, Any]:
        headers = {"Content-Type": "application/json"}
        if key is not None:
            headers["X-Mellyn-API-Key"] = key
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(self.server.url + path, data=data, method=method, headers=headers)  # noqa: S310
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # loopback test server; no proxies
        try:
            with opener.open(request, timeout=10) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read() or b"{}")

    def hold_a_call(self) -> str:
        reply = self.gateway.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "local-workspace__shell_exec", "arguments": {"argv": ["make", "release"]}},
            }
        )
        return reply["error"]["data"]["approval_id"]

    def test_requires_the_approver_key(self) -> None:
        for key in (None, "wrong", ""):
            with self.subTest(key=key):
                self.assertEqual(self.http("GET", "/v1/pending", key)[0], 403)

    def test_list_and_approve(self) -> None:
        approval_id = self.hold_a_call()
        status, body = self.http("GET", "/v1/pending", self.approver_key)
        self.assertEqual(status, 200)
        self.assertEqual(body["pending"][0]["arguments"], {"argv": ["make", "release"]})
        self.assertTrue(body["pending"][0]["reasons"])  # the approver sees why; the agent does not
        status, body = self.http(
            "POST", f"/v1/pending/{approval_id}/approve", self.approver_key, {"approved_by": "reviewer@example.com"}
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(self.http("GET", "/v1/pending", self.approver_key)[1]["pending"], [])

    def test_invalid_approvals_are_refused(self) -> None:
        approval_id = self.hold_a_call()
        path = f"/v1/pending/{approval_id}/approve"
        for body in (
            {},
            {"approved_by": ""},
            {"approved_by": "x", "max_uses": 0},
            {"approved_by": "x", "ttl_seconds": True},
        ):
            with self.subTest(body=body):
                self.assertEqual(self.http("POST", path, self.approver_key, body)[0], 400)
        self.assertEqual(
            self.http("POST", "/v1/pending/apr_unknownunknown/approve", self.approver_key, {"approved_by": "x"})[0], 404
        )

    def test_reject_discards_the_call(self) -> None:
        approval_id = self.hold_a_call()
        self.assertEqual(self.http("POST", f"/v1/pending/{approval_id}/reject", self.approver_key, {})[0], 200)
        self.assertEqual(self.approvals.list(), [])


class TestApproverCli(unittest.TestCase):
    def test_key_is_only_sent_to_loopback_http(self) -> None:
        self.assertEqual(validate_approval_url("http://127.0.0.1:8765"), "http://127.0.0.1:8765")
        for url in (
            "https://127.0.0.1:8765",
            "http://evil.example:8765",
            "http://127.0.0.1.evil.example",
            "http://user:pw@127.0.0.1:1",
            "http://127.0.0.1:1/v1/pending",
            "",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_approval_url(url)


class TestAuditSink(unittest.TestCase):
    def test_events_are_appended_to_the_sink_as_jsonl(self) -> None:
        sink = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            authorizer = Authorizer(workspace_root=Path(tmp), audit_logger=AuditLogger(sink))
            session = authorizer.create_session()
            authorizer.authorize(ToolCallRequest(session, "workspace_read", {"path": "a.txt"}))
        lines = sink.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["tool_name"], "workspace_read")


if __name__ == "__main__":
    unittest.main()
