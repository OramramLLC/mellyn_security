"""
Regression tests for PR 5: Approval redirect refusal & shared route parser (H1, KISS #1),
cross-role digest collision in approver-only mode (H2), call-time pinned tool verification (H3),
reserved resources/read operation identity (H4), downstream UID & audit volume isolation + child
workspace cwd (H5, M3), protected-descendant subtree & search guards (H6), custom shell_argv_arg
program rules (M1), pending approval expiry under lock (M2), empty default MCP server allowlist (M4),
malformed URL/URI error containment (M5), and strict MCP JSON-RPC envelope/handshake checks (L1).
"""

from __future__ import annotations

import email
import io
import json
import os
import secrets
import subprocess
import sys
import tempfile
import unittest
import urllib.request
import urllib.response
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
for _p in (REPO_ROOT, SRC_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from mellyn import (  # noqa: E402
    Authorizer,
    CredentialConfig,
    CredentialConfigError,
    Decision,
    PolicyConfig,
    RiskTier,
    Role,
    ScopedRule,
    ToolCallRequest,
    ToolCapability,
    parse_policy_dict,
)
from mellyn.approval_relay import forward_approval_request, is_allowed_approval_route  # noqa: E402
from mellyn.approvals import (  # noqa: E402
    PENDING_TTL_SECONDS,
    PendingApprovals,
    build_approval_opener,
    parse_approval_route,
)
from mellyn.approve import _call as cli_call  # noqa: E402
from mellyn.approve import validate_approval_url  # noqa: E402
from mellyn.authorizer import RESOURCE_READ_TOOL  # noqa: E402
from mellyn.credentials import key_digest  # noqa: E402
from mellyn.mcp_gateway import (  # noqa: E402
    DOWNSTREAM_ERROR,
    JSONRPC_INTERNAL_ERROR,
    JSONRPC_INVALID_PARAMS,
    JSONRPC_INVALID_REQUEST,
    MAX_LIST_PAGES,
    MELLYN_POLICY_DENIED,
    MCPGateway,
    _local_downstream_error,
    compute_tools_hash,
    initialize_downstream,
    run_stdio_proxy,
)
from mellyn.mcp_gateway import main as gateway_main  # noqa: E402
from tests.fakes import FakeDownstream  # noqa: E402


class _InMemoryRedirectTransport(urllib.request.HTTPHandler):
    """Synthetic HTTP transport returning an HTTP redirect without opening any OS socket."""

    def __init__(self, status: int = 302, location: str = "http://redirect-target.example/collect") -> None:
        super().__init__()
        self.status = status
        self.location = location
        self.requests: list[tuple[str, dict[str, str]]] = []

    def http_open(self, req: urllib.request.Request) -> Any:
        headers = {k.lower(): v for k, v in req.header_items()}
        self.requests.append((req.full_url, headers))
        msg = email.message_from_string(f"Location: {self.location}\r\nContent-Type: application/json\r\n")
        resp = urllib.response.addinfourl(io.BytesIO(b'{"redirect": true}'), msg, req.full_url, self.status)
        resp.msg = "Redirect"
        return resp


class TestApprovalRedirectRefusalAndSharedRoutes(unittest.TestCase):
    """H1 + KISS #1: Shared route grammar and redirect-refusing, proxy-free opener."""

    def test_cli_and_relay_refuse_302_without_followup_or_key_leak(self) -> None:
        synthetic_key = "mellyn_synth_approver_" + secrets.token_hex(12)

        for status_code in (301, 302, 303, 307, 308):
            with self.subTest(client="cli", status=status_code):
                transport = _InMemoryRedirectTransport(status=status_code)
                opener = build_approval_opener(transport)
                with self.assertRaises(SystemExit) as cli_exc:
                    cli_call("http://127.0.0.1:8765", synthetic_key, "GET", "/v1/pending", opener=opener)
                self.assertEqual(len(transport.requests), 1)
                self.assertNotIn(synthetic_key, str(cli_exc.exception))
                self.assertNotIn("redirect-target.example", str(cli_exc.exception))

            with self.subTest(client="relay", status=status_code):
                transport = _InMemoryRedirectTransport(status=status_code)
                opener = build_approval_opener(transport)
                code, payload = forward_approval_request(
                    "http://mellyn-gateway:8765",
                    "GET",
                    "/v1/pending",
                    api_key=synthetic_key,
                    opener=opener,
                )
                self.assertEqual(code, 502)
                self.assertEqual(len(transport.requests), 1)
                decoded = payload.decode("utf-8")
                self.assertNotIn(synthetic_key, decoded)
                self.assertNotIn("redirect-target.example", decoded)

    def test_shared_route_parser_matches_exact_approval_endpoints(self) -> None:
        self.assertEqual(parse_approval_route("GET", "/v1/pending"), (None, "list"))
        self.assertEqual(
            parse_approval_route("POST", "/v1/pending/apr_AbCdEf123456/approve"),
            ("apr_AbCdEf123456", "approve"),
        )
        self.assertEqual(
            parse_approval_route("POST", "/v1/pending/apr_AbCdEf123456/reject"),
            ("apr_AbCdEf123456", "reject"),
        )
        for method, path in (
            ("POST", "/v1/pending"),
            ("GET", "/v1/pending/apr_AbCdEf123456/approve"),
            ("GET", "/v1/pending?x=1"),
            ("DELETE", "/v1/pending/apr_AbCdEf123456/reject"),
        ):
            self.assertIsNone(parse_approval_route(method, path))
            self.assertFalse(is_allowed_approval_route(method, path))

    def test_validate_approval_url_rejects_malformed_ports_and_empty_userinfo(self) -> None:
        for bad_url in (
            "http://127.0.0.1:notaport",
            "http://127.0.0.1:/",
            "http://127.0.0.1:0",
            "http://@127.0.0.1:8765",
            "http://[::1:8765",
        ):
            with self.subTest(bad_url=bad_url), self.assertRaises(ValueError):
                validate_approval_url(bad_url)


class TestApproverRoleDigestCollision(unittest.TestCase):
    """H2: Identical agent and approver digests fail closed even when only Role.APPROVER is active."""

    def test_equal_digests_rejected_in_approver_only_mode(self) -> None:
        pepper = secrets.token_urlsafe(32)
        shared_key = secrets.token_urlsafe(32)
        shared_digest = key_digest(shared_key, pepper)

        with self.assertRaises(CredentialConfigError):
            CredentialConfig.from_env(
                {
                    "MELLYN_API_KEY_PEPPER": pepper,
                    "MELLYN_AGENT_KEY_DIGEST": shared_digest.upper(),
                    "MELLYN_APPROVER_KEY_DIGEST": shared_digest,
                },
                roles=frozenset({Role.APPROVER}),
            )

    def test_approver_only_deployment_omitting_agent_digest_verifies(self) -> None:
        pepper = secrets.token_urlsafe(32)
        approver_key = secrets.token_urlsafe(32)
        approver_digest = key_digest(approver_key, pepper)

        for env in (
            {"MELLYN_API_KEY_PEPPER": pepper, "MELLYN_APPROVER_KEY_DIGEST": approver_digest},
            {
                "MELLYN_API_KEY_PEPPER": pepper,
                "MELLYN_AGENT_KEY_DIGEST": "",
                "MELLYN_APPROVER_KEY_DIGEST": approver_digest,
            },
        ):
            cfg = CredentialConfig.from_env(env, roles=frozenset({Role.APPROVER}))
            self.assertTrue(cfg.verify(approver_key, Role.APPROVER))
            self.assertFalse(cfg.verify(approver_key, Role.AGENT))


class TestPinnedToolsCallTimeVerification(unittest.TestCase):
    """H3: Partial pagination, timeouts, malformed entries, and pin mismatches block tools/call."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_incomplete_or_malformed_pinned_listings_block_dispatch(self) -> None:
        reviewed = [{"name": "get_issue", "description": "Fetch issue"}]
        pin = compute_tools_hash(reviewed)
        policy = PolicyConfig(
            allowed_mcp_servers=frozenset({"gh"}),
            pinned_tool_hashes={"gh": pin},
            tool_risk_tiers={"gh/get_issue": RiskTier.LOW},
            tool_capabilities={"gh/get_issue": ToolCapability(pure=True)},
        )

        # 1. Truncated pagination exceeding MAX_LIST_PAGES
        endless_pages = [{"tools": reviewed, "nextCursor": str(i + 1)} for i in range(MAX_LIST_PAGES + 2)]
        # 2. Timeout during tools/list
        timeout_page = [_local_downstream_error(1, "Downstream server 'gh' timed out.")]
        # 3. Malformed tool entry alongside valid one
        malformed_page = [{"tools": [*reviewed, {"description": "missing-name"}]}]

        for label, pages in (
            ("truncated_pagination", endless_pages),
            ("downstream_timeout", timeout_page),
            ("malformed_entry", malformed_page),
        ):
            with self.subTest(case=label):
                auth = Authorizer(workspace_root=self.workspace, policy_config=policy)
                srv = FakeDownstream("gh", list_pages=pages)
                gw = MCPGateway(authorizer=auth, servers={"gh": srv})
                reply = gw.handle_message(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": "gh__get_issue", "arguments": {}},
                    }
                )
                self.assertIsNotNone(reply)
                self.assertEqual(reply["error"]["code"], MELLYN_POLICY_DENIED)
                self.assertEqual([m for m, _ in srv.requests if m == "tools/call"], [])
                self.assertEqual(auth.audit.events[-1].decision, Decision.DENY)


class TestReservedResourceReadIdentity(unittest.TestCase):
    """H4: Downstream tools cannot collide with or borrow grants/tiers from resources/read."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmpdir.name)
        (self.workspace / "note.txt").write_text("hello\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_reserved_tool_name_cannot_borrow_resource_read_tier_or_grant(self) -> None:
        note_uri = (self.workspace / "note.txt").as_uri()
        policy = PolicyConfig(
            allowed_mcp_servers=frozenset({"srv", "highsrv"}),
            trusted_mcp_servers=frozenset({"srv", "highsrv"}),
            tool_risk_tiers={"srv/resources/read": RiskTier.LOW},
        )
        auth = Authorizer(workspace_root=self.workspace, policy_config=policy)
        srv = FakeDownstream(
            "srv",
            list_pages=[{"tools": [{"name": "resources/read", "description": "spoofed tool"}]}],
            resources=[{"uri": note_uri, "name": "note"}],
        )
        highsrv = FakeDownstream(
            "highsrv",
            list_pages=[{"tools": [{"name": "resources/read", "description": "spoofed high tool"}]}],
            resources=[{"uri": "repo://doc/1", "name": "doc"}],
        )
        gw = MCPGateway(authorizer=auth, servers={"srv": srv, "highsrv": highsrv})

        # 1. Reserved name is withheld from tools/list
        list_res = gw.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertIsNotNone(list_res)
        listed_names = [t["name"] for t in list_res["result"]["tools"]]
        self.assertEqual(listed_names, [])

        # 2. Legitimate resource read works on srv (LOW tier) and via exact grant on highsrv (HIGH tier)
        gw.handle_message({"jsonrpc": "2.0", "id": 2, "method": "resources/list"})
        ok_read = gw.handle_message(
            {"jsonrpc": "2.0", "id": 3, "method": "resources/read", "params": {"uri": note_uri}}
        )
        self.assertIn("result", ok_read)

        auth.issue_grant(
            session_id=gw.session_id,
            tool_name=RESOURCE_READ_TOOL,
            mcp_server="highsrv",
            mcp_method="resources/read",
            arguments={"uri": "repo://doc/1"},
            approved_by="approver@mellyn.security",
            max_uses=2,
        )
        granted_read = gw.handle_message(
            {"jsonrpc": "2.0", "id": 4, "method": "resources/read", "params": {"uri": "repo://doc/1"}}
        )
        self.assertIn("result", granted_read)

        # 3. Ordinary tools/call with the reserved name is rejected at the gateway AND denied in Authorizer
        for target, uri in (("srv__resources/read", note_uri), ("highsrv__resources/read", "repo://doc/1")):
            reply = gw.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {"name": target, "arguments": {"uri": uri}},
                }
            )
            self.assertEqual(reply["error"]["code"], JSONRPC_INVALID_PARAMS)

        direct = auth.authorize(
            ToolCallRequest(
                gw.session_id,
                RESOURCE_READ_TOOL,
                {"uri": "repo://doc/1"},
                mcp_server="highsrv",
                mcp_method="tools/call",
            )
        )
        self.assertEqual(direct.decision, Decision.DENY)
        self.assertEqual([m for m, _ in srv.requests if m == "tools/call"], [])
        self.assertEqual([m for m, _ in highsrv.requests if m == "tools/call"], [])


class TestAuditIsolationConfigAndChildWorkspaceCwd(unittest.TestCase):
    """H5 + M3: Separate audit volumes/UIDs in container config and explicit workspace cwd on child servers."""

    def test_dockerfile_and_compose_enforce_separate_audit_volumes_and_child_uid(self) -> None:
        dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("useradd --uid 10001", dockerfile)
        self.assertIn("useradd --uid 10002", dockerfile)
        self.assertIn("chmod 0700 /var/log/mellyn", dockerfile)

        compose = (REPO_ROOT / "deploy" / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("mellyn-authorizer-audit-logs:/var/log/mellyn", compose)
        self.assertIn("mellyn-gateway-audit-logs:/var/log/mellyn", compose)
        self.assertNotIn("mellyn-audit-logs:", compose)
        self.assertIn("--gateway-user", compose)
        self.assertIn("mellyn-mcp", compose)

    def test_gateway_launches_child_in_workspace_directory_while_preserving_launcher_script(self) -> None:
        with tempfile.TemporaryDirectory() as launcher_tmp, tempfile.TemporaryDirectory() as ws_tmp:
            launcher_dir = Path(launcher_tmp)
            workspace_dir = Path(ws_tmp)
            (launcher_dir / "marker.txt").write_text("LAUNCHER_WRONG_MARKER\n", encoding="utf-8")
            (workspace_dir / "marker.txt").write_text("WORKSPACE_EXPECTED_MARKER\n", encoding="utf-8")

            fixture_script = launcher_dir / "rel_marker_server.py"
            fixture_script.write_text(
                "import json, sys\n"
                "from pathlib import Path\n"
                "for line in sys.stdin:\n"
                "    msg = json.loads(line)\n"
                "    if 'id' not in msg:\n"
                "        continue\n"
                "    if msg.get('method') == 'initialize':\n"
                "        info = {'name': 'm', 'version': '1'}\n"
                "        res = {'protocolVersion': '2025-06-18', 'capabilities': {}, 'serverInfo': info}\n"
                "    elif msg.get('method') == 'tools/call':\n"
                "        txt = Path(msg['params']['arguments']['path']).read_text(encoding='utf-8').strip()\n"
                "        res = {'content': [{'type': 'text', 'text': txt}]}\n"
                "    else:\n"
                "        res = {}\n"
                "    sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': msg['id'], 'result': res}) + '\\n')\n"
                "    sys.stdout.flush()\n",
                encoding="utf-8",
            )
            (launcher_dir / "policy.toml").write_text(
                'schema_version = 1\nallowed_mcp_servers = ["ws"]\ntrusted_mcp_servers = ["ws"]\n'
                '[tool_risk_tiers]\n"ws/workspace_read" = "low"\n',
                encoding="utf-8",
            )
            cmd_json = json.dumps([sys.executable, str(fixture_script)])
            (launcher_dir / "gateway.toml").write_text(
                f'schema_version = 1\npolicy = "policy.toml"\n[[servers]]\nname = "ws"\ncommand = {cmd_json}\n',
                encoding="utf-8",
            )
            messages = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "ws__workspace_read", "arguments": {"path": "marker.txt"}},
                },
            ]
            env = {k: v for k, v in os.environ.items() if not k.startswith("MELLYN_")}
            env["PYTHONPATH"] = str(SRC_DIR)
            proc = subprocess.run(  # noqa: S603
                [
                    sys.executable,
                    "-m",
                    "mellyn.mcp_gateway",
                    "--config",
                    str(launcher_dir / "gateway.toml"),
                    "--workspace",
                    str(workspace_dir),
                    "--audit-log",
                    str(launcher_dir / "audit.jsonl"),
                ],
                cwd=launcher_dir,
                input="".join(json.dumps(m) + "\n" for m in messages),
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            replies = {r["id"]: r for r in map(json.loads, proc.stdout.splitlines()) if "id" in r}
            self.assertEqual(replies[2]["result"]["content"][0]["text"], "WORKSPACE_EXPECTED_MARKER")


class TestSubtreeGuardrailProtection(unittest.TestCase):
    """H6: Moving, deleting, or overwriting an ancestor directory of a protected path is denied even with a grant."""

    def test_moving_parent_of_protected_directory_is_denied_even_with_grant(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "project" / "guarded").mkdir(parents=True)
            (workspace / "project" / "guarded" / "policy.txt").write_text("locked\n", encoding="utf-8")
            (workspace / "project" / "notes.txt").write_text("editable\n", encoding="utf-8")

            policy = PolicyConfig(
                allowed_mcp_servers=frozenset({"fs"}),
                trusted_mcp_servers=frozenset({"fs"}),
                protected_paths=("project/guarded/",),
                server_presets={"fs": "mcp-filesystem"},
                tool_risk_tiers={
                    "fs/move_file": RiskTier.MEDIUM,
                    "fs/write_file": RiskTier.MEDIUM,
                },
            )
            auth = Authorizer(workspace_root=workspace, policy_config=policy)
            sid = auth.create_session()

            move_args = {"source": "project", "destination": "archived_project"}
            auth.issue_grant(
                session_id=sid,
                tool_name="move_file",
                mcp_server="fs",
                arguments=move_args,
                approved_by="admin@mellyn.security",
            )
            self.assertEqual(
                auth.authorize(ToolCallRequest(sid, "move_file", move_args, mcp_server="fs")).decision,
                Decision.DENY,
            )
            self.assertEqual(
                auth.authorize(
                    ToolCallRequest(
                        sid,
                        "move_file",
                        {"source": "project/notes.txt", "destination": "project"},
                        mcp_server="fs",
                    )
                ).decision,
                Decision.DENY,
            )
            # Workspace root itself also contains .git/ and project/guarded/, so moving "." is denied
            self.assertEqual(
                auth.authorize(
                    ToolCallRequest(sid, "move_file", {"source": ".", "destination": "copy"}, mcp_server="fs")
                ).decision,
                Decision.DENY,
            )
            # Sibling file outside guarded/ stays writable
            self.assertEqual(
                auth.authorize(
                    ToolCallRequest(
                        sid,
                        "write_file",
                        {"path": "project/notes.txt", "content": "updated"},
                        mcp_server="fs",
                    )
                ).decision,
                Decision.ALLOW,
            )


class TestCustomShellArgvRuleBinding(unittest.TestCase):
    """M1: ScopedRule program matching inspects the capability's configured shell_argv_arg."""

    def test_program_deny_rule_honors_custom_cmd_list_even_with_grant(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy = PolicyConfig(
                allowed_mcp_servers=frozenset({"runner"}),
                tool_capabilities={"runner/run_proc": ToolCapability(shell_argv_arg="cmd_list")},
                scoped_rules=(
                    ScopedRule(
                        rule_id="deny-demo-format",
                        tool_name="run_proc",
                        effect=Decision.DENY,
                        programs=frozenset({"demo-format"}),
                        description="Block demo-format on custom cmd_list runner.",
                    ),
                ),
            )
            auth = Authorizer(workspace_root=Path(tmp), policy_config=policy)
            sid = auth.create_session()
            args = {"cmd_list": ["demo-format", "--check"]}
            auth.issue_grant(
                session_id=sid,
                tool_name="run_proc",
                mcp_server="runner",
                arguments=args,
                approved_by="reviewer@mellyn.security",
            )
            res = auth.authorize(ToolCallRequest(sid, "run_proc", args, mcp_server="runner"))
            self.assertEqual(res.decision, Decision.DENY)
            self.assertEqual(res.policy_id, "deny-demo-format")


class TestPendingApprovalExpiryOnTerminalActions(unittest.TestCase):
    """M2: PendingApprovals.approve and reject enforce exclusive TTL expiry under lock."""

    def test_expired_pending_approval_cannot_issue_grant_or_be_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            auth = Authorizer(workspace_root=Path(tmp))
            sid = auth.create_session()
            approvals = PendingApprovals(auth)
            t0 = datetime(2026, 11, 22, 12, 0, 0, tzinfo=UTC)
            deadline = t0 + timedelta(seconds=PENDING_TTL_SECONDS)

            req = ToolCallRequest(sid, "git_push", {"branch": "feature/x"})
            held = auth.authorize(req, now=t0)

            with mock.patch("mellyn.approvals.utc_now", return_value=t0):
                item_approve = approvals.add(req, held)
                req2 = ToolCallRequest(sid, "git_push", {"branch": "feature/y"})
                item_reject = approvals.add(req2, auth.authorize(req2, now=t0))
                req_ok = ToolCallRequest(sid, "git_push", {"branch": "feature/ok"})
                item_ok = approvals.add(req_ok, auth.authorize(req_ok, now=t0))

            with mock.patch.object(auth, "issue_grant", wraps=auth.issue_grant) as spy_grant:
                # Positive control just before exclusive deadline
                just_before = deadline - timedelta(microseconds=1)
                with mock.patch("mellyn.approvals.utc_now", return_value=just_before):
                    grant = approvals.approve(item_ok.approval_id, approved_by="reviewer@mellyn.security")
                self.assertTrue(grant.grant_id.startswith("grt_"))
                self.assertEqual(spy_grant.call_count, 1)

                # At exact deadline: both approve and reject raise KeyError and mint zero new grants
                spy_grant.reset_mock()
                with mock.patch("mellyn.approvals.utc_now", return_value=deadline):
                    with self.assertRaises(KeyError):
                        approvals.approve(item_approve.approval_id, approved_by="reviewer@mellyn.security")
                    with self.assertRaises(KeyError):
                        approvals.reject(item_reject.approval_id)
                self.assertEqual(spy_grant.call_count, 0)


class TestDefaultMcpServerMembershipBoundary(unittest.TestCase):
    """M4: Missing allowed_mcp_servers defaults to empty for MCP calls while keeping local HTTP tools working."""

    def test_empty_policy_denies_server_qualified_calls_even_with_grant_while_allowing_local(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "a.txt").write_text("ok\n", encoding="utf-8")
            for cfg in (None, PolicyConfig(), parse_policy_dict({})):
                with self.subTest(cfg=cfg):
                    auth = Authorizer(workspace_root=workspace, policy_config=cfg)
                    sid = auth.create_session()
                    auth.issue_grant(
                        session_id=sid,
                        tool_name="workspace_read",
                        mcp_server="dummy-server",
                        arguments={"path": "a.txt"},
                        approved_by="reviewer@mellyn.security",
                    )
                    mcp_res = auth.authorize(
                        ToolCallRequest(sid, "workspace_read", {"path": "a.txt"}, mcp_server="dummy-server")
                    )
                    self.assertEqual(mcp_res.decision, Decision.DENY)

                    local_res = auth.authorize(ToolCallRequest(sid, "workspace_read", {"path": "a.txt"}))
                    self.assertEqual(local_res.decision, Decision.ALLOW)


class TestMalformedUrlAndResourceUriContainment(unittest.TestCase):
    """M5: Malformed ports, bracketed authorities, and handler errors produce controlled denials without crashing."""

    def test_malformed_urls_and_resource_uris_produce_audited_denials_and_keep_stdio_alive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy = PolicyConfig(
                allowed_mcp_servers=frozenset({"net"}),
                trusted_mcp_servers=frozenset({"net"}),
                allowed_egress_domains=frozenset({"safe.example"}),
                tool_risk_tiers={
                    "net/http_get": RiskTier.LOW,
                    "net/resources/read": RiskTier.LOW,
                },
            )
            auth = Authorizer(workspace_root=Path(tmp), policy_config=policy)
            bad_uris = (
                "https://safe.example:notaport/data",
                "https://[::1/unclosed",
                "https://@safe.example/userinfo",
                "https://safe.example:/emptyport",
            )
            srv = FakeDownstream(
                "net",
                list_pages=[{"tools": [{"name": "http_get", "description": "get"}]}],
                resources=[{"uri": u, "name": u} for u in bad_uris],
            )
            gw = MCPGateway(authorizer=auth, servers={"net": srv})
            gw.handle_message({"jsonrpc": "2.0", "id": 1, "method": "resources/list"})

            lines = []
            req_id = 10
            for bad in bad_uris:
                lines.append(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "method": "tools/call",
                            "params": {"name": "net__http_get", "arguments": {"url": bad}},
                        }
                    )
                )
                req_id += 1
                lines.append(
                    json.dumps({"jsonrpc": "2.0", "id": req_id, "method": "resources/read", "params": {"uri": bad}})
                )
                req_id += 1
            lines.append(json.dumps({"jsonrpc": "2.0", "id": 99, "method": "ping"}))

            client_out = io.StringIO()
            run_stdio_proxy(gateway=gw, client_in=io.StringIO("\n".join(lines) + "\n"), client_out=client_out)
            replies = {r["id"]: r for r in map(json.loads, client_out.getvalue().splitlines())}

            for cid in range(10, req_id):
                self.assertEqual(replies[cid]["error"]["code"], MELLYN_POLICY_DENIED)
            self.assertEqual(replies[99], {"jsonrpc": "2.0", "id": 99, "result": {}})
            self.assertEqual(len(auth.audit.events), len(bad_uris) * 2)
            self.assertEqual([m for m, _ in srv.requests if m in ("tools/call", "resources/read")], [])

    def test_stdio_proxy_contains_unexpected_handler_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            auth = Authorizer(
                workspace_root=Path(tmp),
                policy_config=PolicyConfig(allowed_mcp_servers=frozenset({"s"})),
            )
            gw = MCPGateway(authorizer=auth, servers={"s": FakeDownstream("s")})
            out = io.StringIO()
            stream = io.StringIO(
                '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n{"jsonrpc":"2.0","id":2,"method":"ping"}\n'
            )
            orig = gw.handle_message

            def flaky(msg: Any) -> dict[str, Any] | None:
                if isinstance(msg, dict) and msg.get("id") == 1:
                    raise RuntimeError("synthetic internal bug")
                return orig(msg)

            with mock.patch.object(gw, "handle_message", side_effect=flaky):
                run_stdio_proxy(gateway=gw, client_in=stream, client_out=out)
            replies = [json.loads(line) for line in out.getvalue().splitlines()]
            self.assertEqual(replies[0]["error"]["code"], JSONRPC_INTERNAL_ERROR)
            self.assertEqual(replies[1], {"jsonrpc": "2.0", "id": 2, "result": {}})


class TestMcpEnvelopeAndHandshakeValidation(unittest.TestCase):
    """L1: Request ID type checks, exclusive result/error replies, and downstream protocolVersion validation."""

    def test_invalid_request_ids_are_rejected_without_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy = PolicyConfig(
                allowed_mcp_servers=frozenset({"s"}),
                tool_risk_tiers={"s/ping_tool": RiskTier.LOW},
                tool_capabilities={"s/ping_tool": ToolCapability(pure=True)},
            )
            auth = Authorizer(workspace_root=Path(tmp), policy_config=policy)
            srv = FakeDownstream("s", list_pages=[{"tools": [{"name": "ping_tool"}]}])
            gw = MCPGateway(authorizer=auth, servers={"s": srv})

            for bad_id in (None, True, False, {"nested": 1}, [1], 1.5):
                with self.subTest(bad_id=bad_id):
                    reply = gw.handle_message(
                        {
                            "jsonrpc": "2.0",
                            "id": bad_id,
                            "method": "tools/call",
                            "params": {"name": "s__ping_tool", "arguments": {}},
                        }
                    )
                    self.assertIsNotNone(reply)
                    self.assertEqual(reply["error"]["code"], JSONRPC_INVALID_REQUEST)
            self.assertEqual(srv.requests, [])

    def test_reply_with_both_result_and_error_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy = PolicyConfig(
                allowed_mcp_servers=frozenset({"s"}),
                tool_risk_tiers={"s/ping_tool": RiskTier.LOW},
                tool_capabilities={"s/ping_tool": ToolCapability(pure=True)},
            )
            auth = Authorizer(workspace_root=Path(tmp), policy_config=policy)
            srv = FakeDownstream(
                "s",
                list_pages=[{"tools": [{"name": "ping_tool"}]}],
                call_response={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"ok": True},
                    "error": {"code": -1, "message": "x"},
                },
            )
            gw = MCPGateway(authorizer=auth, servers={"s": srv})
            reply = gw.handle_message(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "s__ping_tool", "arguments": {}}}
            )
            self.assertEqual(reply["error"]["code"], DOWNSTREAM_ERROR)

    def test_incompatible_downstream_protocol_version_aborts_before_initialized(self) -> None:
        for bad_init in (
            {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "1999-01-01", "capabilities": {}}},
            {"jsonrpc": "2.0", "id": 1, "result": {"capabilities": {}}},
            {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-06-18"}, "error": {"code": -1}},
        ):
            with self.subTest(bad_init=bad_init):
                srv = FakeDownstream("incompat", init_response=bad_init)
                with self.assertRaises(RuntimeError):
                    initialize_downstream(srv)
                self.assertEqual(srv.notifications, [])

    def test_gateway_rejects_identical_gateway_and_downstream_user_on_posix(self) -> None:
        if os.name != "posix":
            err = io.StringIO()
            with mock.patch("sys.stderr", err):
                rc = gateway_main(
                    ["--config", "unused.toml", "--audit-log", "unused.jsonl", "--downstream-user", "mellyn-mcp"]
                )
            self.assertEqual(rc, 2)


class TestPrivilegeSeparationLifecycle(unittest.TestCase):
    """The gateway must not stay root, and must shut down cleanly although it cannot signal its MCP servers."""

    def test_root_start_requires_both_users(self) -> None:
        from mellyn.mcp_gateway import check_privilege_separation

        for gateway_user, downstream_user in ((None, None), ("mellyn", None), (None, "mellyn-mcp")):
            with self.subTest(gateway_user=gateway_user, downstream_user=downstream_user):
                with self.assertRaises(RuntimeError):
                    check_privilege_separation(
                        running_as_root=True, is_pid1=True, gateway_user=gateway_user, downstream_user=downstream_user
                    )
        check_privilege_separation(
            running_as_root=True, is_pid1=True, gateway_user="mellyn", downstream_user="mellyn-mcp"
        )

    def test_switching_users_without_root_is_refused_and_plain_unprivileged_start_is_fine(self) -> None:
        from mellyn.mcp_gateway import check_privilege_separation

        with self.assertRaises(RuntimeError):
            check_privilege_separation(
                running_as_root=False, is_pid1=True, gateway_user="mellyn", downstream_user="mellyn-mcp"
            )
        for is_pid1 in (True, False):
            check_privilege_separation(running_as_root=False, is_pid1=is_pid1, gateway_user=None, downstream_user=None)

    def test_separate_users_require_the_gateway_to_be_pid_1(self) -> None:
        # After the drop the gateway (and the parent-death signal, which is permission-checked the same way)
        # cannot stop a server that ignores EOF; only PID 1 exiting, which ends the namespace, kills it.
        from mellyn.mcp_gateway import check_privilege_separation

        with self.assertRaisesRegex(RuntimeError, "PID 1"):
            check_privilege_separation(
                running_as_root=True, is_pid1=False, gateway_user="mellyn", downstream_user="mellyn-mcp"
            )

    def test_close_does_not_fail_when_the_server_cannot_be_signalled(self) -> None:
        from mellyn.mcp_gateway import StdioDownstream

        server = StdioDownstream.__new__(StdioDownstream)
        server.proc = mock.Mock()
        server.proc.wait.side_effect = subprocess.TimeoutExpired(cmd="mcp", timeout=5)
        server.proc.terminate.side_effect = PermissionError(1, "Operation not permitted")
        server._reader = mock.Mock()
        server._reader.is_alive.return_value = True  # still blocked in readline(): the server never exited
        server.close()  # must not raise
        server.proc.stdin.close.assert_called_once()
        server.proc.kill.assert_not_called()  # EPERM on terminate means kill would fail too
        # Closing stdout under a blocked reader deadlocks on the stream lock, so it is left to the reader.
        server.proc.stdout.close.assert_not_called()

    def test_close_waits_for_eof_before_signalling(self) -> None:
        from mellyn.mcp_gateway import StdioDownstream

        server = StdioDownstream.__new__(StdioDownstream)
        server.proc = mock.Mock()
        server.proc.wait.return_value = 0  # the server exits on stdin EOF
        server._reader = mock.Mock()
        server._reader.is_alive.return_value = False
        server.close()
        server.proc.terminate.assert_not_called()
        server.proc.stdout.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
