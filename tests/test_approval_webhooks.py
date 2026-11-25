"""Tests for Pass 3 outbound redacted approval webhooks (Slack/Teams/generic), config, and Console deep links."""

from __future__ import annotations

import contextlib
import http.server
import io
import json
import os
import socketserver
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from http import HTTPStatus
from pathlib import Path
from typing import Any
from unittest import mock

# Importable on its own without requiring PYTHONPATH.
_REPO_ROOT = Path(__file__).resolve().parent.parent
for _import_dir in (_REPO_ROOT / "backend", _REPO_ROOT / "src"):
    if str(_import_dir) not in sys.path:
        sys.path.insert(0, str(_import_dir))

from mellyn import (  # noqa: E402
    ApprovalWebhookNotifier,
    Authorizer,
    CredentialConfig,
    NotificationsConfig,
    PolicyConfig,
    PolicyLoadError,
    RiskTier,
    Role,
    ToolCallRequest,
    build_approval_alert_summary,
    format_webhook_payload,
    load_unified_config,
)
from mellyn.approvals import PendingApproval, PendingApprovals  # noqa: E402
from mellyn.audit import hash_arguments  # noqa: E402
from mellyn.credentials import key_digest  # noqa: E402
from mellyn.egress_proxy import main as egress_main  # noqa: E402
from mellyn.legacy_env import LEGACY_ENV_PREFIX  # noqa: E402
from mellyn.mcp_gateway import MELLYN_APPROVAL_REQUIRED, MCPGateway  # noqa: E402
from mellyn.notifications import resolve_webhook_format  # noqa: E402
from mellyn.oauth_client import build_safe_opener  # noqa: E402
from mellyn.pin_gateway import GatewayPinResult, upsert_server_in_unified_toml  # noqa: E402
from mellyn.viewer_server import ViewerHTTPServer  # noqa: E402


def _synth_value(*parts: str) -> str:
    """Assemble synthetic credentials/canaries dynamically without raw secret literals."""
    return "".join(parts)


class _ReusableWebhookServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


@dataclass
class _WebhookReceiverState:
    lock: threading.Lock = field(default_factory=threading.Lock)
    mode: str = "ok"  # ok | redirect | error_500
    base_url: str = ""
    received: list[dict[str, Any]] = field(default_factory=list)
    redirect_hits: int = 0
    event: threading.Event = field(default_factory=threading.Event)


class _MockWebhookReceiver:
    """In-process loopback HTTP webhook receiver capturing delivered JSON alerts."""

    def __init__(self) -> None:
        self.state = _WebhookReceiverState()
        state = self.state

        class _Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, _format: str, *_args: Any) -> None:
                return

            def _send(
                self,
                status: int,
                body: bytes,
                *,
                content_type: str = "application/json",
                extra_headers: Mapping[str, str] | None = None,
            ) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                if extra_headers:
                    for key, val in extra_headers.items():
                        self.send_header(key, val)
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler dispatch
                if self.path == "/redirect-target":
                    with state.lock:
                        state.redirect_hits += 1
                    self._send(HTTPStatus.OK, b'{"ok":true}')
                    return
                length = int(self.headers.get("Content-Length") or "0")
                raw = self.rfile.read(length) if length > 0 else b""
                with state.lock:
                    mode = state.mode
                    base = state.base_url
                if mode == "redirect":
                    self._send(
                        HTTPStatus.FOUND,
                        b"",
                        content_type="text/plain",
                        extra_headers={"Location": f"{base}/redirect-target"},
                    )
                    return
                if mode == "error_500":
                    self._send(HTTPStatus.INTERNAL_SERVER_ERROR, b'{"error":"down"}')
                    return
                parsed = json.loads(raw.decode("utf-8"))
                with state.lock:
                    state.received.append(
                        {
                            "path": self.path,
                            "content_type": self.headers.get("Content-Type"),
                            "payload": parsed,
                        }
                    )
                    state.event.set()
                self._send(HTTPStatus.OK, b'{"ok":true}')

        self._server = _ReusableWebhookServer(("127.0.0.1", 0), _Handler)
        self.base_url = f"http://127.0.0.1:{self._server.server_port}"
        self.state.base_url = self.base_url
        self._thread = threading.Thread(target=self._server.serve_forever, name="mock-webhook", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2.0)


class _FakeHighDownstream:
    """Downstream stub used to exercise held calls cleanly."""

    def __init__(self, name: str = "github") -> None:
        self.name = name

    def request(self, method: str, params: dict[str, Any], timeout: float = 10.0) -> dict[str, Any]:
        del params, timeout
        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "tools": [
                        {
                            "name": "create_comment",
                            "description": "Post a comment.",
                            "inputSchema": {"type": "object", "properties": {}},
                        }
                    ]
                },
            }
        return {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        del method, params

    def close(self) -> None:
        return None


class TestNotificationsConfigAndFormatting(unittest.TestCase):
    """Tests for NotificationsConfig validation, URL redaction, and Slack/Teams/generic payload sanitization."""

    def test_config_validations_and_url_redaction(self) -> None:
        # Both URL and env rejected
        with self.assertRaises(ValueError):
            NotificationsConfig(
                approval_webhook_url="https://hooks.slack.com/services/T1/B1/tok1",
                approval_webhook_url_env="MY_WEBHOOK_ENV",
            )
        # Reserved or invalid env names rejected
        for bad_env in ("MELLYN_WEBHOOK", f"{LEGACY_ENV_PREFIX}WEBHOOK", "123_BAD"):
            with self.subTest(bad_env=bad_env), self.assertRaises(ValueError):
                NotificationsConfig(approval_webhook_url_env=bad_env)

        # Bad webhook URLs fail closed when loopback test flag is False
        for bad_url in (
            "http://hooks.slack.com/services/T1/B1/tok1",
            "https://127.0.0.1/webhook",
            "https://localhost/webhook",
            "https://printer.local/webhook",
            "https://user:pw@hooks.slack.com/services/T1/B1/tok1",
            "https://hooks.slack.com/services/T1/B1/tok1#frag",
        ):
            with self.subTest(bad_url=bad_url), self.assertRaises(ValueError):
                NotificationsConfig(approval_webhook_url=bad_url)

        # Invalid timeout / format fail closed
        for bad_timeout in (0.5, -1.0, 31.0, True, float("nan")):
            with self.assertRaises(ValueError):
                NotificationsConfig(timeout_seconds=bad_timeout)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            NotificationsConfig(webhook_format="discord")  # type: ignore[arg-type]

        # Console URL permits https domains and local loopback, rejects http public/IP/query/fragment/userinfo
        self.assertEqual(
            NotificationsConfig(console_base_url="https://console.corp.example/mellyn/").console_base_url,
            "https://console.corp.example/mellyn",
        )
        self.assertEqual(
            NotificationsConfig(console_base_url="http://127.0.0.1:8080/").console_base_url,
            "http://127.0.0.1:8080",
        )
        self.assertEqual(
            NotificationsConfig(console_base_url="http://localhost:3000/").console_base_url,
            "http://localhost:3000",
        )
        for bad_console in (
            "http://console.corp.example",
            "https://192.0.2.10",
            "https://console.corp.example?x=1",
            "https://console.corp.example#frag",
            "https://u:p@console.corp.example",
        ):
            with self.subTest(bad_console=bad_console), self.assertRaises(ValueError):
                NotificationsConfig(console_base_url=bad_console)

        # repr() redacts secret webhook path tokens completely
        secret_hook = _synth_value("https://hooks.slack.com/services/", "T00/B00/", "SECRET_WH_998877")
        cfg = NotificationsConfig(approval_webhook_url=secret_hook)
        rendered_repr = repr(cfg)
        self.assertIn("https://hooks.slack.com/[REDACTED]", rendered_repr)
        self.assertNotIn("SECRET_WH_998877", rendered_repr)
        self.assertNotIn("T00/B00", rendered_repr)
        self.assertTrue(cfg.enabled)

    def test_auto_format_detection_redaction_and_slack_mrkdwn_escaping(self) -> None:
        self.assertEqual(resolve_webhook_format("auto", "https://hooks.slack.com/services/a/b/c"), "slack")
        self.assertEqual(resolve_webhook_format("auto", "https://hooks.slack-gov.com/services/a/b/c"), "slack")
        self.assertEqual(resolve_webhook_format("auto", "https://acme.webhook.office.com/webhookb2/x"), "teams")
        self.assertEqual(resolve_webhook_format("auto", "https://prod.logic.azure.com:443/workflows/x"), "teams")
        self.assertEqual(resolve_webhook_format("auto", "https://alerts.corp.example/hook"), "generic")

        canary_val = _synth_value("MELLYN_CANARY_", "ALERT_4412")
        synth_api_key = _synth_value("sk-proj-", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4")
        injected_key = f"<https://evil.example|Click>_{canary_val}"
        args = {
            "body": f"ship {canary_val} and {synth_api_key}",
            injected_key: "top-secret-arg-value-never-sent",
        }
        pending = PendingApproval(
            approval_id="apr_demo12345678",
            session_id="ses_session99",
            mcp_server="github",
            tool_name="create_comment\x07",
            arguments=args,
            reasons=(f"Blocked candidate {synth_api_key} and <https://phish.example|Login> {canary_val}",),
            audit_id="aud_777",
        )
        summary = build_approval_alert_summary(
            pending,
            console_base_url="https://console.corp.example/",
            canary_tokens=(canary_val,),
        )
        self.assertEqual(summary.arguments_sha256, hash_arguments(args))
        self.assertEqual(summary.console_url, "https://console.corp.example/approvals/apr_demo12345678")

        for fmt_name in ("slack", "teams", "generic"):
            payload = format_webhook_payload(
                summary,
                fmt=fmt_name,  # type: ignore[arg-type]
                canary_tokens=(canary_val,),
            )
            serialized = json.dumps(payload)
            self.assertNotIn(canary_val, serialized)
            self.assertNotIn(synth_api_key, serialized)
            self.assertNotIn("top-secret-arg-value-never-sent", serialized)
            self.assertNotIn("\x07", serialized)
            self.assertIn("https://console.corp.example/approvals/apr_demo12345678", serialized)
            if fmt_name == "slack":
                self.assertIn("&lt;https://phish.example|Login&gt;", serialized)
                self.assertNotIn("<https://phish.example|Login>", serialized)


class TestApprovalWebhookDeliveryAndGatewayIntegration(unittest.TestCase):
    """Tests for webhook delivery, deduplication, redirect rejection, error resilience, and MCPGateway wiring."""

    def test_pending_approvals_dedup_gateway_async_and_fail_closed_delivery(self) -> None:
        receiver = _MockWebhookReceiver()
        receiver.start()
        try:
            secret_path = _synth_value("/wh/", "tok_live_4455")
            hook_url = f"{receiver.base_url}{secret_path}"
            cfg = NotificationsConfig(
                approval_webhook_url=hook_url,
                webhook_format="generic",
                console_base_url="http://127.0.0.1:8080",
                allow_insecure_loopback_for_tests=True,
            )
            notifier = ApprovalWebhookNotifier(cfg, canary_tokens=("MELLYN_CAN_1",))
            try:
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    policy = PolicyConfig(
                        allowed_mcp_servers=frozenset({"github"}),
                        tool_risk_tiers={"github/create_comment": RiskTier.HIGH},
                    )
                    authz = Authorizer(workspace_root=root, policy_config=policy)
                    approvals = PendingApprovals(authz, on_new_pending=notifier.notify_async)
                    gw = MCPGateway(
                        authorizer=authz,
                        servers={"github": _FakeHighDownstream("github")},
                        approvals=approvals,
                    )

                    # First HIGH call generates pending + async webhook; duplicate retry does not re-fire.
                    call_msg = {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": "github__create_comment", "arguments": {"secret_note": "private-val"}},
                    }
                    reply1 = gw.handle_message(call_msg)
                    self.assertIsNotNone(reply1)
                    if reply1 is not None:
                        self.assertEqual(reply1["error"]["code"], MELLYN_APPROVAL_REQUIRED)
                    reply2 = gw.handle_message({**call_msg, "id": 2})
                    self.assertIsNotNone(reply2)

                    self.assertTrue(receiver.state.event.wait(timeout=5.0))
                    notifier.close(timeout=2.0)

                    self.assertEqual(len(receiver.state.received), 1)
                    rec = receiver.state.received[0]
                    self.assertEqual(rec["path"], secret_path)
                    body = rec["payload"]
                    self.assertEqual(body["event"], "mellyn.approval_required")
                    self.assertEqual(body["mcp_server"], "github")
                    self.assertEqual(body["tool_name"], "create_comment")
                    # Key names are chosen by the agent too, so only the count leaves the host.
                    self.assertEqual(body["argument_count"], 1)
                    self.assertNotIn("secret_note", json.dumps(body))
                    self.assertEqual(body["arguments_sha256"], hash_arguments({"secret_note": "private-val"}))
                    self.assertNotIn("private-val", json.dumps(body))
                    self.assertEqual(body["console_url"], f"http://127.0.0.1:8080/approvals/{body['approval_id']}")
            finally:
                notifier.close(timeout=1.0)

            # Env-var webhook resolution + allowlist check + redirect/500 failure handling
            sample_pending = PendingApproval(
                approval_id="apr_test98765432",
                session_id="ses_1",
                mcp_server="github",
                tool_name="create_comment",
                arguments={"k": "v"},
                reasons=("Needs review.",),
                audit_id="aud_1",
            )
            env_name = _synth_value("TEST_WH_URL_", "ENV")
            env_cfg = NotificationsConfig(
                approval_webhook_url_env=env_name,
                webhook_host="127.0.0.1",
                allow_insecure_loopback_for_tests=True,
            )

            # Redirect -> rejected fail closed, redirect target never hit, secret path absent from stderr
            with receiver.state.lock:
                receiver.state.mode = "redirect"
            redir_notifier = ApprovalWebhookNotifier(env_cfg)
            try:
                err_buf = io.StringIO()
                with mock.patch.dict(os.environ, {env_name: hook_url}), contextlib.redirect_stderr(err_buf):
                    self.assertFalse(redir_notifier.deliver(sample_pending))
                self.assertEqual(receiver.state.redirect_hits, 0)
                self.assertNotIn(secret_path, err_buf.getvalue())
                self.assertIn("[REDACTED]", err_buf.getvalue())
            finally:
                redir_notifier.close()

            # HTTP 500 -> fails gracefully returning False without raising into caller
            with receiver.state.lock:
                receiver.state.mode = "error_500"
            err500_notifier = ApprovalWebhookNotifier(env_cfg)
            try:
                err_buf2 = io.StringIO()
                with mock.patch.dict(os.environ, {env_name: hook_url}), contextlib.redirect_stderr(err_buf2):
                    self.assertFalse(err500_notifier.deliver(sample_pending))
            finally:
                err500_notifier.close()

            # Domain missing from allowed_domains rejected fail closed before socket open
            denied_cfg = NotificationsConfig(
                approval_webhook_url="https://unlisted-hook.example/services/a/b/tok_hidden",
            )
            denied_notifier = ApprovalWebhookNotifier(
                denied_cfg,
                allowed_domains=frozenset({"hooks.slack.com"}),
            )
            try:
                err_buf3 = io.StringIO()
                with contextlib.redirect_stderr(err_buf3):
                    self.assertFalse(denied_notifier.deliver(sample_pending))
                self.assertNotIn("tok_hidden", err_buf3.getvalue())
            finally:
                denied_notifier.close()

            # Hook exception inside PendingApprovals.add never breaks queuing
            with tempfile.TemporaryDirectory() as tmp2:
                authz2 = Authorizer(workspace_root=Path(tmp2), policy_config=PolicyConfig())

                def _broken_hook(_pending: PendingApproval) -> None:
                    raise RuntimeError("boom")

                pa2 = PendingApprovals(authz2, on_new_pending=_broken_hook)
                sid = authz2.create_session()
                req = ToolCallRequest(sid, "send_email", {"to": "a@b.c"})
                auth_res = authz2.authorize(req)
                with contextlib.redirect_stderr(io.StringIO()):
                    created = pa2.add(req, auth_res)
                self.assertEqual(len(pa2.list()), 1)
                self.assertTrue(created.approval_id.startswith("apr_"))
        finally:
            receiver.stop()


class TestUnifiedNotificationsConfigAndSquid(unittest.TestCase):
    """Tests for [notifications] schema compilation, Squid allowlist sync, and TOML preservation."""

    def test_notifications_config_syncs_squid_and_survives_upsert(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg_path = root / "mellyn.toml"
            squid_path = root / "squid.conf"
            cfg_path.write_text(
                "\n".join(
                    [
                        "schema_version = 2",
                        "",
                        "[notifications]",
                        'approval_webhook_url_env = "SLACK_APPROVALS_WEBHOOK"',
                        'webhook_host = "hooks.slack.com"',
                        'webhook_format = "auto"',
                        'console_base_url = "https://console.corp.example"',
                        "timeout_seconds = 7.5",
                        "",
                        "[[servers]]",
                        'name = "local-ws"',
                        'transport = "stdio"',
                        'preset = "mcp-filesystem"',
                        "trusted = true",
                        'command = ["mcp-fs", "--root", "."]',
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            loaded = load_unified_config(cfg_path)
            self.assertEqual(loaded.notifications.approval_webhook_url_env, "SLACK_APPROVALS_WEBHOOK")
            self.assertEqual(loaded.notifications.console_base_url, "https://console.corp.example")
            self.assertEqual(loaded.notifications.timeout_seconds, 7.5)
            # The gateway may reach the webhook host; tools may not (it is not in the tool egress policy).
            self.assertNotIn("hooks.slack.com", loaded.policy.allowed_egress_domains)
            self.assertIn("hooks.slack.com", loaded.gateway_egress_domains)
            self.assertIn("SLACK_APPROVALS_WEBHOOK", loaded.secret_env_names)

            with contextlib.redirect_stdout(io.StringIO()):
                rc = egress_main(["--policy", str(cfg_path), "--output", str(squid_path)])
            self.assertEqual(rc, 0)
            self.assertIn("acl gateway_domains dstdomain hooks.slack.com", squid_path.read_text(encoding="utf-8"))

            pin_res = GatewayPinResult(
                server_name="local-ws",
                command=("mcp-fs", "--root", "."),
                preset="mcp-filesystem",
                trusted=True,
                tools=(),
                tools_sha256="d" * 64,
                warnings=(),
            )
            upsert_server_in_unified_toml(cfg_path, pin_res)
            reloaded = load_unified_config(cfg_path)
            self.assertEqual(reloaded.notifications.approval_webhook_url_env, "SLACK_APPROVALS_WEBHOOK")
            self.assertEqual(reloaded.notifications.webhook_host, "hooks.slack.com")
            self.assertEqual(reloaded.notifications.console_base_url, "https://console.corp.example")

    def test_notifications_fail_closed_toml_rejections(self) -> None:
        base_srv = 'schema_version = 2\n[[servers]]\nname = "ws"\ntransport = "stdio"\ncommand = ["mcp-fs"]\n'
        bad_blocks = [
            '[notifications]\nwebhook_secret = "raw"\n',
            '[notifications]\nsigning_secret = "raw"\n',
            '[notifications]\nbot_token = "raw"\n',
            '[notifications]\nslack_token = "raw"\n',
            '[notifications]\napproval_webhook_url = "http://hooks.slack.com/services/x"\n',
            '[notifications]\napproval_webhook_url = "https://127.0.0.1/hook"\n',
            '[notifications]\napproval_webhook_url_env = "MELLYN_SECRET"\n',
            '[notifications]\napproval_webhook_url = "https://hooks.slack.com/x"\napproval_webhook_url_env = "WH"\n',
            "[notifications]\nallow_insecure_loopback_for_tests = true\n",
            # The webhook URL is a credential: never in the file, even when valid.
            '[notifications]\napproval_webhook_url = "https://hooks.slack.com/services/T/B/x"\n',
            # The env form must declare the one host alerts may go to, and the host needs the env form.
            '[notifications]\napproval_webhook_url_env = "WH"\n',
            '[notifications]\nwebhook_host = "hooks.slack.com"\n',
        ]
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "bad_notif.toml"
            for idx, block in enumerate(bad_blocks):
                cfg_path.write_text(f"{block}\n{base_srv}", encoding="utf-8")
                with self.subTest(case=idx), self.assertRaises((PolicyLoadError, ValueError)):
                    load_unified_config(cfg_path)


class TestViewerDeepLinkSpaRoute(unittest.TestCase):
    """Tests that ViewerHTTPServer serves SPA HTML on `/approvals/apr_...` deep links while 404ing missing assets."""

    def test_viewer_serves_spa_index_for_approval_deep_link(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            static_dir = Path(tmp)
            (static_dir / "index.html").write_text("<!doctype html><html><body>Mellyn Console SPA</body></html>")
            (static_dir / "app.js").write_text("console.log('ok');")

            pepper = _synth_value("p_" * 20)
            v_key = _synth_value("viewer_", "k1")
            a_key = _synth_value("approver_", "k2")
            v_creds = CredentialConfig(
                pepper=pepper,
                digests={Role.VIEWER: key_digest(v_key, pepper)},
                roles=frozenset({Role.VIEWER}),
            )
            a_creds = CredentialConfig(
                pepper=pepper,
                digests={Role.APPROVER: key_digest(a_key, pepper)},
                roles=frozenset({Role.APPROVER}),
            )
            srv = ViewerHTTPServer(
                host="127.0.0.1",
                port=0,
                viewer_credentials=v_creds,
                approver_credentials=a_creds,
                static_dir=static_dir,
            )
            srv.start_in_background()
            try:
                opener = build_safe_opener(bypass_ambient_proxy=True)
                deep_url = f"{srv.url}/approvals/apr_demo12345678"
                with opener.open(deep_url, timeout=5.0) as resp:  # noqa: S310 - loopback test viewer URL
                    self.assertEqual(resp.status, 200)
                    html = resp.read().decode("utf-8")
                self.assertIn("Mellyn Console SPA", html)

                for missing_path in ("/approvals/missing.js", "/approvals/../secret.txt"):
                    req = urllib.request.Request(f"{srv.url}{missing_path}", method="GET")  # noqa: S310 - loopback test
                    try:
                        with opener.open(req, timeout=5.0):  # noqa: S310 - loopback test
                            self.fail(f"Expected 404 for {missing_path}")
                    except urllib.error.HTTPError as exc:
                        code = exc.code
                        exc.close()
                        self.assertEqual(code, 404)
            finally:
                srv.shutdown()
                srv.server_close()


if __name__ == "__main__":
    unittest.main()
