"""Regression tests for review fixes to approval webhooks.

- The webhook and identity-provider hosts are for the gateway only: they never join the tool egress policy.
- Secret environment variables the config names are withheld from downstream MCP servers.
- Alerts carry no agent-chosen text that a chat client could render as a link, and no argument key names.
- The webhook URL lives in the environment, may only reach the declared host, and alerts are rate limited.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
for _import_dir in (REPO_ROOT, REPO_ROOT / "backend", REPO_ROOT / "src"):
    if str(_import_dir) not in sys.path:
        sys.path.insert(0, str(_import_dir))

from mellyn import http_gateway, mcp_gateway  # noqa: E402
from mellyn.approvals import PendingApproval  # noqa: E402
from mellyn.egress import EgressValidator  # noqa: E402
from mellyn.egress_proxy import generate_squid_config  # noqa: E402
from mellyn.mcp_gateway import downstream_environment  # noqa: E402
from mellyn.notifications import (  # noqa: E402
    ApprovalWebhookNotifier,
    NotificationsConfig,
    build_approval_alert_summary,
    format_webhook_payload,
)
from mellyn.policy_loader import PolicyLoadError  # noqa: E402
from mellyn.unified_config import parse_unified_dict  # noqa: E402

from tests.test_approval_webhooks import _MockWebhookReceiver  # noqa: E402

ATTACKER = "https://hooks.slack.com/services/" + "TATTACKER/BATTACKER/" + "exfil"
WEBHOOK_ENV = "APPROVALS_" + "WEBHOOK_URL"
CLIENT_SECRET_ENV = "REMOTE_" + "CLIENT_SECRET"


def _config(extra: str = "") -> str:
    return f"""
schema_version = 2
[notifications]
approval_webhook_url_env = "{WEBHOOK_ENV}"
webhook_host = "hooks.slack.com"
{extra}
[[servers]]
name = "web"
transport = "stdio"
preset = "mcp-fetch"
command = ["mcp-fetch"]

[[servers]]
name = "remote"
transport = "streamable-http"
url = "https://mcp.remote.example/mcp"
oauth = {{ flow = "client_credentials", allowed_authorization_servers = ["https://auth.remote.example"], \
client_id = "mellyn", client_secret_env = "{CLIENT_SECRET_ENV}", \
token_endpoint = "https://auth.remote.example/token" }}
"""


def _pending(**overrides: Any) -> PendingApproval:
    fields: dict[str, Any] = {
        "approval_id": "apr_0123456789abcdef",
        "session_id": "ses_1",
        "mcp_server": "notes",
        "tool_name": "write_note",
        "arguments": {"path": "notes.txt"},
        "reasons": ("Medium-risk tool call in a tainted session requires human approval.",),
        "audit_id": "aud_1",
    }
    fields.update(overrides)
    return PendingApproval(**fields)


class TestGatewayHostsStayOutOfToolEgress(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def load(self, text: str) -> Any:
        return parse_unified_dict(tomllib.loads(text), base_dir=self.root, config_path=self.root / "mellyn.toml")

    def test_a_tool_cannot_reach_another_webhook_on_the_shared_host(self) -> None:
        extra = '[auth]\nmode = "oidc"\nissuer = "https://idp.corp.example"\naudience = "https://mcp.corp.example"\n'
        unified = self.load(_config(extra))
        self.assertEqual(unified.gateway_egress_domains, frozenset({"hooks.slack.com", "idp.corp.example"}))
        self.assertNotIn("hooks.slack.com", unified.policy.allowed_egress_domains)
        self.assertNotIn("idp.corp.example", unified.policy.allowed_egress_domains)

        # Before the fix this passed: any tool could post to an attacker's own webhook on hooks.slack.com.
        allowed, _ = EgressValidator(unified.policy.allowed_egress_domains).validate_url(ATTACKER)
        self.assertFalse(allowed)

        squid = generate_squid_config(unified.policy, gateway_domains=unified.gateway_egress_domains)
        self.assertIn("acl gateway_domains dstdomain hooks.slack.com", squid)
        self.assertNotIn("dstdomain .hooks.slack.com", squid)  # exact host, not every subdomain


class TestSecretsAreWithheldFromDownstreamServers(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "ws"
        self.workspace.mkdir()
        self.config = self.root / "mellyn.toml"
        # OIDC so `serve` needs no agent key and gets as far as launching its servers.
        oidc = '[auth]\nmode = "oidc"\nissuer = "https://idp.corp.example"\naudience = "https://mcp.corp.example"\n'
        self.config.write_text(_config(oidc), encoding="utf-8")

    def test_named_secrets_are_dropped_from_the_child_environment(self) -> None:
        unified = parse_unified_dict(tomllib.loads(_config()), base_dir=self.root, config_path=self.config)
        self.assertEqual(set(unified.secret_env_names), {WEBHOOK_ENV, CLIENT_SECRET_ENV})
        parent = {WEBHOOK_ENV: "https://hooks.slack.com/x", CLIENT_SECRET_ENV.lower(): "s", "PATH": "/bin"}
        child = downstream_environment(parent, secret_names=unified.secret_env_names)
        self.assertEqual(child, {"PATH": "/bin"})  # matched case-insensitively, as Windows treats names

    def _recorded_secret_names(self, main: Any, module: Any, argv: list[str]) -> Any:
        seen: dict[str, Any] = {}

        def record(*_args: Any, **kwargs: Any) -> Any:
            seen.update(kwargs)
            raise RuntimeError("stop after recording the downstream environment")

        with (
            mock.patch.object(module, "StdioDownstream", side_effect=record),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            main(argv)
        return seen.get("secret_env_names")

    def test_both_gateways_pass_the_secret_names_to_their_servers(self) -> None:
        argv = ["--config", str(self.config), "--workspace", str(self.workspace)]
        audit = ["--audit-log", str(self.root / "audit.jsonl")]
        for label, main, module in (
            ("stdio", mcp_gateway.main, mcp_gateway),
            ("serve", http_gateway.main, http_gateway),
        ):
            with self.subTest(label):
                names = self._recorded_secret_names(main, module, [*argv, *audit])
                # Before the fix nothing was withheld: servers inherited the webhook URL and OAuth secrets.
                self.assertIsNotNone(names)
                self.assertEqual(set(names or ()), {WEBHOOK_ENV, CLIENT_SECRET_ENV})


class TestAlertsCarryNoAgentMarkup(unittest.TestCase):
    def test_key_names_and_tool_names_cannot_become_links(self) -> None:
        leaked_key = "db_" + "password=" + "Hunter2" + "-9f81e2"  # built at runtime so secret scanners stay quiet
        pending = _pending(
            tool_name="[Approve](https://atk.example/b)",
            arguments={"[Approve: verified](https://atk.example/a)": 1, leaked_key: 2},
        )
        summary = build_approval_alert_summary(pending, console_base_url="https://console.corp.example")
        for fmt in ("teams", "slack", "generic"):
            with self.subTest(fmt=fmt):
                text = json.dumps(format_webhook_payload(summary, fmt=fmt))
                # Before the fix the key reached the Teams card verbatim and rendered as a clickable link.
                self.assertNotIn("atk.example", text)
                self.assertNotIn("](", text)
                self.assertNotIn("Hunter2", text)
                self.assertIn("https://console.corp.example/approvals/apr_0123456789abcdef", text)
        generic = format_webhook_payload(summary, fmt="generic")
        self.assertEqual(generic["argument_count"], 2)
        self.assertNotIn("argument_keys", generic)

    def test_teams_reasons_cannot_carry_links(self) -> None:
        pending = _pending(reasons=("See [the runbook](https://atk.example/r) or <b>this</b>.",))
        payload = format_webhook_payload(build_approval_alert_summary(pending), fmt="teams")
        reasons = payload["attachments"][0]["content"]["body"][2]["text"]
        self.assertNotIn("](", reasons)
        self.assertNotIn("<b>", reasons)
        self.assertNotIn("https://", reasons)


class TestWebhookDestinationAndRate(unittest.TestCase):
    def test_the_url_must_point_at_the_declared_host(self) -> None:
        receiver = _MockWebhookReceiver()
        receiver.start()
        self.addCleanup(receiver.stop)
        cfg = NotificationsConfig(
            approval_webhook_url_env=WEBHOOK_ENV, webhook_host="localhost", allow_insecure_loopback_for_tests=True
        )
        notifier = ApprovalWebhookNotifier(cfg)
        self.addCleanup(notifier.close)
        err = io.StringIO()
        # The environment points somewhere other than the declared host: refused before connecting.
        with mock.patch.dict(os.environ, {WEBHOOK_ENV: f"{receiver.base_url}/hook"}), contextlib.redirect_stderr(err):
            self.assertFalse(notifier.deliver(_pending()))
        self.assertEqual(receiver.state.received, [])
        self.assertIn("webhook_host", err.getvalue())

        ok_cfg = NotificationsConfig(
            approval_webhook_url_env=WEBHOOK_ENV, webhook_host="127.0.0.1", allow_insecure_loopback_for_tests=True
        )
        ok_notifier = ApprovalWebhookNotifier(ok_cfg)
        self.addCleanup(ok_notifier.close)
        with mock.patch.dict(os.environ, {WEBHOOK_ENV: f"{receiver.base_url}/hook"}):
            self.assertTrue(ok_notifier.deliver(_pending()))

    def test_the_url_never_comes_from_the_config_file(self) -> None:
        text = _config().replace(
            f'approval_webhook_url_env = "{WEBHOOK_ENV}"', 'approval_webhook_url = "https://hooks.slack.com/x/y/z"'
        )
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(PolicyLoadError) as ctx:
            parse_unified_dict(tomllib.loads(text), base_dir=Path(tmp), config_path=Path(tmp) / "m.toml")
        self.assertIn("environment variable", str(ctx.exception))
        with self.assertRaises(ValueError):
            NotificationsConfig(approval_webhook_url_env=WEBHOOK_ENV)  # no declared host

    def test_alerts_are_rate_limited(self) -> None:
        cfg = NotificationsConfig(approval_webhook_url_env=WEBHOOK_ENV, webhook_host="hooks.slack.com")
        notifier = ApprovalWebhookNotifier(cfg, max_alerts_per_minute=2)
        self.addCleanup(notifier.close)
        with mock.patch.object(notifier, "deliver", return_value=True), contextlib.redirect_stderr(io.StringIO()):
            results = [notifier.notify_async(_pending(approval_id=f"apr_{i:016d}")) for i in range(4)]
            notifier.close()  # drain while `deliver` is still mocked
        self.assertEqual(results, [True, True, False, False])


if __name__ == "__main__":
    unittest.main()
