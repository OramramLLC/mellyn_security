"""Regression tests for review fixes to the inbound HTTP gateway and OIDC resource server.

- An agent's /mcp token can never approve held calls, and an approver token can never call /mcp.
- Approvers are chosen by `sub` or group, never by an email claim.
- A canary leak over HTTP contains the identity that sent it, not every caller sharing the downstream servers.
- `mellyn serve` starts, and passes the downstream account's HOME and USER the right way round.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
for _import_dir in (REPO_ROOT, REPO_ROOT / "backend", REPO_ROOT / "src"):
    if str(_import_dir) not in sys.path:
        sys.path.insert(0, str(_import_dir))

from mellyn import http_gateway  # noqa: E402
from mellyn.approvals import ApprovalHTTPServer, PendingApprovals  # noqa: E402
from mellyn.authorizer import Authorizer  # noqa: E402
from mellyn.http_gateway import PrincipalContainedError, StreamableHttpGatewayServer  # noqa: E402
from mellyn.mcp_gateway import MELLYN_AAD_CONTAINED, StdioDownstream, initialize_downstream  # noqa: E402
from mellyn.oauth_resource import AuthConfig, OAuthResourceValidator  # noqa: E402
from mellyn.policy_loader import parse_policy_dict  # noqa: E402
from mellyn.scanner import ScannerConfig  # noqa: E402

FAKE_SERVER = REPO_ROOT / "tests" / "fixtures" / "fake_mcp_server.py"
CANARY = "MELLYN-" + "canary-" + "7f3a9c21d4e8b605"
ISSUER, AUDIENCE = "https://idp.example.com", "https://mellyn.example/mcp"

_HAS_CRYPTOGRAPHY = importlib.util.find_spec("cryptography") is not None
_REQUIRE = os.environ.get("MELLYN_REQUIRE_API_TESTS") == "1"
_needs_cryptography = unittest.skipUnless(
    _HAS_CRYPTOGRAPHY or _REQUIRE, "cryptography is not installed (it only signs test tokens)"
)

_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _http(url: str, token: str, *, method: str = "GET", body: dict[str, Any] | None = None, sid: str = "") -> int:
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    if sid:
        headers["Mcp-Session-Id"] = sid
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)  # noqa: S310 - loopback
    try:
        with _NO_PROXY.open(req, timeout=10) as resp:
            return int(resp.status)
    except urllib.error.HTTPError as exc:
        with exc:
            return int(exc.code)


class TestApproverConfigValidation(unittest.TestCase):
    def _oidc(self, **extra: Any) -> AuthConfig:
        return AuthConfig(mode="oidc", issuer=ISSUER, audience=AUDIENCE, required_scopes=("mcp:use",), **extra)

    def test_listed_approvers_need_a_separate_approver_scope(self) -> None:
        # Before the fix, listing approvers without a scope made the agent's own /mcp token an approver token.
        for extra in ({"approver_subjects": ("alice",)}, {"approver_groups": ("sec",)}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                self._oidc(**extra)
        with self.assertRaises(ValueError):
            self._oidc(approver_scopes=("mcp:use",))  # the agent scope cannot double as the approver scope
        self._oidc(approver_scopes=("mcp:approve",), approver_subjects=("alice",))


@_needs_cryptography
class TestTokenRoleSeparation(unittest.TestCase):
    """One token, one role: what the agent's MCP client holds cannot approve, and an approver token cannot call."""

    @classmethod
    def setUpClass(cls) -> None:
        from cryptography.hazmat.primitives.asymmetric import rsa

        from tests.test_http_gateway_and_oidc import _rsa_to_jwk, _sign_rsa_jwt

        cls._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls._jwk = _rsa_to_jwk(cls._key.public_key(), kid="k1")
        cls._sign = staticmethod(_sign_rsa_jwt)

    def setUp(self) -> None:
        self.auth = AuthConfig(
            mode="oidc",
            issuer=ISSUER,
            audience=AUDIENCE,
            required_scopes=("mcp:use",),
            approver_scopes=("mcp:approve",),
            approver_subjects=("alice",),
            approver_groups=("sec-approvers",),
        )
        self.validator = OAuthResourceValidator(self.auth)
        self.validator._get_keys = lambda *, kid: (self._jwk,)  # type: ignore[method-assign]
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def token(self, sub: str, scope: str, **claims: Any) -> str:
        now = int(time.time())
        body = {"iss": ISSUER, "aud": AUDIENCE, "sub": sub, "scope": scope, "iat": now, "exp": now + 600, **claims}
        return str(self._sign(body, self._key, kid="k1"))

    def test_only_a_listed_approvers_approver_token_reaches_the_approval_server(self) -> None:
        server = ApprovalHTTPServer(
            PendingApprovals(Authorizer(workspace_root=self.root, session_ttl_seconds=None)),
            oidc_validator=self.validator,
        )
        server.start_in_background()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        pending = f"{server.url}/v1/pending"
        cases = {
            # Before the fix: 200, so an agent process holding its /mcp token could approve its own held calls.
            "listed approver's agent token": (self.token("alice", "mcp:use"), 403),
            "listed approver's approver token": (self.token("alice", "mcp:approve"), 200),
            "approver group member": (self.token("carol", "mcp:approve", groups=["sec-approvers"]), 200),
            "approver scope, not listed": (self.token("bob", "mcp:approve"), 403),
            # Before the fix: 200, since a verified email matching an approver_subjects entry granted approval.
            "approver's email on another sub": (
                self.token("mallory", "mcp:approve", email="alice", email_verified=True),
                403,
            ),
        }
        for label, (tok, expected) in cases.items():
            with self.subTest(label):
                self.assertEqual(_http(pending, tok), expected)

    def test_an_approver_token_cannot_call_mcp(self) -> None:
        policy = parse_policy_dict({"schema_version": 1, "allowed_mcp_servers": ["notes"]})
        authorizer = Authorizer(workspace_root=self.root, policy_config=policy, session_ttl_seconds=None)
        downstream = StdioDownstream("notes", [sys.executable, str(FAKE_SERVER)])
        self.addCleanup(downstream.close)
        gateway = StreamableHttpGatewayServer(
            authorizer=authorizer, servers={"notes": downstream}, auth_config=self.auth, oidc_validator=self.validator
        )
        gateway.start_in_background()
        self.addCleanup(gateway.server_close)
        self.addCleanup(gateway.shutdown)
        init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        self.assertEqual(_http(gateway.url, self.token("alice", "mcp:approve"), method="POST", body=init), 403)
        both = self.token("alice", "mcp:use mcp:approve")  # carrying the agent scope too does not make it an agent
        self.assertEqual(_http(gateway.url, both, method="POST", body=init), 403)
        initialize_downstream(downstream)
        self.assertEqual(_http(gateway.url, self.token("alice", "mcp:use"), method="POST", body=init), 200)


class TestAadContainsOneIdentity(unittest.TestCase):
    """Real stdio server shared by two identities; one leaks a canary."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        policy = parse_policy_dict(
            {
                "schema_version": 1,
                "allowed_mcp_servers": ["notes"],
                "trusted_mcp_servers": ["notes"],
                "tool_risk_tiers": {"notes/read_note": "low"},
                "tool_capabilities": {"notes/read_note": {"pure": True}},
            }
        )
        authorizer = Authorizer(workspace_root=Path(self._tmp.name), policy_config=policy, session_ttl_seconds=None)
        self.downstream = StdioDownstream("notes", [sys.executable, str(FAKE_SERVER)])
        self.addCleanup(self.downstream.close)
        with contextlib.redirect_stderr(io.StringIO()):
            initialize_downstream(self.downstream)
        self.server = StreamableHttpGatewayServer(
            authorizer=authorizer,
            servers={"notes": self.downstream},
            scanner_config=ScannerConfig(canary_tokens=(CANARY,)),
        )
        self.addCleanup(self.server.server_close)

    def call(self, entry: Any, text: str) -> dict[str, Any]:
        message = {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "notes__read_note", "arguments": {"q": text}},
        }
        with entry.lock, contextlib.redirect_stderr(io.StringIO()):
            reply = entry.gateway.handle_message(message)
        self.assertIsNotNone(reply)
        return dict(reply or {})

    def test_a_canary_from_one_identity_leaves_the_others_running(self) -> None:
        _, alice = self.server.create_session_entry(owner_subject="oidc:idp|alice")
        alice_other_sid, alice_other = self.server.create_session_entry(owner_subject="oidc:idp|alice")
        _, bob = self.server.create_session_entry(owner_subject="oidc:idp|bob")
        for entry in (alice, alice_other, bob):
            with entry.lock, contextlib.redirect_stderr(io.StringIO()):
                entry.gateway.handle_message({"jsonrpc": "2.0", "id": 0, "method": "tools/list", "params": {}})
        self.assertIn("result", self.call(bob, "hello"))

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            leak = self.call(alice, CANARY)
        self.assertEqual(leak["error"]["code"], MELLYN_AAD_CONTAINED)

        # Before the fix the shared server was killed, so Bob's next call failed and nothing restarted it.
        self.assertIsNone(self.downstream.proc.poll())
        self.assertIn("result", self.call(bob, "hello"))

        # Alice is cut off everywhere: her other session, new sessions, and resuming one.
        self.assertIn("error", self.call(alice_other, "hello"))
        self.assertTrue(self.server.is_principal_contained("oidc:idp|alice"))
        self.assertFalse(self.server.is_principal_contained("oidc:idp|bob"))
        with self.assertRaises(PrincipalContainedError):
            self.server.create_session_entry(owner_subject="oidc:idp|alice")
        entry, status, _ = self.server.resolve_session_entry(alice_other_sid, owner_subject="oidc:idp|alice")
        self.assertIsNone(entry)
        self.assertEqual(int(status), 403)


class TestServeStarts(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "ws"
        self.workspace.mkdir()
        self.config = self.root / "mellyn.toml"
        command = json.dumps([sys.executable, str(FAKE_SERVER)])
        self.config.write_text(
            "\n".join(
                [
                    "schema_version = 2",
                    "[auth]",
                    'mode = "oidc"',
                    f'issuer = "{ISSUER}"',
                    f'audience = "{AUDIENCE}"',
                    'required_scopes = ["mcp:use"]',
                    "[[servers]]",
                    'name = "notes"',
                    'transport = "stdio"',
                    f"command = {command}",
                    "",
                ]
            ),
            encoding="utf-8",
        )

    def argv(self, *extra: str) -> list[str]:
        return [
            "--config",
            str(self.config),
            "--workspace",
            str(self.workspace),
            "--audit-log",
            str(self.root / "audit.jsonl"),
            "--port",
            "0",
            "--approval-port",
            "0",
            *extra,
        ]

    @unittest.skipIf(os.name == "posix" and os.geteuid() == 0, "as root, serve rightly requires --gateway-user")
    def test_serve_reaches_listening(self) -> None:
        # A real file: the downstream server process inherits the gateway's stderr.
        with (
            open(self.root / "stderr.txt", "w+", encoding="utf-8") as err,
            mock.patch.object(StreamableHttpGatewayServer, "serve_forever", side_effect=KeyboardInterrupt),
            contextlib.redirect_stderr(err),
        ):
            rc = http_gateway.main(self.argv())
            err.seek(0)
            output = err.read()
        # Before the fix: a TypeError from check_privilege_separation before anything started.
        self.assertEqual(rc, 0, msg=output)
        self.assertIn("gateway listening on http://127.0.0.1:", output)

    @unittest.skipUnless(os.name == "posix", "--downstream-user is POSIX-only")
    def test_downstream_servers_get_the_accounts_home_and_name(self) -> None:
        seen: dict[str, Any] = {}

        def record(*_args: Any, **kwargs: Any) -> Any:
            seen.update(kwargs)
            raise RuntimeError("stop after recording the downstream account")

        account = (1234, 1234, "mcp-runner", "/home/mcp-runner")
        with (
            mock.patch.object(http_gateway, "check_privilege_separation"),
            mock.patch.object(http_gateway, "_resolve_posix_account", return_value=account),
            mock.patch.object(http_gateway, "StdioDownstream", side_effect=record),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            rc = http_gateway.main(self.argv("--downstream-user", "mcp-runner"))
        self.assertEqual(rc, 2)
        # Before the fix these were swapped: HOME=mcp-runner and USER=/home/mcp-runner.
        self.assertEqual(seen["child_home"], "/home/mcp-runner")
        self.assertEqual(seen["child_username"], "mcp-runner")
        self.assertEqual((seen["user"], seen["group"]), (1234, 1234))


if __name__ == "__main__":
    unittest.main()
