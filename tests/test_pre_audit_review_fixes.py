"""Regression tests for the review of the pre-audit hardening round (2026-11-27)."""

from __future__ import annotations

import ast
import importlib.util
import json
import secrets
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
for _import_dir in (REPO_ROOT, REPO_ROOT / "src"):
    if str(_import_dir) not in sys.path:
        sys.path.insert(0, str(_import_dir))

from mellyn.approval_relay import ApprovalRelayServer  # noqa: E402
from mellyn.approvals import ApprovalHTTPServer, PendingApprovals  # noqa: E402
from mellyn.authorizer import Authorizer  # noqa: E402
from mellyn.core.strict_input import (  # noqa: E402
    MAX_JSON_DEPTH,
    StrictJsonError,
    parse_content_length,
    strict_json_loads,
)
from mellyn.credentials import CredentialConfig, Role, key_digest  # noqa: E402
from mellyn.egress_proxy import BLOCKED_DESTINATION_CIDRS  # noqa: E402
from mellyn.gateway_config import CODE_INJECTION_ENV_NAMES  # noqa: E402
from mellyn.http_downstream import _strict_json_loads as http_strict_json_loads  # noqa: E402
from mellyn.mcp_gateway import downstream_environment  # noqa: E402
from mellyn.policy_loader import PolicyLoadError  # noqa: E402
from mellyn.unified_config import parse_unified_dict  # noqa: E402

HAS_FASTAPI = all(importlib.util.find_spec(name) is not None for name in ("fastapi", "httpx"))
SRC = REPO_ROOT / "src" / "mellyn"
DEEP_JSON = b"[" * 8000 + b"]" * 8000  # 16 000 bytes: under every body cap, far over the recursion limit


def _approver_credentials() -> tuple[CredentialConfig, str]:
    pepper, key = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    creds = CredentialConfig.from_env(
        {"MELLYN_API_KEY_PEPPER": pepper, "MELLYN_APPROVER_KEY_DIGEST": key_digest(key, pepper)},
        roles=frozenset({Role.APPROVER}),
    )
    return creds, key


def _raw_request(port: int, raw: bytes, *, timeout: float = 5.0) -> bytes:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
            sock.sendall(raw)
            chunks: list[bytes] = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
            return b"".join(chunks)
    except OSError:
        return b""


def _trickle_forever(port: int, stop: threading.Event) -> None:
    """Start a request and never finish it: one header line every 0.4 s keeps the per-read idle timeout happy."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5.0) as sock:
            sock.sendall(b"GET /v1/pending HTTP/1.1\r\n")
            while not stop.is_set():
                sock.sendall(b"X-Slow: a\r\n")
                stop.wait(0.4)
    except OSError:
        return


class TestStrictInputParsers(unittest.TestCase):
    def test_content_length_accepts_only_ascii_digits(self) -> None:
        for good, value in (("16", 16), (" 16\t", 16), (b"16", 16), ("0", 0)):
            self.assertEqual(parse_content_length(good), value)
        for bad in ("1_6", "+16", "-1", "\u0661\u0666", "0x10", "", "1 6", b"\xff", "1" * 19):
            with self.subTest(value=bad):
                self.assertIsNone(parse_content_length(bad))

    def test_strict_json_rejects_duplicates_constants_and_deep_nesting(self) -> None:
        self.assertEqual(strict_json_loads(b'{"a": [1, 2.5]}'), {"a": [1, 2.5]})
        for bad in ('{"a": 1, "a": 2}', '{"a": 1, "\\u0061": 2}', "[NaN]", "[Infinity]", "[-Infinity]", DEEP_JSON):
            with self.subTest(value=bad[:20]):
                with self.assertRaises(StrictJsonError):
                    strict_json_loads(bad)
        with self.assertRaises(json.JSONDecodeError) as ctx:
            strict_json_loads("{")
        self.assertNotIsInstance(ctx.exception, StrictJsonError)

    def test_depth_limit_is_exact_and_ignores_brackets_in_strings(self) -> None:
        self.assertEqual(MAX_JSON_DEPTH, 128)
        self.assertIsInstance(strict_json_loads("[" * 128 + "]" * 128), list)
        with self.assertRaises(StrictJsonError):
            strict_json_loads("[" * 129 + "]" * 129)
        with self.assertRaises(StrictJsonError):
            strict_json_loads('{"a":' * 129 + "1" + "}" * 129)
        brackets_in_strings = json.dumps({"s": "[" * 500, "t": 'a\\"[{' * 200, "u": ["]" * 300]})
        self.assertEqual(strict_json_loads(brackets_in_strings), json.loads(brackets_in_strings))

    def test_http_downstream_uses_the_shared_parser(self) -> None:
        self.assertIs(http_strict_json_loads, strict_json_loads)
        with self.assertRaises(ValueError):
            http_strict_json_loads(DEEP_JSON.decode())

    def test_only_one_strict_json_copy_in_the_reviewed_modules(self) -> None:
        for module in ("api.py", "approvals.py", "http_downstream.py"):
            tree = ast.parse((SRC / module).read_text(encoding="utf-8"))
            defined = {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
            with self.subTest(module=module):
                self.assertFalse(defined & {"_strict_json_loads", "_reject_json_constant", "_StrictJsonError"})

    def test_strict_input_is_stdlib_only(self) -> None:
        tree = ast.parse((SRC / "core" / "strict_input.py").read_text(encoding="utf-8"))
        imported = {
            (node.module or "").split(".")[0] if isinstance(node, ast.ImportFrom) else alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertLessEqual(imported, {"__future__", "json", "re", "typing"})


class TestApprovalRequestDeadline(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.creds, self.key = _approver_credentials()
        self.approvals = PendingApprovals(Authorizer(workspace_root=Path(self._tmp.name)))
        self.stop = threading.Event()
        self.addCleanup(self.stop.set)

    def _start(self, server: ApprovalHTTPServer | ApprovalRelayServer) -> int:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1]

    def _legit_get(self, port: int) -> bytes:
        return _raw_request(
            port,
            (
                f"GET /v1/pending HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Mellyn-API-Key: {self.key}\r\n"
                "Connection: close\r\n\r\n"
            ).encode(),
        )

    def _assert_trickling_clients_cannot_hold_every_slot(self, port: int) -> None:
        for _ in range(2):
            threading.Thread(target=_trickle_forever, args=(port, self.stop), daemon=True).start()
        time.sleep(0.6)
        self.assertEqual(self._legit_get(port), b"", "both slots should be taken while the trickles are fresh")
        time.sleep(1.6)  # past the 1.5 s total deadline, while the trickles are still sending
        self.assertTrue(self._legit_get(port).startswith(b"HTTP/1.0 200"))

    def test_approval_server_frees_slots_at_the_deadline(self) -> None:
        server = ApprovalHTTPServer(self.approvals, self.creds, max_connections=2, request_deadline_seconds=1.5)
        self._assert_trickling_clients_cannot_hold_every_slot(self._start(server))

    def test_relay_frees_slots_at_the_deadline(self) -> None:
        upstream = ApprovalHTTPServer(self.approvals, self.creds)
        upstream_port = self._start(upstream)
        relay = ApprovalRelayServer(
            listen_host="127.0.0.1",
            listen_port=0,
            upstream_host="127.0.0.1",
            upstream_port=upstream_port,
            max_connections=2,
            request_deadline_seconds=1.5,
        )
        self._assert_trickling_clients_cannot_hold_every_slot(self._start(relay))

    def test_deadline_must_be_positive(self) -> None:
        for bad in (0, -1.0):
            with self.subTest(deadline=bad):
                with self.assertRaises(ValueError):
                    ApprovalHTTPServer(self.approvals, self.creds, request_deadline_seconds=bad)

    def test_approval_server_rejects_deep_json_and_odd_content_length(self) -> None:
        port = self._start(ApprovalHTTPServer(self.approvals, self.creds))
        head = (
            f"POST /v1/pending/apr_12345678/approve HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Mellyn-API-Key: {self.key}\r\n"
            "Connection: close\r\n"
        )
        deep = _raw_request(port, (head + f"Content-Length: {len(DEEP_JSON)}\r\n\r\n").encode() + DEEP_JSON)
        self.assertTrue(deep.startswith(b"HTTP/1.0 400"), deep[:40])
        odd = _raw_request(port, (head + "Content-Length: 1_6\r\n\r\n").encode() + b"x" * 16)
        self.assertTrue(odd.startswith(b"HTTP/1.0 400"), odd[:40])
        self.assertTrue(self._legit_get(port).startswith(b"HTTP/1.0 200"), "server must still be serving")


@unittest.skipUnless(HAS_FASTAPI, "mellyn.api needs fastapi and httpx")
class TestApiMiddlewareReviewFixes(unittest.TestCase):
    def setUp(self) -> None:
        from fastapi.testclient import TestClient

        from mellyn.api import _StrictJsonBodyLimitMiddleware, create_app

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        pepper, self.agent_key = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        creds = CredentialConfig.from_env(
            {
                "MELLYN_API_KEY_PEPPER": pepper,
                "MELLYN_AGENT_KEY_DIGEST": key_digest(self.agent_key, pepper),
                "MELLYN_APPROVER_KEY_DIGEST": key_digest(secrets.token_urlsafe(32), pepper),
            }
        )
        self.app = create_app(Path(self._tmp.name), credentials=creds)
        self.middleware_cls = _StrictJsonBodyLimitMiddleware
        self.client = TestClient(self.app, raise_server_exceptions=False)

    def test_deep_json_is_a_400_with_or_without_a_key(self) -> None:
        for label, headers in (
            ("no key", {"Content-Type": "application/json"}),
            ("agent key", {"Content-Type": "application/json", "X-Mellyn-API-Key": self.agent_key}),
        ):
            with self.subTest(label):
                resp = self.client.post("/v1/agent/authorize", headers=headers, content=DEEP_JSON)
                self.assertEqual(resp.status_code, 400)

    def test_middleware_is_always_installed(self) -> None:
        self.assertIn(self.middleware_cls, [m.cls for m in self.app.user_middleware])


class TestDownstreamEnvironmentReviewFixes(unittest.TestCase):
    def test_windows_runtime_variables_are_kept(self) -> None:
        env = {
            "APPDATA": r"C:\Users\u\AppData\Roaming",
            "LOCALAPPDATA": r"C:\Users\u\AppData\Local",
            "PROGRAMDATA": r"C:\ProgramData",
            "SYSTEMDRIVE": "C:",
            "ProgramFiles": r"C:\Program Files",
            "ProgramFiles(x86)": r"C:\Program Files (x86)",
            "NUMBER_OF_PROCESSORS": "8",
            "GITHUB_TOKEN": "not-for-children",
        }
        out = downstream_environment(env)
        self.assertEqual(set(out), set(env) - {"GITHUB_TOKEN"})

    def test_code_injection_names_are_withheld_even_via_pass_env(self) -> None:
        env = {name: "x" for name in CODE_INJECTION_ENV_NAMES} | {"PATH": "/bin", "MY_TOKEN": "t"}
        out = downstream_environment(env, pass_env=[*CODE_INJECTION_ENV_NAMES, "MY_TOKEN"])
        self.assertEqual(set(out), {"PATH", "MY_TOKEN"})

    def test_config_rejects_every_code_injection_name(self) -> None:
        def config(pass_env: list[str]) -> dict[str, object]:
            return {
                "schema_version": 2,
                "servers": [
                    {"name": "tools", "transport": "stdio", "command": ["my-mcp-server"], "pass_env": pass_env}
                ],
            }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg_path = root / "mellyn.toml"
            # The same config with a harmless name must parse, or the rejections below would prove nothing.
            parsed = parse_unified_dict(config(["CUSTOM_MODE"]), base_dir=root, config_path=cfg_path)
            self.assertEqual(parsed.gateway.servers[0].pass_env, ("CUSTOM_MODE",))
            for name in sorted(CODE_INJECTION_ENV_NAMES) + ["ld_audit"]:
                with self.subTest(name=name):
                    with self.assertRaisesRegex(PolicyLoadError, "protected variable"):
                        parse_unified_dict(config([name]), base_dir=root, config_path=cfg_path)


class TestSpecialUseCidrsReviewFixes(unittest.TestCase):
    def test_local_nat64_and_teredo_are_blocked_in_both_lists(self) -> None:
        squid = (REPO_ROOT / "deploy" / "egress" / "squid.conf").read_text(encoding="utf-8")
        for cidr in ("64:ff9b:1::/48", "2001::/32"):
            with self.subTest(cidr=cidr):
                self.assertIn(cidr, BLOCKED_DESTINATION_CIDRS)
                self.assertIn(f"acl blocked_dst dst {cidr}\n", squid)


if __name__ == "__main__":
    unittest.main()
