"""Regression tests for pre-audit core hardening fixes."""

from __future__ import annotations

import http.server
import importlib.util
import json
import secrets
import socket
import sys
import tempfile
import threading
import tomllib
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
for _import_dir in (REPO_ROOT, REPO_ROOT / "src"):
    if str(_import_dir) not in sys.path:
        sys.path.insert(0, str(_import_dir))

from mellyn.approval_relay import ApprovalRelayServer, _RelayHandler  # noqa: E402
from mellyn.approvals import ApprovalHTTPServer, PendingApprovals, _ApprovalHandler  # noqa: E402
from mellyn.authorizer import Authorizer  # noqa: E402
from mellyn.credentials import CredentialConfig, Role, key_digest  # noqa: E402
from mellyn.egress_proxy import BLOCKED_DESTINATION_CIDRS  # noqa: E402
from mellyn.http_downstream import _strict_json_loads as http_strict_json_loads  # noqa: E402
from mellyn.http_downstream import _valid_reply_shape  # noqa: E402
from mellyn.legacy_env import LEGACY_ENV_PREFIX  # noqa: E402
from mellyn.mcp_gateway import downstream_environment  # noqa: E402
from mellyn.policy_loader import PolicyLoadError  # noqa: E402
from mellyn.unified_config import parse_unified_dict  # noqa: E402

HAS_FASTAPI = all(importlib.util.find_spec(name) is not None for name in ("fastapi", "httpx"))


def _send_raw_http(host: str, port: int, raw_request: bytes) -> bytes:
    with socket.create_connection((host, port), timeout=5.0) as sock:
        sock.sendall(raw_request)
        chunks: list[bytes] = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)


class TestSquidSpecialUseIpv6Cidrs(unittest.TestCase):
    def test_blocked_cidrs_cover_ipv4_mapped_nat64_and_special_use_ranges(self) -> None:
        required = (
            "192.0.0.0/24",
            "198.18.0.0/15",
            "::/128",
            "::ffff:0:0/96",
            "64:ff9b::/96",
            "100::/64",
            "2001:db8::/32",
            "2002::/16",
        )
        for cidr in required:
            self.assertIn(cidr, BLOCKED_DESTINATION_CIDRS)
        squid_conf = (REPO_ROOT / "deploy" / "egress" / "squid.conf").read_text(encoding="utf-8")
        for cidr in required:
            self.assertIn(f"acl blocked_dst dst {cidr}", squid_conf)


class TestDownstreamEnvironmentAllowlist(unittest.TestCase):
    def test_ambient_secrets_and_injectors_are_dropped_by_default(self) -> None:
        parent = {
            "PATH": "/usr/bin",
            "HOME": "/home/mcp",
            "HTTPS_PROXY": "http://mellyn-egress:3128",
            "AWS_SECRET_ACCESS_KEY": "dummy",
            "OPENAI_API_KEY": "dummy",
            "GITHUB_TOKEN": "dummy",
            "PYTHONPATH": "/opt/evil",
            "LD_PRELOAD": "/opt/evil.so",
            "NODE_OPTIONS": "--require=/opt/evil.js",
            "MELLYN_API_KEY_PEPPER": "p",
            f"{LEGACY_ENV_PREFIX}PEPPER": "p2",
            "CUSTOM_TOOL_FLAG": "1",
        }
        child = downstream_environment(parent)
        self.assertEqual(
            child,
            {
                "PATH": "/usr/bin",
                "HOME": "/home/mcp",
                "HTTPS_PROXY": "http://mellyn-egress:3128",
            },
        )

    def test_explicit_pass_env_cannot_leak_secrets(self) -> None:
        parent = {
            "PATH": "/usr/bin",
            "CUSTOM_TOOL_FLAG": "yes",
            "MELLYN_PEPPER": "p",
            "OAUTH_SECRET": "s",
        }
        child = downstream_environment(
            parent,
            secret_names=("OAUTH_SECRET",),
            pass_env=("CUSTOM_TOOL_FLAG", "MELLYN_PEPPER", "OAUTH_SECRET"),
        )
        self.assertEqual(child, {"PATH": "/usr/bin", "CUSTOM_TOOL_FLAG": "yes"})

    def test_unified_config_validates_pass_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg_path = root / "mellyn.toml"
            valid_toml = """
schema_version = 2
[[servers]]
name = "tools"
transport = "stdio"
command = ["my-mcp-server"]
pass_env = ["CUSTOM_MODE"]
"""
            parsed = parse_unified_dict(tomllib.loads(valid_toml), base_dir=root, config_path=cfg_path)
            self.assertEqual(parsed.gateway.servers[0].pass_env, ("CUSTOM_MODE",))

            for bad_env in ("MELLYN_PEPPER", f"{LEGACY_ENV_PREFIX}PEPPER", "LD_PRELOAD", "PYTHONPATH", "BAD-NAME"):
                bad_toml = f"""
schema_version = 2
[[servers]]
name = "tools"
transport = "stdio"
command = ["my-mcp-server"]
pass_env = ["{bad_env}"]
"""
                with self.subTest(bad_env=bad_env), self.assertRaises(PolicyLoadError):
                    parse_unified_dict(tomllib.loads(bad_toml), base_dir=root, config_path=cfg_path)

            http_server_toml = """
schema_version = 2
[[servers]]
name = "remote"
transport = "streamable-http"
url = "https://mcp.example.com/mcp"
pass_env = ["CUSTOM_MODE"]
"""
            with self.assertRaises(PolicyLoadError):
                parse_unified_dict(tomllib.loads(http_server_toml), base_dir=root, config_path=cfg_path)


class TestHttpDownstreamStrictJsonAndBoolId(unittest.TestCase):
    def test_rejects_non_finite_json_constants(self) -> None:
        for bad in ('{"jsonrpc": "2.0", "id": 1, "result": NaN}', '{"jsonrpc": "2.0", "id": 1, "result": Infinity}'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                http_strict_json_loads(bad)

    def test_rejects_boolean_id_matching_integer_one(self) -> None:
        self.assertFalse(_valid_reply_shape({"jsonrpc": "2.0", "id": True, "result": {}}, 1))
        self.assertFalse(_valid_reply_shape({"jsonrpc": "2.0", "id": False, "result": {}}, 0))
        self.assertTrue(_valid_reply_shape({"jsonrpc": "2.0", "id": 1, "result": {}}, 1))


@unittest.skipUnless(HAS_FASTAPI, "fastapi and httpx are not installed")
class TestFastApiStrictJsonAndBodyCap(unittest.TestCase):
    def setUp(self) -> None:
        from fastapi.testclient import TestClient

        from mellyn.api import MAX_REQUEST_BODY_BYTES, create_app

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        pepper = secrets.token_urlsafe(32)
        self.agent_key = secrets.token_urlsafe(32)
        approver_key = secrets.token_urlsafe(32)
        creds = CredentialConfig.from_env(
            {
                "MELLYN_API_KEY_PEPPER": pepper,
                "MELLYN_AGENT_KEY_DIGEST": key_digest(self.agent_key, pepper),
                "MELLYN_APPROVER_KEY_DIGEST": key_digest(approver_key, pepper),
            }
        )
        self.max_bytes = MAX_REQUEST_BODY_BYTES
        self.client = TestClient(create_app(Path(self._tmp.name), credentials=creds))
        self.headers = {"X-Mellyn-API-Key": self.agent_key, "Content-Type": "application/json"}

    def test_rejects_oversized_request_body_before_parsing(self) -> None:
        sess = self.client.post("/v1/sessions", headers=self.headers).json()["session_id"]
        oversized = json.dumps(
            {"session_id": sess, "tool_name": "workspace_write", "arguments": {"x": "a" * (self.max_bytes + 1024)}}
        )
        resp = self.client.post("/v1/agent/authorize", headers=self.headers, content=oversized)
        self.assertEqual(resp.status_code, 413)

    def test_rejects_duplicate_keys_and_non_finite_constants(self) -> None:
        sess = self.client.post("/v1/sessions", headers=self.headers).json()["session_id"]
        dup_payload = (
            f'{{"session_id": "{sess}", "tool_name": "workspace_read", "tool_name": "shell_exec", "arguments": {{}}}}'
        )
        resp_dup = self.client.post("/v1/agent/authorize", headers=self.headers, content=dup_payload)
        self.assertEqual(resp_dup.status_code, 400)

        nan_payload = f'{{"session_id": "{sess}", "tool_name": "workspace_read", "arguments": {{"x": NaN}}}}'
        resp_nan = self.client.post("/v1/agent/authorize", headers=self.headers, content=nan_payload)
        self.assertEqual(resp_nan.status_code, 400)


class TestApprovalHttpAndRelayHardening(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        pepper = secrets.token_urlsafe(32)
        self.approver_key = secrets.token_urlsafe(32)
        creds = CredentialConfig.from_env(
            {"MELLYN_API_KEY_PEPPER": pepper, "MELLYN_APPROVER_KEY_DIGEST": key_digest(self.approver_key, pepper)},
            roles=frozenset({Role.APPROVER}),
        )
        auth = Authorizer(workspace_root=Path(self._tmp.name))
        self.approvals = PendingApprovals(auth)
        self.server = ApprovalHTTPServer(self.approvals, creds)
        self.server.start_in_background()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

        self.relay = ApprovalRelayServer(
            listen_host="127.0.0.1",
            listen_port=0,
            upstream_host="127.0.0.1",
            upstream_port=self.server.server_address[1],
        )
        threading.Thread(target=self.relay.serve_forever, daemon=True).start()
        self.addCleanup(self.relay.server_close)
        self.addCleanup(self.relay.shutdown)

    def test_handlers_configure_socket_timeout(self) -> None:
        self.assertEqual(_ApprovalHandler.timeout, 10.0)
        self.assertEqual(_RelayHandler.timeout, 10.0)

    def test_rejects_transfer_encoding_and_duplicate_content_length(self) -> None:
        relay_port = self.relay.server_address[1]
        app_port = self.server.server_address[1]
        te_req = (
            b"POST /v1/pending/apr_12345678/approve HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n\r\n"
            b"0\r\n\r\n"
        )
        self.assertTrue(_send_raw_http("127.0.0.1", relay_port, te_req).startswith(b"HTTP/1.0 400"))

        dup_cl_req = (
            f"POST /v1/pending/apr_12345678/approve HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"X-Mellyn-API-Key: {self.approver_key}\r\n"
            f"Content-Length: 2\r\n"
            f"Content-Length: 2\r\n"
            f"Connection: close\r\n\r\n{{}}"
        ).encode()
        self.assertTrue(_send_raw_http("127.0.0.1", app_port, dup_cl_req).startswith(b"HTTP/1.0 400"))

    def test_approval_server_rejects_duplicate_json_keys(self) -> None:
        app_port = self.server.server_address[1]
        body = b'{"approved_by": "a", "approved_by": "b"}'
        req = (
            f"POST /v1/pending/apr_12345678/approve HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"X-Mellyn-API-Key: {self.approver_key}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode() + body
        self.assertTrue(_send_raw_http("127.0.0.1", app_port, req).startswith(b"HTTP/1.0 400"))

    def test_concurrency_semaphore_caps_excess_connections(self) -> None:
        held = threading.Event()

        class SlowUpstream(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                pass

            def do_GET(self) -> None:  # noqa: N802
                held.wait(timeout=3.0)
                self.send_response(200)
                self.send_header("Content-Length", "15")
                self.end_headers()
                self.wfile.write(b'{"pending": []}')

        upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), SlowUpstream)
        capped_relay = ApprovalRelayServer(
            listen_host="127.0.0.1",
            listen_port=0,
            upstream_host="127.0.0.1",
            upstream_port=upstream.server_address[1],
            max_connections=1,
        )
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        threading.Thread(target=capped_relay.serve_forever, daemon=True).start()
        self.addCleanup(upstream.server_close)
        self.addCleanup(upstream.shutdown)
        self.addCleanup(capped_relay.server_close)
        self.addCleanup(capped_relay.shutdown)

        port = capped_relay.server_address[1]
        first_res: list[bytes] = []

        def _hold_first() -> None:
            first_res.append(
                _send_raw_http(
                    "127.0.0.1",
                    port,
                    b"GET /v1/pending HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                )
            )

        t = threading.Thread(target=_hold_first, daemon=True)
        t.start()
        try:
            # Wait briefly for the first handler to occupy the single semaphore slot.
            for _ in range(50):
                if not capped_relay._conn_semaphore.acquire(blocking=False):
                    break
                capped_relay._conn_semaphore.release()
                threading.Event().wait(0.02)
            try:
                second = _send_raw_http(
                    "127.0.0.1",
                    port,
                    b"GET /v1/pending HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                )
            except (ConnectionAbortedError, ConnectionResetError):
                second = b""
            self.assertEqual(second, b"")
        finally:
            held.set()
            t.join(timeout=5.0)
        self.assertTrue(first_res and b"200" in first_res[0])


if __name__ == "__main__":
    unittest.main()
