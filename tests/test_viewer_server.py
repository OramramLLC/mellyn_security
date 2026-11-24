"""Unit & loopback HTTP integration tests for `mellyn.viewer_server` (Plane 4)."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"
SRC_DIR = REPO_ROOT / "src"
for p in (BACKEND_DIR, SRC_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

# The viewer reconstructs Airlock ledgers with `mcp_airlock`, which needs pydantic. As in `tests/unit`, skip in the
# pre-commit hook's bare environment, but fail when MELLYN_REQUIRE_API_TESTS=1 (as in CI) so CI never skips silently.
if importlib.util.find_spec("pydantic") is None and os.environ.get("MELLYN_REQUIRE_API_TESTS") != "1":
    raise unittest.SkipTest("pydantic is not installed; viewer server tests skipped")

from mellyn.approvals import API_KEY_HEADER, ApprovalHTTPServer, PendingApprovals, build_approval_opener  # noqa: E402
from mellyn.authorizer import Authorizer  # noqa: E402
from mellyn.credentials import CredentialConfig, Role, key_digest  # noqa: E402
from mellyn.models import Decision, RiskTier, ToolCallRequest  # noqa: E402
from mellyn.policy import PolicyConfig  # noqa: E402
from mellyn.viewer_server import CSP_HEADER_VALUE, ViewerHTTPServer  # noqa: E402

from mcp_airlock.core.audit import AuditLedger  # noqa: E402
from mcp_airlock.core.schemas import AAD_CONTAINMENT_CONFIRMED_RULE_ID, ZoneEvent  # noqa: E402

PEPPER = "viewer-test-pepper-at-least-32-chars!!"
AGENT_KEY = "agent-viewer-test-key"
APPROVER_KEY = "approver-viewer-test-key"
VIEWER_KEY = "viewer-read-only-test-key"
CREDS = CredentialConfig(
    pepper=PEPPER,
    digests={
        Role.AGENT: key_digest(AGENT_KEY, PEPPER),
        Role.APPROVER: key_digest(APPROVER_KEY, PEPPER),
    },
)
VIEWER_CREDS = CredentialConfig(
    pepper=PEPPER, digests={Role.VIEWER: key_digest(VIEWER_KEY, PEPPER)}, roles=frozenset({Role.VIEWER})
)
APPROVER_CREDS = CredentialConfig(
    pepper=PEPPER, digests={Role.APPROVER: key_digest(APPROVER_KEY, PEPPER)}, roles=frozenset({Role.APPROVER})
)


def _http_call(
    url: str,
    *,
    method: str = "GET",
    api_key: str | None = None,
    body: dict[str, Any] | None = None,
    host_header: str | None = None,
) -> tuple[int, dict[str, str], bytes]:
    headers: dict[str, str] = {}
    if api_key is not None:
        headers[API_KEY_HEADER] = api_key
    if host_header is not None:
        headers["Host"] = host_header
    data: bytes | None = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, method=method, headers=headers, data=data)  # noqa: S310 - test loopback only
    opener = build_approval_opener()
    try:
        with opener.open(req, timeout=5) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, dict(exc.headers), exc.read()


class _RedirectApprovalStubHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(302)
        self.send_header("Location", "https://evil.example/steal-key")
        self.end_headers()


class TestViewerServerSecurityAndApi(unittest.TestCase):
    def test_fails_closed_when_unconfigured_except_healthz(self) -> None:
        # No credentials passed and none in the environment: every keyed route must refuse with 503.
        with mock.patch.dict(os.environ, {}, clear=True):
            server = ViewerHTTPServer(host="127.0.0.1", port=0)
        server.start_in_background()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        code, headers, body = _http_call(f"{server.url}/api/v1/healthz")
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body), {"status": "ok"})
        self.assertEqual(headers.get("Content-Security-Policy"), CSP_HEADER_VALUE)
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(headers.get("Referrer-Policy"), "no-referrer")
        self.assertEqual(headers.get("Cache-Control"), "no-store")

        for method, path, key in (
            ("GET", "/api/v1/status", VIEWER_KEY),
            ("GET", "/api/v1/airlock/report", VIEWER_KEY),
            ("GET", "/api/v1/gateway/audit", VIEWER_KEY),
            ("GET", "/api/v1/assurance", VIEWER_KEY),
            ("GET", "/api/v1/pending", APPROVER_KEY),
            ("POST", "/api/v1/pending/apr_12345678/reject", APPROVER_KEY),
        ):
            with self.subTest(method=method, path=path):
                s_code, _, _ = _http_call(f"{server.url}{path}", method=method, api_key=key)
                self.assertEqual(s_code, 503)

    def test_auth_matrix_telemetry_endpoints_and_static_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            airlock_log = root / "airlock-audit.jsonl"
            ledger = AuditLedger(airlock_log)
            ts = datetime(2026, 11, 23, 19, 0, 0, tzinfo=UTC).isoformat().replace("+00:00", "Z")
            ledger.record(
                ZoneEvent(
                    event_id="evt-trig-1",
                    timestamp_utc=ts,
                    zone="airlock",
                    action="tools/list",
                    verdict_allow=False,
                    severity="AAD_FIRE",
                    rule_id="airlock.agbom_pin_mismatch",
                    reason="Mismatch on read_file",
                    artifact_sha256="a" * 64,
                    tool_name="read_file",
                    request_id=2,
                    metadata={"session_id": "sess-1"},
                )
            )
            ledger.record(
                ZoneEvent(
                    event_id="evt-conf-1",
                    timestamp_utc=ts,
                    zone="airlock",
                    action="airlock/containment",
                    verdict_allow=False,
                    severity="INFO",
                    rule_id=AAD_CONTAINMENT_CONFIRMED_RULE_ID,
                    reason="Child terminated and reaped.",
                    artifact_sha256="a" * 64,
                    tool_name="read_file",
                    request_id=2,
                    metadata={"session_id": "sess-1", "trigger_event_id": "evt-trig-1", "downstream_returncode": -9},
                )
            )

            gw_log = root / "gateway-audit.jsonl"
            gw_row1 = {
                "audit_id": "aud_1",
                "timestamp": ts,
                "session_id": "s1",
                "tool_name": "t1",
                "decision": "ALLOW",
            }
            gw_row2 = {
                "audit_id": "aud_2",
                "timestamp": ts,
                "session_id": "s1",
                "tool_name": "t2",
                "decision": "DENY",
            }
            gw_log.write_text(
                "\n".join([json.dumps(gw_row1), "corrupt-line", json.dumps(gw_row2)]) + "\n",
                encoding="utf-8",
            )

            assurance_path = root / "assurance.json"
            assurance_path.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "overall_status": "pass",
                        "frameworks": {
                            "owasp_llm_top_10": "2025",
                            "owasp_agentic_top_10": "2026",
                            "mitre_atlas": "5.6.0",
                        },
                        "summary": {"total_cases": 1, "counts": {"pass": 1, "fail": 0, "error": 0, "not_run": 0}},
                        "cases": [{"case_id": "c1", "status": "pass"}],
                    }
                ),
                encoding="utf-8",
            )

            dist_dir = root / "dist"
            (dist_dir / "assets").mkdir(parents=True)
            (dist_dir / "index.html").write_text("<html><body>Mellyn UI</body></html>", encoding="utf-8")
            (dist_dir / "assets" / "app.js").write_text("console.log('ok');", encoding="utf-8")
            (root / "secret.txt").write_text("TOP_SECRET", encoding="utf-8")

            server = ViewerHTTPServer(
                host="127.0.0.1",
                port=0,
                viewer_credentials=VIEWER_CREDS,
                approver_credentials=APPROVER_CREDS,
                airlock_audit_path=airlock_log,
                gateway_audit_path=gw_log,
                assurance_report_path=assurance_path,
                static_dir=dist_dir,
            )
            server.start_in_background()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)

            # Auth enforcement: 401 missing, 403 AGENT or APPROVER key on reads, 200 VIEWER key
            self.assertEqual(_http_call(f"{server.url}/api/v1/status")[0], 401)
            self.assertEqual(_http_call(f"{server.url}/api/v1/status", api_key=AGENT_KEY)[0], 403)
            self.assertEqual(_http_call(f"{server.url}/api/v1/status", api_key="wrong")[0], 403)
            self.assertEqual(_http_call(f"{server.url}/api/v1/status", api_key=APPROVER_KEY)[0], 403)

            st_code, _, st_body = _http_call(f"{server.url}/api/v1/status", api_key=VIEWER_KEY)
            self.assertEqual(st_code, 200)
            status_obj = json.loads(st_body)
            self.assertEqual(
                status_obj,
                {
                    "airlock_ledger_configured": True,
                    "gateway_audit_configured": True,
                    "assurance_report_configured": True,
                    "approval_relay_configured": False,
                },
            )
            self.assertNotIn(str(root), st_body.decode("utf-8"))

            # Airlock report returns confirmed containment & filename-only ledger_path
            air_code, _, air_body = _http_call(f"{server.url}/api/v1/airlock/report", api_key=VIEWER_KEY)
            self.assertEqual(air_code, 200)
            air_json = json.loads(air_body)
            self.assertEqual(air_json["status"], "AAD_CONTAINED")
            self.assertEqual(air_json["verification"]["ledger_path"], "airlock-audit.jsonl")
            self.assertNotIn(str(root), air_body.decode("utf-8"))

            # Tamper ledger mid-log -> fail-closed INTEGRITY_COMPROMISED
            airlock_log.write_text(
                airlock_log.read_text(encoding="utf-8").replace("Mismatch on read_file", "Tamper on read_file"),
                encoding="utf-8",
            )
            tamper_code, _, tamper_body = _http_call(f"{server.url}/api/v1/airlock/report", api_key=VIEWER_KEY)
            self.assertEqual(tamper_code, 200)
            tamper_json = json.loads(tamper_body)
            self.assertFalse(tamper_json["chain_valid"])
            self.assertEqual(tamper_json["status"], "INTEGRITY_COMPROMISED")
            self.assertEqual(tamper_json["verification"]["first_invalid_seq"], 0)

            # Gateway audit limit clamping & malformed tracking
            gw_code, _, gw_body = _http_call(f"{server.url}/api/v1/gateway/audit?limit=1", api_key=VIEWER_KEY)
            self.assertEqual(gw_code, 200)
            gw_json = json.loads(gw_body)
            self.assertEqual(gw_json["total_lines"], 3)
            self.assertEqual(gw_json["malformed_lines"], 1)
            self.assertEqual(gw_json["returned_count"], 1)
            self.assertEqual(gw_json["events"][0]["audit_id"], "aud_2")
            self.assertEqual(_http_call(f"{server.url}/api/v1/gateway/audit?limit=abc", api_key=VIEWER_KEY)[0], 400)

            # Assurance endpoint
            assur_code, _, assur_body = _http_call(f"{server.url}/api/v1/assurance", api_key=VIEWER_KEY)
            self.assertEqual(assur_code, 200)
            self.assertEqual(json.loads(assur_body)["overall_status"], "pass")

            # Static SPA serving, JS content-type, fallback, and traversal blocking
            idx_code, idx_hdrs, idx_body = _http_call(f"{server.url}/")
            self.assertEqual(idx_code, 200)
            self.assertIn("Mellyn UI", idx_body.decode("utf-8"))
            self.assertEqual(idx_hdrs.get("X-Frame-Options"), "DENY")

            js_code, js_hdrs, _ = _http_call(f"{server.url}/assets/app.js")
            self.assertEqual(js_code, 200)
            self.assertTrue(js_hdrs.get("Content-Type", "").startswith("application/javascript"))

            self.assertEqual(_http_call(f"{server.url}/assets/missing.js")[0], 404)
            self.assertEqual(_http_call(f"{server.url}/%2e%2e/secret.txt")[0], 404)
            self.assertEqual(_http_call(f"{server.url}/assets/..%2f..%2fsecret.txt")[0], 404)

    def test_approvals_proxy_lifecycle_and_redirect_refusal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            auth = Authorizer(workspace_root=Path(tmp), policy_config=PolicyConfig())
            approvals = PendingApprovals(auth)
            sid = auth.create_session()
            fake_res = type(
                "_Res",
                (),
                {
                    "decision": Decision.REQUIRE_APPROVAL,
                    "risk_tier": RiskTier.HIGH,
                    "reasons": ("tainted",),
                    "audit_id": "aud_test_1",
                },
            )()
            pending = approvals.add(
                ToolCallRequest(session_id=sid, tool_name="shell_exec", arguments={"argv": ["git", "status"]}),
                fake_res,  # type: ignore[arg-type]
            )
            approval_server = ApprovalHTTPServer(approvals, CREDS)
            approval_server.start_in_background()
            self.addCleanup(approval_server.server_close)
            self.addCleanup(approval_server.shutdown)

            viewer = ViewerHTTPServer(
                host="127.0.0.1",
                port=0,
                viewer_credentials=VIEWER_CREDS,
                approver_credentials=APPROVER_CREDS,
                approval_upstream=approval_server.url,
            )
            viewer.start_in_background()
            self.addCleanup(viewer.server_close)
            self.addCleanup(viewer.shutdown)

            list_code, _, list_body = _http_call(f"{viewer.url}/api/v1/pending", api_key=APPROVER_KEY)
            self.assertEqual(list_code, 200)
            self.assertEqual(len(json.loads(list_body)["pending"]), 1)

            app_code, _, app_body = _http_call(
                f"{viewer.url}/api/v1/pending/{pending.approval_id}/approve",
                method="POST",
                api_key=APPROVER_KEY,
                body={"approved_by": "ops@example", "ttl_seconds": 120, "max_uses": 1},
            )
            self.assertEqual(app_code, 200)
            self.assertIn("grant_id", json.loads(app_body))

            # Queue is now empty
            _, _, list_body2 = _http_call(f"{viewer.url}/api/v1/pending", api_key=APPROVER_KEY)
            self.assertEqual(json.loads(list_body2)["pending"], [])

            # Invalid route rejected 404
            bad_route = _http_call(
                f"{viewer.url}/api/v1/pending/apr_12345678/other",
                method="POST",
                api_key=APPROVER_KEY,
                body={},
            )
            self.assertEqual(bad_route[0], 404)

        # Upstream returning 302 redirect is refused fail-closed with 502
        redir_server = HTTPServer(("127.0.0.1", 0), _RedirectApprovalStubHandler)
        import threading

        t = threading.Thread(target=redir_server.serve_forever, daemon=True)
        t.start()
        self.addCleanup(redir_server.server_close)
        self.addCleanup(redir_server.shutdown)

        viewer_redir = ViewerHTTPServer(
            host="127.0.0.1",
            port=0,
            viewer_credentials=VIEWER_CREDS,
            approver_credentials=APPROVER_CREDS,
            approval_upstream=f"http://127.0.0.1:{redir_server.server_port}",
        )
        viewer_redir.start_in_background()
        self.addCleanup(viewer_redir.server_close)
        self.addCleanup(viewer_redir.shutdown)

        code, _, body = _http_call(f"{viewer_redir.url}/api/v1/pending", api_key=APPROVER_KEY)
        self.assertEqual(code, 502)
        self.assertIn("redirect", json.loads(body)["error"].lower())


class TestViewerReviewFixes(unittest.TestCase):
    """Regression tests for the viewer review: role separation, Host check, bind opt-in, path-free errors."""

    def _start(self, **kwargs: Any) -> ViewerHTTPServer:
        server = ViewerHTTPServer(
            host="127.0.0.1",
            port=0,
            viewer_credentials=VIEWER_CREDS,
            approver_credentials=APPROVER_CREDS,
            **kwargs,
        )
        server.start_in_background()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def test_viewer_key_cannot_touch_approvals_and_approver_key_cannot_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            auth = Authorizer(workspace_root=Path(tmp), policy_config=PolicyConfig())
            approval_server = ApprovalHTTPServer(PendingApprovals(auth), CREDS)
            approval_server.start_in_background()
            self.addCleanup(approval_server.server_close)
            self.addCleanup(approval_server.shutdown)
            viewer = self._start(approval_upstream=approval_server.url)

            self.assertEqual(_http_call(f"{viewer.url}/api/v1/status", api_key=VIEWER_KEY)[0], 200)
            self.assertEqual(_http_call(f"{viewer.url}/api/v1/status", api_key=APPROVER_KEY)[0], 403)
            self.assertEqual(_http_call(f"{viewer.url}/api/v1/pending", api_key=VIEWER_KEY)[0], 403)
            self.assertEqual(_http_call(f"{viewer.url}/api/v1/pending", api_key=APPROVER_KEY)[0], 200)
            post = _http_call(
                f"{viewer.url}/api/v1/pending/apr_12345678/approve",
                method="POST",
                api_key=VIEWER_KEY,
                body={"approved_by": "x", "ttl_seconds": 60, "max_uses": 1},
            )
            self.assertEqual(post[0], 403)

    def test_unexpected_host_header_is_refused_everywhere(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            (dist / "index.html").write_text("<html>ui</html>", encoding="utf-8")
            server = self._start(static_dir=dist, extra_allowed_host_names=frozenset({"viewer.internal"}))
            port = server.server_address[1]
            for path in ("/api/v1/healthz", "/", "/api/v1/status"):
                with self.subTest(path=path):
                    code = _http_call(f"{server.url}{path}", api_key=VIEWER_KEY, host_header="attacker.example")[0]
                    self.assertEqual(code, 421)
            post = _http_call(
                f"{server.url}/api/v1/pending/apr_12345678/reject",
                method="POST",
                api_key=APPROVER_KEY,
                body={},
                host_header=f"attacker.example:{port}",
            )
            self.assertEqual(post[0], 421)
            for good in (f"localhost:{port}", f"127.0.0.1:{port}", f"[::1]:{port}", f"viewer.internal:{port}"):
                with self.subTest(host=good):
                    self.assertEqual(_http_call(f"{server.url}/api/v1/healthz", host_header=good)[0], 200)

    def test_binding_all_interfaces_needs_explicit_opt_in(self) -> None:
        with self.assertRaises(ValueError):
            ViewerHTTPServer(host="0.0.0.0", port=0, viewer_credentials=VIEWER_CREDS)  # noqa: S104
        from mellyn.viewer_server import main as viewer_main

        with mock.patch("sys.stderr"):
            self.assertEqual(viewer_main(["--listen-host", "0.0.0.0"]), 2)  # noqa: S104

    def test_error_messages_do_not_reveal_host_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            gw_log = root / "gateway-audit.jsonl"
            gw_log.write_text("{}\n", encoding="utf-8")
            assurance = root / "assurance.json"
            assurance.write_text("{}", encoding="utf-8")
            server = self._start(gateway_audit_path=gw_log, assurance_report_path=assurance)

            denied = PermissionError(13, "Permission denied", str(gw_log))
            with mock.patch.object(Path, "read_bytes", side_effect=denied):
                code, _, body = _http_call(f"{server.url}/api/v1/gateway/audit", api_key=VIEWER_KEY)
            self.assertEqual(code, 500)
            self.assertNotIn(str(root), body.decode("utf-8"))
            self.assertIn("PermissionError", body.decode("utf-8"))

            denied = PermissionError(13, "Permission denied", str(assurance))
            with mock.patch.object(Path, "read_text", side_effect=denied):
                code, _, body = _http_call(f"{server.url}/api/v1/assurance", api_key=VIEWER_KEY)
            self.assertEqual(code, 500)
            self.assertNotIn(str(root), body.decode("utf-8"))

    def test_viewer_key_must_differ_from_the_other_keys_and_is_opt_in(self) -> None:
        from mellyn.credentials import CredentialConfigError

        base = {
            "MELLYN_API_KEY_PEPPER": PEPPER,
            "MELLYN_AGENT_KEY_DIGEST": key_digest(AGENT_KEY, PEPPER),
            "MELLYN_APPROVER_KEY_DIGEST": key_digest(APPROVER_KEY, PEPPER),
        }
        # The HTTP API's default roles are unchanged: no viewer key needed.
        self.assertTrue(CredentialConfig.from_env(base).verify(APPROVER_KEY, Role.APPROVER))
        with self.assertRaises(CredentialConfigError):
            CredentialConfig.from_env(
                {**base, "MELLYN_VIEWER_KEY_DIGEST": key_digest(APPROVER_KEY, PEPPER)},
                roles=frozenset({Role.VIEWER}),
            )
        viewer_only = CredentialConfig.from_env(
            {**base, "MELLYN_VIEWER_KEY_DIGEST": key_digest(VIEWER_KEY, PEPPER)}, roles=frozenset({Role.VIEWER})
        )
        self.assertTrue(viewer_only.verify(VIEWER_KEY, Role.VIEWER))
        self.assertFalse(viewer_only.verify(APPROVER_KEY, Role.APPROVER))


if __name__ == "__main__":
    unittest.main()
