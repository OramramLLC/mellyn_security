"""E2E regression tests for the 5-minute Mellyn Airlock + Plane 4 Viewer demo walkthrough."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import secrets
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
BACKEND_DIR = REPO_ROOT / "backend"
DEMO_DIR = REPO_ROOT / "examples" / "airlock_demo"

for _path in (REPO_ROOT, SRC_DIR, BACKEND_DIR):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

if importlib.util.find_spec("pydantic") is None and os.environ.get("MELLYN_REQUIRE_API_TESTS") != "1":
    raise unittest.SkipTest("pydantic is not installed; demo walkthrough tests skipped")

from mellyn.approvals import API_KEY_HEADER, build_approval_opener  # noqa: E402
from mellyn.credentials import CredentialConfig, Role, key_digest  # noqa: E402
from mellyn.viewer_server import ViewerHTTPServer  # noqa: E402

from examples.airlock_demo.run_demo import POLICY_PATH, SERVER_PATH, run_demo_session  # noqa: E402
from mcp_airlock.airlock.models import parse_airlock_policy_toml  # noqa: E402
from mcp_airlock.airlock.pin_cli import inspect_mcp_server  # noqa: E402
from mcp_airlock.airlock.proxy import JSONRPC_POLICY_VIOLATION  # noqa: E402


def _http_get(url: str, *, api_key: str | None = None) -> tuple[int, dict[str, Any]]:
    headers = {API_KEY_HEADER: api_key} if api_key is not None else {}
    req = urllib.request.Request(url, method="GET", headers=headers)  # noqa: S310 - test loopback only
    opener = build_approval_opener()
    try:
        with opener.open(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))


class TestDemoWalkthrough(unittest.TestCase):
    def test_reviewed_policy_pins_match_sample_server(self) -> None:
        inspection = asyncio.run(inspect_mcp_server([sys.executable, str(SERVER_PATH)]))
        self.assertEqual(inspection.warnings, [])

        policy = parse_airlock_policy_toml(POLICY_PATH.read_text(encoding="utf-8"))
        self.assertEqual(inspection.manifest_sha256, policy.manifest_sha256)
        self.assertEqual(inspection.tool_pins, policy.agbom_pins)
        self.assertEqual(policy.allowed_tools, ["read_status_note"])

    def test_demo_session_allows_blocks_verifies_and_serves_in_viewer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = run_demo_session(Path(tmp))

            self.assertEqual(result.proxy_exit_code, 0)
            self.assertTrue(result.audit_path.is_file())
            self.assertTrue(result.report_path.is_file())

            # Allowed call succeeded and returned the in-memory note.
            allowed_content = result.allowed_call_response["result"]["content"][0]["text"]
            self.assertIn("Release readiness note", allowed_content)

            # Blocked call was stopped fail-closed by Airlock with -32000.
            blocked_error = result.blocked_call_response["error"]
            self.assertEqual(blocked_error["code"], JSONRPC_POLICY_VIOLATION)

            # Incident report verified the hash chain and recorded both outcomes.
            report = result.incident_report
            self.assertTrue(report.chain_valid)
            self.assertEqual(report.status, "BLOCKED_ACTIVITY")
            self.assertEqual(len(report.sessions), 1)
            events = report.sessions[0].events
            self.assertTrue(
                any(ev.verdict_allow and ev.severity == "INFO" and ev.tool_name == "read_status_note" for ev in events)
            )
            self.assertTrue(
                any(
                    not ev.verdict_allow and ev.severity == "BLOCK" and ev.tool_name == "export_diagnostics"
                    for ev in events
                )
            )

            # Viewer server exposes the reconstructed ledger with Role.VIEWER auth only.
            pepper = secrets.token_urlsafe(32)
            viewer_key = secrets.token_urlsafe(24)
            viewer_creds = CredentialConfig(
                pepper=pepper,
                digests={Role.VIEWER: key_digest(viewer_key, pepper)},
                roles=frozenset({Role.VIEWER}),
            )
            server = ViewerHTTPServer(
                host="127.0.0.1",
                port=0,
                viewer_credentials=viewer_creds,
                approver_credentials=None,
                airlock_audit_path=result.audit_path,
            )
            server.start_in_background()
            # Register server_close before shutdown so LIFO teardown stops serve_forever first.
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)

            unauth_code, _ = _http_get(f"{server.url}/api/v1/airlock/report")
            self.assertEqual(unauth_code, 401)

            ok_code, payload = _http_get(f"{server.url}/api/v1/airlock/report", api_key=viewer_key)
            self.assertEqual(ok_code, 200)
            self.assertTrue(payload["chain_valid"])
            self.assertEqual(payload["status"], "BLOCKED_ACTIVITY")
            self.assertEqual(payload["verification"]["ledger_path"], "audit.jsonl")
