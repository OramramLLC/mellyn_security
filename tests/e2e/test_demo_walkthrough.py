"""E2E regression tests for the 5-minute Mellyn Airlock + Forensic Flight Recorder demo walkthrough."""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"

for _path in (REPO_ROOT, SRC_DIR):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

if importlib.util.find_spec("pydantic") is None and os.environ.get("MELLYN_REQUIRE_API_TESTS") != "1":
    raise unittest.SkipTest("pydantic is not installed; demo walkthrough tests skipped")

from examples.airlock_demo.run_demo import POLICY_PATH, SERVER_PATH, run_demo_session  # noqa: E402
from examples.airlock_demo.run_demo import main as demo_main  # noqa: E402
from mellyn.airlock.models import parse_airlock_policy_toml  # noqa: E402
from mellyn.airlock.pin_cli import inspect_mcp_server  # noqa: E402
from mellyn.airlock.proxy import JSONRPC_POLICY_VIOLATION  # noqa: E402


class TestDemoWalkthrough(unittest.TestCase):
    def test_reviewed_policy_pins_match_sample_server(self) -> None:
        inspection = asyncio.run(inspect_mcp_server([sys.executable, str(SERVER_PATH)]))
        self.assertEqual(inspection.warnings, [])

        policy = parse_airlock_policy_toml(POLICY_PATH.read_text(encoding="utf-8"))
        self.assertEqual(inspection.manifest_sha256, policy.manifest_sha256)
        self.assertEqual(inspection.tool_pins, policy.agbom_pins)
        self.assertEqual(policy.allowed_tools, ["read_status_note"])

    def test_demo_session_allows_blocks_verifies_and_prints_timeline(self) -> None:
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

        with tempfile.TemporaryDirectory() as tmp_cli:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = demo_main(["--output-dir", tmp_cli])
            self.assertEqual(rc, 0)
            out = buf.getvalue()
            self.assertIn("Chain Valid  : True", out)
            self.assertIn("BLOCKED_ACTIVITY", out)
            self.assertIn("read_status_note", out)
            self.assertIn("export_diagnostics", out)
            self.assertIn("Reconstructed Incident Timeline (mellyn-ir)", out)


if __name__ == "__main__":
    unittest.main()
