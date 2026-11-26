"""
Regression tests for the observe-mode review: observe mode (which forwards every violation) must need the reviewed
policy's consent as well as the launch flag, every session must record its mode, and `resources/read` binary blobs
must not be blocked by the entropy detector while canaries hidden in them are still caught.
"""

from __future__ import annotations

import asyncio
import base64
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from pydantic import ValidationError

from mellyn.airlock.engine import evaluate_tool_response
from mellyn.airlock.models import AirlockPolicy, JsonRpcSuccessResponse, parse_airlock_policy_toml
from mellyn.airlock.proxy import AirlockProxy
from mellyn.core.audit import AuditLedger
from mellyn.core.schemas import SESSION_STARTED_RULE_ID
from mellyn.ir_lab.reconstruct import reconstruct_incident, render_markdown

from .test_proxy_aad import CANARY, HOSTILE_SERVER, REPO_ROOT, ProxyHarness, _QueueClientWriter


def _cli_env() -> dict[str, str]:
    env = {"PYTHONPATH": str(REPO_ROOT / "src"), "PYTHONUTF8": "1"}
    for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATH", "TMPDIR", "LANG"):
        if key in os.environ:
            env[key] = os.environ[key]
    return env


class TestObserveModeNeedsPolicyConsent(ProxyHarness):
    async def test_constructor_refuses_observe_without_the_policy_opt_in(self) -> None:
        with self.assertRaises(ValueError):
            AirlockProxy(
                command=[sys.executable, str(HOSTILE_SERVER)],
                policy=self._build_policy(),
                ledger=AuditLedger(self.audit_path),
                client_reader=asyncio.StreamReader(),
                client_writer=_QueueClientWriter(),
                mode="observe",
            )
        self.assertTrue(parse_airlock_policy_toml("allow_observe_mode = true\n").allow_observe_mode)
        with self.assertRaises(ValidationError):  # the mode itself still cannot come from the policy
            parse_airlock_policy_toml('mode = "observe"\n')

    def test_cli_refuses_observe_without_the_opt_in_and_never_starts_the_server(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "p.toml"
            policy.write_text("", encoding="utf-8")
            pid_file = root / "server.pid"
            res = subprocess.run(  # noqa: S603 - explicit argv, no shell
                [
                    sys.executable,
                    "-m",
                    "mellyn.airlock.proxy",
                    "--policy",
                    str(policy),
                    "--audit-log",
                    str(root / "audit.jsonl"),
                    "--mode",
                    "observe",
                    "--",
                    sys.executable,
                    str(HOSTILE_SERVER),
                    "--pid-file",
                    str(pid_file),
                ],
                capture_output=True,
                text=True,
                env=_cli_env(),
                timeout=30,
                input="",
            )
            self.assertEqual(res.returncode, 2, res.stderr)
            self.assertIn("allow_observe_mode", res.stderr)
            time.sleep(0.2)
            self.assertFalse(pid_file.exists(), "downstream was started despite the refusal")


class TestEverySessionRecordsItsMode(ProxyHarness):
    async def _run_session(self, mode: str, policy: AirlockPolicy) -> tuple[list[dict[str, object]], str]:
        if self.audit_path.exists():
            self.audit_path.unlink()
        err = io.StringIO()
        reader, writer = asyncio.StreamReader(), _QueueClientWriter()
        proxy = AirlockProxy(
            command=[sys.executable, str(HOSTILE_SERVER), "--mode", "benign"],
            policy=policy,
            ledger=AuditLedger(self.audit_path),
            client_reader=reader,
            client_writer=writer,
            err_stream=err,
            mode=mode,  # type: ignore[arg-type]
        )
        task = asyncio.create_task(proxy.run())
        self._send(reader, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        await self._recv(writer)
        reader.feed_eof()
        await asyncio.wait_for(task, timeout=8.0)
        rows = [json.loads(line) for line in self.audit_path.read_text(encoding="utf-8").splitlines() if line]
        return rows, err.getvalue()

    async def test_first_record_states_the_mode_and_ir_shows_it(self) -> None:
        base = self._build_policy().model_dump()
        for mode in ("enforce", "observe"):
            with self.subTest(mode=mode):
                policy = AirlockPolicy.model_validate({**base, "allow_observe_mode": mode == "observe"})
                rows, err = await self._run_session(mode, policy)
                first = rows[0]["event"]
                self.assertEqual(first["rule_id"], SESSION_STARTED_RULE_ID)
                self.assertEqual(first["metadata"]["enforcement_mode"], mode)
                self.assertIn("record_redacted_payloads", first["metadata"])
                report = reconstruct_incident(self.audit_path)
                self.assertEqual(report.sessions[0].enforcement_mode, mode)
                self.assertIn(f"- **Mode**: {mode}", render_markdown(report))
                self.assertEqual("OBSERVE MODE" in err, mode == "observe")

    def test_older_ledgers_without_a_session_start_show_unknown_mode(self) -> None:
        from .test_cli_review_fixes import _event

        AuditLedger(self.audit_path).record(_event(0, request_id=1))
        report = reconstruct_incident(self.audit_path)
        self.assertIsNone(report.sessions[0].enforcement_mode)
        self.assertIn("unknown (no session_start record)", render_markdown(report))


class TestResourceBlobsAreNotFlaggedAsSecrets(unittest.TestCase):
    def _response(self, blob: str) -> JsonRpcSuccessResponse:
        return JsonRpcSuccessResponse(
            jsonrpc="2.0",
            id=1,
            result={"contents": [{"uri": "file:///ws/logo.png", "mimeType": "image/png", "blob": blob}]},
        )

    def test_binary_blob_passes_but_a_canary_inside_it_still_fires_aad(self) -> None:
        policy = AirlockPolicy(allow_resources_read=True, canary_tokens=[CANARY])
        binary = base64.b64encode(os.urandom(2000)).decode("ascii")
        self.assertTrue(evaluate_tool_response(self._response(binary), policy, resource_read=True).verdict_allow)
        # Outside resources/read the same content is still subject to the entropy detector.
        self.assertFalse(evaluate_tool_response(self._response(binary), policy).verdict_allow)

        leaking = base64.b64encode(os.urandom(300) + CANARY.encode("utf-8") + os.urandom(300)).decode("ascii")
        verdict = evaluate_tool_response(self._response(leaking), policy, resource_read=True)
        self.assertEqual(verdict.severity, "AAD_FIRE")

    def test_high_entropy_text_content_is_still_blocked(self) -> None:
        policy = AirlockPolicy(allow_resources_read=True)
        # Built at runtime so repository secret scanners do not treat this synthetic credential as a real one.
        fake_credential = "tok" + "en=" + "aZ9_kL2m" + "P8qR4vW7" + "xN3bY5cQ"
        response = JsonRpcSuccessResponse(
            jsonrpc="2.0",
            id=1,
            result={"contents": [{"uri": "file:///ws/k.txt", "text": fake_credential}]},
        )
        self.assertFalse(evaluate_tool_response(response, policy, resource_read=True).verdict_allow)
