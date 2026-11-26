"""
Pass 2C regression & concurrency tests for the unified `schema_version = 2` ledger and verifier.

Gateway/stdlib tests run with standard library only; Airlock and `mellyn-ir` tests skip only when
`pydantic` is absent (e.g. the bare-stdlib pre-commit venv).
"""

from __future__ import annotations

import ast
import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
for _path in (REPO_ROOT, SRC_DIR):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from mellyn.audit import (  # noqa: E402
    GENESIS_PREV_HASH,
    AuditChainError,
    AuditLogger,
    compute_audit_entry_hash,
    verify_gateway_audit_file,
)
from mellyn.cli import main as cli_main  # noqa: E402
from mellyn.core.audit import (  # noqa: E402
    LEDGER_SCHEMA_VERSION,
    CoreAuditLedger,
    LedgerIntegrityError,
    is_legacy_unchained_bytes,
    verify_ledger_bytes_core,
    verify_ledger_file_core,
)
from mellyn.core.normalize import JsonObject, canonical_json_bytes, sha256_canonical  # noqa: E402
from mellyn.core.scan import canary_present_in_json  # noqa: E402
from mellyn.models import Decision, RiskTier  # noqa: E402

HAS_PYDANTIC = importlib.util.find_spec("pydantic") is not None


def _build_v1_gateway_lines(*, include_raw_line_break: bool = False) -> list[str]:
    lines: list[str] = []
    prev_hash = GENESIS_PREV_HASH
    specs = (
        ("aud_v1_0", "taint", "tainted", "low", True, ["web_page:https://example.com"]),
        ("aud_v1_1", "authorization", "allow", "low", False, []),
        (
            "aud_v1_2",
            "authorization",
            "deny",
            "high",
            True,
            ["web_page:a\u2028b"] if include_raw_line_break else ["web_page:a"],
        ),
    )
    for seq, (aid, ev_type, decision, tier, tainted, taints) in enumerate(specs):
        body: dict[str, Any] = {
            "args_sha256": "a" * 64,
            "audit_id": aid,
            "decision": decision,
            "enforcement_mode": "enforce",
            "event_type": ev_type,
            "grant_id": None,
            "mcp_server": "docs" if ev_type == "authorization" else None,
            "policy_id": "rule.demo" if decision == "deny" else None,
            "prev_hash": prev_hash,
            "reasons": [f"reason-{seq}"],
            "risk_tier": tier,
            "seq": seq,
            "session_id": "ses-legacy-gw",
            "taint_count": len(taints),
            "taint_sources": taints,
            "tainted": tainted,
            "timestamp": f"2026-11-23T00:00:0{seq}Z",
            "tool_name": "docs/read" if ev_type == "authorization" else "session/taint",
        }
        entry_hash = compute_audit_entry_hash(body)
        record = {**body, "entry_hash": entry_hash}
        lines.append(json.dumps(record, sort_keys=True, ensure_ascii=False))
        prev_hash = entry_hash
    return lines


def _build_v1_airlock_lines() -> list[str]:
    lines: list[str] = []
    prev_hash = GENESIS_PREV_HASH
    specs = (
        ("evt-v1-0", "airlock", "tools/call", True, "ALLOW", "rule.allow", "allowed"),
        ("evt-v1-1", "egress", "tools/call", False, "BLOCK", "egress.deny", "blocked"),
    )
    for seq, (eid, zone, action, allow, sev, rule_id, reason) in enumerate(specs):
        event: JsonObject = {
            "action": action,
            "artifact_sha256": "b" * 64,
            "event_id": eid,
            "metadata": {"session_id": "sess-v1-airlock"},
            "reason": reason,
            "redactions": [],
            "request_id": seq,
            "rule_id": rule_id,
            "severity": sev,
            "timestamp_utc": f"2026-11-23T01:00:0{seq}Z",
            "tool_name": "read_note",
            "verdict_allow": allow,
            "zone": zone,
        }
        entry_hash = sha256_canonical({"seq": seq, "prev_hash": prev_hash, "event": event})
        entry: JsonObject = {
            "seq": seq,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
            "event": event,
        }
        lines.append(canonical_json_bytes(entry).decode("utf-8"))
        prev_hash = entry_hash
    return lines


def _make_gateway_v2_ledger(path: Path) -> None:
    logger, handle = AuditLogger.open_chained(path, canary_tokens=(), enforcement_mode="enforce")
    try:
        logger.record(
            session_id="ses-gw-ir",
            tool_name="read_file",
            mcp_server="docs",
            arguments={"path": "README.md"},
            decision=Decision.ALLOW,
            risk_tier=RiskTier.LOW,
            tainted=False,
            taint_sources=(),
            reasons=("Allowed low-risk read.",),
            policy_id="preset.docs.read",
        )
        logger.record_taint(
            session_id="ses-gw-ir",
            taint_count=1,
            taint_sources=("mcp_metadata:untrusted/list",),
        )
        logger.record(
            session_id="ses-gw-ir",
            tool_name="run|<b>evil",
            mcp_server="docs",
            arguments={"cmd": "rm"},
            decision=Decision.DENY,
            risk_tier=RiskTier.HIGH,
            tainted=True,
            taint_sources=("mcp_metadata:untrusted/list",),
            reasons=("Denied|destructive\ncommand.",),
            policy_id="policy.deny_destructive",
        )
        logger.record_containment(
            session_id="ses-gw-ir",
            tool_name="send_msg",
            mcp_server="docs",
            decision="blocked_egress",
            reasons=("Egress scanner request match (secret:aws-access-key-id).",),
            payload={"x": 1},
            tainted=True,
            taint_count=1,
            taint_sources=("mcp_metadata:untrusted/list",),
        )
    finally:
        handle.close()


class TestUnifiedV2LedgerStdlib(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def test_single_verifier_and_no_duplicate_chain_logic_in_audit_py(self) -> None:
        audit_src = (SRC_DIR / "mellyn" / "audit.py").read_text(encoding="utf-8")
        tree = ast.parse(audit_src, filename="src/mellyn/audit.py")
        imported_from_core: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "mellyn.core.audit":
                imported_from_core.update(alias.name for alias in node.names)
        self.assertTrue(
            {"CoreAuditLedger", "verify_ledger_file_core", "verify_ledger_lines_core"} <= imported_from_core
        )
        self.assertNotIn("compare_digest", audit_src)

    def test_read_only_v1_airlock_v1_gateway_and_pre_chain_verification(self) -> None:
        v1_airlock = self.root / "v1_airlock.jsonl"
        v1_airlock.write_text("\n".join(_build_v1_airlock_lines()) + "\n", encoding="utf-8", newline="\n")

        v1_gw = self.root / "v1_gateway.jsonl"
        v1_gw.write_text("\n".join(_build_v1_gateway_lines(include_raw_line_break=True)) + "\n", encoding="utf-8")

        pre_chain = self.root / "pre_chain.jsonl"
        pre_chain.write_text('{"audit_id": "aud_10", "decision": "allow"}\n', encoding="utf-8", newline="\n")

        res_air = verify_ledger_file_core(v1_airlock)
        self.assertTrue(res_air.valid, res_air.reason)
        self.assertEqual(res_air.ledger_format, "v1_airlock")
        self.assertEqual(res_air.entry_count, 2)

        res_gw = verify_gateway_audit_file(v1_gw)
        self.assertTrue(res_gw.valid, res_gw.reason)
        self.assertEqual(res_gw.ledger_format, "v1_gateway")
        self.assertEqual(res_gw.entry_count, 3)

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(cli_main(["verify", str(v1_gw), "--json"]), 0)
        cli_report = json.loads(buf.getvalue())
        self.assertEqual(cli_report["ledger_type"], "gateway")
        self.assertEqual(cli_report["ledger_format"], "v1_gateway")
        self.assertTrue(cli_report["valid"])

        res_pre = verify_ledger_file_core(pre_chain)
        self.assertFalse(res_pre.valid)
        self.assertEqual(res_pre.ledger_format, "pre_chain")
        self.assertTrue(is_legacy_unchained_bytes(pre_chain.read_bytes()))

    def test_v1_gateway_rotation_collision_and_sequential_resume(self) -> None:
        path = self.root / "gateway.jsonl"
        v1_raw = "\n".join(_build_v1_gateway_lines()) + "\n"
        path.write_text(v1_raw, encoding="utf-8", newline="\n")

        fixed_now = datetime(2026, 11, 25, 22, 0, 0, tzinfo=UTC)
        stamp = fixed_now.strftime("%Y%m%dT%H%M%SZ")
        clash = self.root / f"gateway.jsonl.v1-{stamp}"
        clash.write_text("earlier v1 rotation\n", encoding="utf-8", newline="\n")

        with mock.patch("mellyn.audit.utc_now", return_value=fixed_now):
            logger, handle = AuditLogger.open_chained(path, source="gateway")
        try:
            rotated = logger.rotated_legacy_path
            if rotated is None:
                self.fail("Expected v1 gateway ledger to rotate aside")
            self.assertEqual(rotated.name, f"gateway.jsonl.v1-{stamp}-1")
            self.assertEqual(logger.rotated_legacy_format, "v1_gateway")
            self.assertEqual(rotated.read_text(encoding="utf-8"), v1_raw)
            self.assertEqual(clash.read_text(encoding="utf-8"), "earlier v1 rotation\n")

            next_ev = logger.record_taint(session_id="ses-after", taint_count=1, taint_sources=("src:new",))
            self.assertEqual(next_ev.seq, 1)
        finally:
            handle.close()

        res = verify_gateway_audit_file(path)
        self.assertTrue(res.valid, res.reason)
        self.assertEqual(res.ledger_format, "v2")
        self.assertEqual(res.entry_count, 2)

        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(rows[0]["schema_version"], LEDGER_SCHEMA_VERSION)
        self.assertEqual(rows[0]["source"], "gateway")
        self.assertEqual(rows[0]["event"]["event_type"], "ledger_rotated")
        self.assertEqual(rows[0]["event"]["decision"], "v1_log_rotated")
        self.assertIn(rotated.name, rows[0]["event"]["reasons"][0])

    def test_mixed_versions_and_tampered_v2_fail_closed_without_rotation(self) -> None:
        v2_src = self.root / "v2_ref.jsonl"
        logger, handle = AuditLogger.open_chained(v2_src)
        logger.record_taint(session_id="s", taint_count=1, taint_sources=("src:1",))
        logger.record_taint(session_id="s", taint_count=2, taint_sources=("src:2",))
        handle.close()
        v2_lines = v2_src.read_text(encoding="utf-8").splitlines()

        v1_air_lines = _build_v1_airlock_lines()
        v1_gw_lines = _build_v1_gateway_lines()
        pre_line = '{"audit_id":"aud_1","decision":"allow"}'

        # Tampered v2 variants
        bad_sv = json.loads(v2_lines[0])
        bad_sv["schema_version"] = 1
        bad_src = json.loads(v2_lines[0])
        bad_src["source"] = "unknown_zone"
        extra_key = json.loads(v2_lines[0])
        extra_key["forged"] = 1

        cases = {
            "v1_airlock_plus_v2": "\n".join([v1_air_lines[0], v2_lines[1]]) + "\n",
            "v1_gateway_plus_v2": "\n".join([v1_gw_lines[0], v2_lines[1]]) + "\n",
            "v2_plus_v1_airlock": "\n".join([v2_lines[0], v1_air_lines[1]]) + "\n",
            "v2_plus_v1_gateway": "\n".join([v2_lines[0], v1_gw_lines[1]]) + "\n",
            "v1_airlock_plus_v1_gateway": "\n".join([v1_air_lines[0], v1_gw_lines[1]]) + "\n",
            "pre_chain_plus_v2": "\n".join([pre_line, v2_lines[1]]) + "\n",
            "bad_schema_version": json.dumps(bad_sv, separators=(",", ":")) + "\n",
            "bad_source": json.dumps(bad_src, separators=(",", ":")) + "\n",
            "extra_envelope_key": json.dumps(extra_key, separators=(",", ":")) + "\n",
            "invisible_unicode_in_v2": v2_lines[0].replace("src:1", "src\u200b:1") + "\n",
            "missing_trailing_newline": v2_lines[0],
        }
        for label, content in cases.items():
            with self.subTest(case=label):
                case_path = self.root / f"{label}.jsonl"
                case_path.write_text(content, encoding="utf-8", newline="\n")
                self.assertFalse(verify_ledger_file_core(case_path).valid)
                with self.assertRaises(AuditChainError):
                    _, h = AuditLogger.open_chained(case_path)
                    h.close()
                self.assertEqual(case_path.read_text(encoding="utf-8"), content)
                self.assertEqual(list(self.root.glob(f"{case_path.name}.v1-*")), [])
                self.assertEqual(list(self.root.glob(f"{case_path.name}.pre-chain-*")), [])

    def test_symlink_ledger_parent_and_lock_refused_fail_closed(self) -> None:
        real_path = self.root / "audit.jsonl"
        logger, handle = AuditLogger.open_chained(real_path)
        logger.record_taint(session_id="s", taint_count=1, taint_sources=("x",))
        handle.close()

        lock_path = real_path.with_name("audit.jsonl.lock")
        for blocked in (real_path, real_path.parent, lock_path):
            with self.subTest(blocked=blocked.name):

                def fake_is_symlink(self_path: Path, target: Path = blocked) -> bool:
                    return self_path == target

                with mock.patch.object(Path, "is_symlink", fake_is_symlink):
                    if blocked != lock_path:
                        with self.assertRaises(AuditChainError):
                            verify_gateway_audit_file(real_path)
                        self.assertFalse(verify_ledger_file_core(real_path).valid)
                    with self.assertRaises(AuditChainError):
                        _, h = AuditLogger.open_chained(real_path)
                        h.close()
                    with self.assertRaises(LedgerIntegrityError):
                        CoreAuditLedger(real_path)

        # Also test a genuine OS symlink if the platform/privileges permit creating one.
        target = self.root / "real_target.jsonl"
        target.write_bytes(real_path.read_bytes())
        link = self.root / "symlink_audit.jsonl"
        try:
            os.symlink(target, link)
        except OSError:
            return
        with self.assertRaises(AuditChainError):
            verify_gateway_audit_file(link)
        with self.assertRaises(AuditChainError):
            _, h = AuditLogger.open_chained(link)
            h.close()

    def test_two_process_concurrent_appends_gateway_writer(self) -> None:
        ledger_path = self.root / "concurrent_gw.jsonl"
        worker_code = textwrap.dedent(
            """\
            import sys
            from pathlib import Path
            from mellyn.audit import AuditLogger

            path = Path(sys.argv[1])
            worker_id = sys.argv[2]
            count = int(sys.argv[3])
            logger, handle = AuditLogger.open_chained(path, source="gateway")
            try:
                for idx in range(count):
                    logger.record_taint(
                        session_id=f"ses-{worker_id}",
                        taint_count=idx + 1,
                        taint_sources=(f"src:{worker_id}:{idx}",),
                    )
            finally:
                handle.close()
            """
        )
        env = dict(os.environ)
        env["PYTHONPATH"] = str(SRC_DIR) + os.pathsep + env.get("PYTHONPATH", "")
        procs = [
            subprocess.Popen(  # noqa: S603 - test-owned fixed python invocation
                [sys.executable, "-c", worker_code, str(ledger_path), f"w{i}", "15"],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for i in range(2)
        ]
        for proc in procs:
            out, err = proc.communicate(timeout=30)
            self.assertEqual(proc.returncode, 0, f"worker failed: {err}\n{out}")

        res = verify_gateway_audit_file(ledger_path)
        self.assertTrue(res.valid, res.reason)
        self.assertEqual(res.ledger_format, "v2")
        self.assertEqual(res.entry_count, 30)
        rows = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual([r["seq"] for r in rows], list(range(30)))

    def test_cli_verify_gateway_external_anchors_and_flag_errors(self) -> None:
        gw_path = self.root / "anchored_gw.jsonl"
        _make_gateway_v2_ledger(gw_path)
        full_res = verify_gateway_audit_file(gw_path)
        self.assertTrue(full_res.valid)
        self.assertEqual(full_res.entry_count, 4)
        anchor_seq = full_res.last_seq
        anchor_hash = full_res.last_hash
        self.assertEqual(anchor_seq, 3)

        # Valid external anchor succeeds
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cli_main(
                ["verify", str(gw_path), "--anchor-seq", str(anchor_seq), "--anchor-hash", anchor_hash, "--json"]
            )
        self.assertEqual(rc, 0)
        report = json.loads(out.getvalue())
        self.assertTrue(report["valid"])
        self.assertTrue(report["anchored"])
        self.assertEqual(report["ledger_type"], "gateway")

        # Missing paired flag fails closed (rc 2)
        for bad_args in (
            ["verify", str(gw_path), "--anchor-seq", "0"],
            ["verify", str(gw_path), "--anchor-hash", "a" * 64],
        ):
            with self.subTest(bad_args=bad_args), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli_main(bad_args), 2)

        # Tail truncation caught ONLY with external anchor
        lines = gw_path.read_bytes().splitlines(keepends=True)
        gw_path.write_bytes(b"".join(lines[:2]))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli_main(["verify", str(gw_path), "--json"]), 0)
        trunc_out = io.StringIO()
        with contextlib.redirect_stdout(trunc_out):
            rc_trunc = cli_main(
                ["verify", str(gw_path), "--anchor-seq", str(anchor_seq), "--anchor-hash", anchor_hash, "--json"]
            )
        self.assertEqual(rc_trunc, 2)
        self.assertFalse(json.loads(trunc_out.getvalue())["valid"])

        # Rewritten chain caught by anchor
        gw_path.unlink()
        _make_gateway_v2_ledger(gw_path)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(
                cli_main(["verify", str(gw_path), "--anchor-seq", str(anchor_seq), "--anchor-hash", anchor_hash]),
                2,
            )

    def test_split_canary_across_arbitrary_keys_never_reaches_disk(self) -> None:
        canary = "MEL_CANARY_V2_REDACT_7741"
        path = self.root / "canary_core.jsonl"
        core = CoreAuditLedger(path, source="gateway", canary_tokens=(canary,))
        half = len(canary) // 2
        entry = core.append(
            {
                "audit_id": "aud_split_test",
                "timestamp": "2026-11-25T22:00:00Z",
                "custom_a": canary[:half],
                "custom_b": canary[half:],
            }
        )
        raw = path.read_text(encoding="utf-8")
        self.assertNotIn(canary, raw)
        self.assertFalse(canary_present_in_json(entry.event, canary))
        self.assertTrue(verify_ledger_bytes_core(path.read_bytes()).valid)


@unittest.skipUnless(HAS_PYDANTIC, "pydantic not installed; skipping Airlock/IR v2 ledger tests")
class TestUnifiedV2AirlockAndIR(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def test_v1_airlock_rotation_preserves_file_and_writes_v2_ledger_rotated(self) -> None:
        from mellyn.core.audit import AuditLedger, verify_ledger
        from mellyn.core.schemas import ZoneEvent

        path = self.root / "airlock.jsonl"
        v1_raw = "\n".join(_build_v1_airlock_lines()) + "\n"
        path.write_text(v1_raw, encoding="utf-8", newline="\n")

        ledger = AuditLedger(path)
        rotated = ledger.rotated_legacy_path
        if rotated is None:
            self.fail("Expected v1 Airlock ledger to rotate aside")
        self.assertTrue(rotated.name.startswith("airlock.jsonl.v1-"))
        self.assertEqual(ledger.rotated_legacy_format, "v1_airlock")
        self.assertEqual(rotated.read_text(encoding="utf-8"), v1_raw)

        entry = ledger.record(
            ZoneEvent(
                event_id="evt-after-rot",
                timestamp_utc="2026-11-25T22:05:00Z",
                zone="airlock",
                action="tools/call",
                verdict_allow=True,
                severity="ALLOW",
                rule_id="airlock.allow",
                reason="ok",
                artifact_sha256="c" * 64,
                metadata={"session_id": "sess-rot"},
            )
        )
        self.assertEqual(entry.schema_version, 2)
        self.assertEqual(entry.source, "airlock")
        self.assertEqual(entry.seq, 1)

        res = verify_ledger(path)
        self.assertTrue(res.valid, res.reason)
        self.assertEqual(res.ledger_format, "v2")
        self.assertEqual(res.entry_count, 2)

        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(rows[0]["event"]["rule_id"], "core.ledger_rotated")
        self.assertEqual(rows[0]["event"]["metadata"]["event_type"], "ledger_rotated")
        self.assertEqual(rows[0]["event"]["metadata"]["rotated_from"], rotated.name)

    def test_v1_airlock_mixed_and_tampered_fail_closed_and_refuse_symlink(self) -> None:
        from mellyn.core.audit import AuditLedger, verify_ledger
        from mellyn.ir_lab.reconstruct import reconstruct_incident

        v1_air_lines = _build_v1_airlock_lines()
        ledger_path = self.root / "ok.jsonl"
        AuditLedger(ledger_path)
        from mellyn.core.schemas import ZoneEvent

        AuditLedger(ledger_path).record(
            ZoneEvent(
                event_id="e0",
                timestamp_utc="2026-11-25T22:05:00Z",
                zone="airlock",
                action="tools/call",
                verdict_allow=True,
                severity="ALLOW",
                rule_id="airlock.allow",
                reason="ok",
                artifact_sha256="d" * 64,
                metadata={"session_id": "s"},
            )
        )
        v2_line = ledger_path.read_text(encoding="utf-8").splitlines()[0]

        mixed = self.root / "mixed.jsonl"
        mixed_text = "\n".join([v1_air_lines[0], v2_line]) + "\n"
        mixed.write_text(mixed_text, encoding="utf-8", newline="\n")
        self.assertFalse(verify_ledger(mixed).valid)
        with self.assertRaises(ValueError):
            AuditLedger(mixed)
        self.assertEqual(mixed.read_text(encoding="utf-8"), mixed_text)
        self.assertEqual(list(self.root.glob("mixed.jsonl.v1-*")), [])

        with mock.patch.object(Path, "is_symlink", lambda p: p == ledger_path):
            with self.assertRaises(ValueError):
                AuditLedger(ledger_path)
            self.assertFalse(verify_ledger(ledger_path).valid)
            report = reconstruct_incident(ledger_path)
            self.assertEqual(report.status, "INTEGRITY_COMPROMISED")

    def test_two_process_concurrent_appends_airlock_writer(self) -> None:
        from mellyn.core.audit import verify_ledger

        ledger_path = self.root / "concurrent_airlock.jsonl"
        worker_code = textwrap.dedent(
            """\
            import sys
            from pathlib import Path
            from mellyn.core.audit import AuditLedger
            from mellyn.core.schemas import ZoneEvent

            path = Path(sys.argv[1])
            worker_id = sys.argv[2]
            count = int(sys.argv[3])
            ledger = AuditLedger(path)
            for idx in range(count):
                ledger.record(
                    ZoneEvent(
                        event_id=f"evt-{worker_id}-{idx}",
                        timestamp_utc="2026-11-25T22:05:00Z",
                        zone="airlock",
                        action="tools/call",
                        verdict_allow=True,
                        severity="ALLOW",
                        rule_id="airlock.allow",
                        reason=f"ok-{worker_id}-{idx}",
                        artifact_sha256="a" * 64,
                        metadata={"session_id": f"sess-{worker_id}"},
                    )
                )
            """
        )
        env = dict(os.environ)
        env["PYTHONPATH"] = str(SRC_DIR) + os.pathsep + env.get("PYTHONPATH", "")
        procs = [
            subprocess.Popen(  # noqa: S603 - test-owned fixed python invocation
                [sys.executable, "-c", worker_code, str(ledger_path), f"a{i}", "15"],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for i in range(2)
        ]
        for proc in procs:
            out, err = proc.communicate(timeout=30)
            self.assertEqual(proc.returncode, 0, f"worker failed: {err}\n{out}")

        res = verify_ledger(ledger_path)
        self.assertTrue(res.valid, res.reason)
        self.assertEqual(res.ledger_format, "v2")
        self.assertEqual(res.entry_count, 30)

    def test_reconstruct_and_cli_ir_on_gateway_v1_v2_and_demo_ledgers(self) -> None:
        from mellyn.ir_lab.reconstruct import main as ir_main
        from mellyn.ir_lab.reconstruct import reconstruct_incident, render_markdown

        gw_path = self.root / "gateway_session.jsonl"
        _make_gateway_v2_ledger(gw_path)

        report = reconstruct_incident(gw_path)
        self.assertTrue(report.chain_valid)
        self.assertEqual(report.status, "BLOCKED_ACTIVITY")
        self.assertEqual(report.verification.ledger_format, "v2")
        self.assertEqual(report.session_count, 1)
        self.assertEqual(report.total_events, 4)
        self.assertEqual(len(report.sessions[0].block_precursors), 2)
        self.assertEqual(report.sessions[0].zones_traversed, ["gateway", "egress"])
        self.assertEqual(report.sessions[0].enforcement_mode, "enforce")

        md = render_markdown(report)
        self.assertIn("BLOCKED_ACTIVITY", md)
        self.assertNotIn("<b>", md)
        rows = [ln for ln in md.splitlines() if ln.startswith("| ") and not ln.startswith("| Seq") and "---" not in ln]
        self.assertEqual(len(rows), 4)

        # CLI `mellyn-ir --json` works on gateway ledger
        ir_out = io.StringIO()
        with contextlib.redirect_stdout(ir_out):
            rc = ir_main([str(gw_path), "--json"])
        self.assertEqual(rc, 0)
        parsed = json.loads(ir_out.getvalue())
        self.assertEqual(parsed["status"], "BLOCKED_ACTIVITY")
        self.assertEqual(parsed["verification"]["ledger_format"], "v2")

        # Observe-mode gateway ledger + aad_fire trigger
        obs_path = self.root / "gateway_obs.jsonl"
        obs_logger, obs_handle = AuditLogger.open_chained(obs_path, enforcement_mode="observe")
        try:
            obs_logger.record_containment(
                session_id="ses-obs",
                tool_name="export_data",
                mcp_server="docs",
                decision="observed_aad",
                reasons=("Observed canary exfil.",),
            )
        finally:
            obs_handle.close()
        obs_report = reconstruct_incident(obs_path)
        self.assertEqual(obs_report.status, "OBSERVED_VIOLATIONS")
        self.assertEqual(obs_report.observed_aad_count, 1)

        # Read-only v1 gateway & v1 airlock fixtures reconstruct cleanly via mellyn-ir
        v1_gw = self.root / "v1_gw.jsonl"
        v1_gw.write_text("\n".join(_build_v1_gateway_lines(include_raw_line_break=True)) + "\n", encoding="utf-8")
        v1_gw_report = reconstruct_incident(v1_gw)
        self.assertTrue(v1_gw_report.chain_valid)
        self.assertEqual(v1_gw_report.status, "BLOCKED_ACTIVITY")
        self.assertEqual(v1_gw_report.verification.ledger_format, "v1_gateway")

        v1_air = self.root / "v1_air.jsonl"
        v1_air.write_text("\n".join(_build_v1_airlock_lines()) + "\n", encoding="utf-8", newline="\n")
        v1_air_report = reconstruct_incident(v1_air)
        self.assertTrue(v1_air_report.chain_valid)
        self.assertEqual(v1_air_report.status, "BLOCKED_ACTIVITY")
        self.assertEqual(v1_air_report.verification.ledger_format, "v1_airlock")


if __name__ == "__main__":
    unittest.main()
