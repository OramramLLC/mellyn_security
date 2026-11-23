"""
Unittest conformance runner and negative tests for the EvidenceRecorder and Control Assurance Report.

Discovered automatically by `python -m unittest discover -s tests` and `pytest`.
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"
SCRIPTS_DIR = REPO_ROOT / "scripts"
for _p in (REPO_ROOT, BACKEND_DIR, SCRIPTS_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import run_conformance_report as rcr  # noqa: E402
import verify_container_stack as vcs  # noqa: E402

from tests.conformance.cases import (  # noqa: E402
    CONFORMANCE_SUITE,
    FORBIDDEN_CONFORMANCE_MARKERS,
    LINUX_AUDIT_ISOLATION_SPEC,
    LINUX_NETWORK_EGRESS_SPEC,
    execute_conformance_profile,
)
from tests.conformance.recorder import (  # noqa: E402
    REPORT_SCHEMA_VERSION,
    AuditVerification,
    CaseOutcome,
    CaseSpec,
    ControlMapping,
    EvidenceRecorder,
    assert_report_redacted,
    build_assurance_report,
    evaluate_observation,
    make_error_record,
    non_audit_verification,
    render_markdown_report,
    verify_audit_sink,
    write_assurance_artifacts,
)


class TestFastConformanceSuite(unittest.TestCase):
    """Execute all six synthetic conformance families through the authoritative EvidenceRecorder."""

    def test_all_fast_conformance_cases_pass_and_linux_cases_are_marked_not_run(self) -> None:
        recorder = execute_conformance_profile("fast")
        self.assertEqual(len(recorder.records), len(CONFORMANCE_SUITE))

        fast_records = [r for r in recorder.records if r.profile == "fast"]
        linux_records = [r for r in recorder.records if r.profile == "linux-container"]
        self.assertGreaterEqual(len(fast_records), 14)
        self.assertEqual(len(linux_records), 2)

        for rec in fast_records:
            with self.subTest(case_id=rec.case_id):
                self.assertEqual(rec.status, "pass", f"Case {rec.case_id} failed: {rec.failure_detail}")

        for rec in linux_records:
            with self.subTest(linux_case_id=rec.case_id):
                self.assertEqual(rec.status, "not_run")
                self.assertEqual(rec.observed, {})

        report = build_assurance_report(
            recorder.records,
            execution_profile="fast",
            forbidden_markers=FORBIDDEN_CONFORMANCE_MARKERS,
        )
        self.assertEqual(report["schema_version"], REPORT_SCHEMA_VERSION)
        self.assertEqual(report["overall_status"], "pass")
        self.assertEqual(report["summary"]["counts"]["pass"], len(fast_records))
        self.assertEqual(report["summary"]["counts"]["not_run"], len(linux_records))
        self.assertEqual(report["summary"]["counts"]["fail"], 0)
        self.assertEqual(report["summary"]["counts"]["error"], 0)

        md = render_markdown_report(report, forbidden_markers=FORBIDDEN_CONFORMANCE_MARKERS)
        self.assertIn("# Mellyn Security — Control Assurance Report", md)
        self.assertIn("`linux-audit-writer-uid-isolation`", md)
        self.assertIn("`not_run`", md)


class TestRecorderFailureSemanticsAndRedaction(unittest.TestCase):
    """Verify pass/fail/error/not_run classification, audit completeness enforcement, and leak rejection."""

    def _sample_spec(self, *, profile: str = "fast", audit_required: bool = True) -> CaseSpec:
        return CaseSpec(
            case_id="synthetic-sample-case",
            family="paths-resources-and-egress",
            control_ids=("TM-03",),
            mappings=ControlMapping(
                owasp_llm_2025=("LLM02",), owasp_agentic_2026=("ASI02",), mitre_atlas=("AML.M0028",)
            ),
            profile=profile,
            synthetic_case="Read a temporary file designated sensitive",
            evidence_source="audit_jsonl_and_downstream_spy" if audit_required else "scanner_cli_result",
            expected_summary={"decision": "deny", "downstream_calls": 0},
        )

    def test_denied_call_that_reached_downstream_is_recorded_as_fail(self) -> None:
        spec = self._sample_spec()
        complete_audit = AuditVerification(
            required=True,
            matching_events=1,
            decision_matches=True,
            argument_digest_matches=True,
            synthetic_marker_absent=True,
            complete=True,
        )
        rec = evaluate_observation(
            spec,
            CaseOutcome(observed={"decision": "deny", "downstream_calls": 1}, audit=complete_audit),
        )
        self.assertEqual(rec.status, "fail")
        self.assertIn("downstream_calls", rec.failure_detail or "")

    def test_matching_decision_with_missing_required_audit_event_is_recorded_as_fail(self) -> None:
        spec = self._sample_spec()
        missing_audit = verify_audit_sink("", expected_decision="deny", expected_arguments={"path": ".env"})
        self.assertFalse(missing_audit.complete)

        rec = evaluate_observation(
            spec,
            CaseOutcome(observed={"decision": "deny", "downstream_calls": 0}, audit=missing_audit),
        )
        self.assertEqual(rec.status, "fail")
        self.assertIn("audit evidence incomplete", rec.failure_detail or "")

    def test_broken_probe_exception_is_recorded_as_error_not_pass(self) -> None:
        recorder = EvidenceRecorder(execution_profile="fast")
        spec = self._sample_spec()

        def _broken_probe() -> CaseOutcome:
            raise RuntimeError("synthetic broken probe")

        rec = recorder.run_case(spec, _broken_probe)
        self.assertEqual(rec.status, "error")
        self.assertTrue(recorder.has_failures_or_errors())

    def test_redaction_gate_rejects_machine_paths_and_synthetic_markers(self) -> None:
        for leaked in (
            '{"detail": "C:\\\\Users\\\\alice\\\\repo\\\\secret.txt"}',
            '{"detail": "/home/runner/work/mellyn/workspace/.env"}',
            f'{{"detail": "{FORBIDDEN_CONFORMANCE_MARKERS[0]}"}}',
        ):
            with self.subTest(leaked=leaked[:28]), self.assertRaises(ValueError):
                assert_report_redacted(leaked, extra_forbidden=FORBIDDEN_CONFORMANCE_MARKERS)

    def test_report_cli_writes_artifacts_even_on_failure_and_returns_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            json_ok = out_dir / "fast-pass.json"
            md_ok = out_dir / "fast-pass.md"

            with mock.patch("sys.stdout", io.StringIO()):
                rc_pass = rcr.main(["--json-out", str(json_ok), "--markdown-out", str(md_ok)])
            self.assertEqual(rc_pass, 0)
            self.assertTrue(json_ok.is_file())
            self.assertTrue(md_ok.is_file())
            parsed_ok = json.loads(json_ok.read_text(encoding="utf-8"))
            self.assertEqual(parsed_ok["overall_status"], "pass")

            # Simulate a failing case: CLI must STILL write both JSON and Markdown, then return exit code 1!
            failing_recorder = EvidenceRecorder(execution_profile="fast")
            spec = self._sample_spec()
            failing_recorder.run_case(
                spec,
                lambda: CaseOutcome(
                    observed={"decision": "deny", "downstream_calls": 1},
                    audit=non_audit_verification(),
                ),
            )
            json_fail = out_dir / "fast-fail.json"
            md_fail = out_dir / "fast-fail.md"
            with (
                mock.patch.object(rcr, "execute_conformance_profile", return_value=failing_recorder),
                mock.patch("sys.stdout", io.StringIO()),
            ):
                rc_fail = rcr.main(["--json-out", str(json_fail), "--markdown-out", str(md_fail)])

            self.assertEqual(rc_fail, 1)
            self.assertTrue(json_fail.is_file())
            self.assertTrue(md_fail.is_file())
            parsed_fail = json.loads(json_fail.read_text(encoding="utf-8"))
            self.assertEqual(parsed_fail["overall_status"], "fail")
            self.assertEqual(parsed_fail["summary"]["counts"]["fail"], 1)
            self.assertIn("## 4. Failures & Errors", md_fail.read_text(encoding="utf-8"))

            # Also verify round-trip write_assurance_artifacts helper directly
            write_assurance_artifacts(parsed_ok, json_path=json_ok, markdown_path=md_ok)

    def test_linux_profile_report_and_ci_wiring_separate_fast_and_container_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            linux_rec = execute_conformance_profile("linux-container")
            # Fast cases must be not_run under linux-container profile
            fast_statuses = {r.status for r in linux_rec.records if r.profile == "fast"}
            self.assertEqual(fast_statuses, {"not_run"})

            # Simulate passing Linux audit-isolation and network-egress observations
            complete_audit = AuditVerification(
                required=True,
                matching_events=1,
                decision_matches=True,
                argument_digest_matches=True,
                synthetic_marker_absent=True,
                complete=True,
            )
            linux_rec.record_direct(
                evaluate_observation(
                    LINUX_AUDIT_ISOLATION_SPEC,
                    CaseOutcome(
                        observed=dict(LINUX_AUDIT_ISOLATION_SPEC.expected_summary),
                        audit=complete_audit,
                    ),
                )
            )
            linux_rec.record_direct(
                evaluate_observation(
                    LINUX_NETWORK_EGRESS_SPEC,
                    CaseOutcome(
                        observed=dict(LINUX_NETWORK_EGRESS_SPEC.expected_summary),
                        audit=non_audit_verification(),
                    ),
                )
            )

            j_path = out_dir / "linux.json"
            m_path = out_dir / "linux.md"
            vcs.emit_linux_assurance_report(linux_rec, json_out=j_path, markdown_out=m_path)
            parsed = json.loads(j_path.read_text(encoding="utf-8"))
            self.assertEqual(parsed["execution_profile"], "linux-container")
            self.assertEqual(parsed["overall_status"], "pass")
            self.assertEqual(parsed["summary"]["by_profile"]["linux-container"]["counts"]["pass"], 2)
            self.assertEqual(parsed["summary"]["by_profile"]["fast"]["counts"]["not_run"], 14)

            # Simulate an unexpected Docker failure recording error rows and retaining report
            err_rec = execute_conformance_profile("linux-container")
            err_rec.record_direct(make_error_record(LINUX_AUDIT_ISOLATION_SPEC, RuntimeError("docker daemon down")))
            err_rec.record_direct(make_error_record(LINUX_NETWORK_EGRESS_SPEC, RuntimeError("docker daemon down")))
            j_err = out_dir / "linux-err.json"
            m_err = out_dir / "linux-err.md"
            vcs.emit_linux_assurance_report(err_rec, json_out=j_err, markdown_out=m_err)
            parsed_err = json.loads(j_err.read_text(encoding="utf-8"))
            self.assertEqual(parsed_err["overall_status"], "fail")
            self.assertEqual(parsed_err["summary"]["counts"]["error"], 2)

        ci_yaml = (REPO_ROOT / ".github" / "workflows" / "ai-security-gate.yml").read_text(encoding="utf-8")
        self.assertIn("scripts/run_conformance_report.py", ci_yaml)
        self.assertIn("control-assurance-fast-py", ci_yaml)
        self.assertIn("control-assurance-linux-container", ci_yaml)
        self.assertGreaterEqual(ci_yaml.count("if: always()"), 4)
        self.assertIn("actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2", ci_yaml)
        self.assertNotIn("ea165f8d65b6e75b540449e92b4886f43607fa02", ci_yaml)  # v4.6.2 (Node 20)


class TestFrameworkMappingsAreAccurate(unittest.TestCase):
    """The report is read by customers: every framework edition and ID it cites must be real and current."""

    def test_report_cites_the_atlas_edition_the_ids_were_checked_against(self) -> None:
        from tests.conformance.recorder import MITRE_ATLAS_EDITION

        report = build_assurance_report([], execution_profile="fast", git_commit="0" * 40, policy_sha256="0" * 64)
        self.assertEqual(report["frameworks"]["mitre_atlas"], MITRE_ATLAS_EDITION)
        # AML.M0027 / AML.M0028 (agent permissions) only exist from ATLAS v5, so an older label would be false.
        self.assertTrue(MITRE_ATLAS_EDITION.startswith("5."), MITRE_ATLAS_EDITION)
        self.assertIn(f"MITRE ATLAS `{MITRE_ATLAS_EDITION}`", render_markdown_report(report))

    def test_every_cited_id_is_a_known_mitigation_or_a_valid_owasp_entry(self) -> None:
        from tests.conformance.recorder import MITRE_ATLAS_MITIGATIONS

        cited_atlas: set[str] = set()
        for spec, _fn in CONFORMANCE_SUITE:
            with self.subTest(case_id=spec.case_id):
                for atlas_id in spec.mappings.mitre_atlas:
                    self.assertIn(atlas_id, MITRE_ATLAS_MITIGATIONS)
                    cited_atlas.add(atlas_id)
                for llm_id in spec.mappings.owasp_llm_2025:
                    self.assertRegex(llm_id, r"^LLM(0[1-9]|10)$")
                for asi_id in spec.mappings.owasp_agentic_2026:
                    self.assertRegex(asi_id, r"^ASI(0[1-9]|10)$")
        self.assertNotIn("AML.M0010", cited_atlas)  # "Input Restoration" is adversarial-input cleaning, not framing
        self.assertEqual(cited_atlas, set(MITRE_ATLAS_MITIGATIONS))  # no unused entries left in the known list


if __name__ == "__main__":
    unittest.main()
