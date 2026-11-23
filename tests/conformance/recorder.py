"""
Evidence recorder, audit verifier, and versioned JSON/Markdown Control Assurance Report renderer.

Design invariants:
  1. One comparison (`evaluate_observation`) determines both `unittest` pass/fail and the JSON report row.
  2. Statuses are strictly `pass`, `fail`, `error`, and `not_run`:
     - A denied/escalated call that still reached `FakeDownstream` is `fail`.
     - A matching decision whose required `AuditEvent` is missing, incomplete, or leaks a marker is `fail`.
     - An unexpected exception inside a probe/case is `error`.
     - A case belonging to another execution profile (e.g. `linux-container` during `fast`) is `not_run`.
  3. Markdown is rendered exclusively from the versioned JSON dictionary after leak/path sanitization.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from mellyn.audit import EMPTY_ARGS_SHA256  # noqa: E402
from mellyn.models import canonical_json  # noqa: E402


def canonical_args_sha256(arguments: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(arguments).encode("utf-8")).hexdigest()


REPORT_SCHEMA_VERSION = "1.0"
# The ATLAS release the `mitre_atlas` mitigation IDs below were checked against (mitre-atlas/atlas-data). The agent
# mitigations AML.M0027/AML.M0028 only exist from the v5 line, so the report must not claim an older edition.
MITRE_ATLAS_EDITION = "5.6.0"
# Every ATLAS mitigation a case may cite, with its official name, so a typo or a stale ID fails the suite.
MITRE_ATLAS_MITIGATIONS: dict[str, str] = {
    "AML.M0014": "Verify AI Artifacts",
    "AML.M0024": "AI Telemetry Logging",
    "AML.M0027": "Single-User AI Agent Permissions Configuration",
    "AML.M0028": "AI Agent Tools Permissions Configuration",
}
VALID_STATUSES: frozenset[str] = frozenset({"pass", "fail", "error", "not_run"})
VALID_PROFILES: frozenset[str] = frozenset({"fast", "linux-container"})

REQUIRED_AUDIT_EVENT_KEYS: frozenset[str] = frozenset(
    {
        "audit_id",
        "timestamp",
        "session_id",
        "tool_name",
        "mcp_server",
        "decision",
        "risk_tier",
        "tainted",
        "taint_sources",
        "args_sha256",
        "reasons",
        "policy_id",
        "grant_id",
        "event_type",
        "taint_count",
    }
)

OUT_OF_SCOPE_NOTES: tuple[str, ...] = (
    "Model pre-training, fine-tuning data poisoning, and weight tampering (OWASP LLM04) are outside Plane-3 scope.",
    "Vector/embedding store inversion and RAG ranking quality (OWASP LLM08) are not measured by gateway conformance.",
    "Model factual accuracy, hallucinated prose, and misinformation (OWASP LLM09) are outside tool authorization.",
    "Multi-turn autonomous goal drift without unauthorized tool/resource calls is outside gateway enforcement scope.",
    "Host OS kernel sandboxing (seccomp/AppArmor/Landlock) is complementary infrastructure outside policy scope.",
)

# Patterns that must never appear in an exported customer or portfolio assurance report.
_MACHINE_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"[A-Za-z]:\\\\"),
    re.compile(r"[A-Za-z]:/Users/", re.IGNORECASE),
    re.compile(r"(?:^|[\s\"'])/(?:home|Users|private/var/folders|tmp/tmp)[/\w.-]*"),
)


@dataclass(frozen=True)
class ControlMapping:
    owasp_llm_2025: tuple[str, ...] = ()
    owasp_agentic_2026: tuple[str, ...] = ()
    mitre_atlas: tuple[str, ...] = ()


@dataclass(frozen=True)
class CaseSpec:
    case_id: str
    family: str
    control_ids: tuple[str, ...]
    mappings: ControlMapping
    profile: str
    synthetic_case: str
    evidence_source: str
    expected_summary: dict[str, Any]


@dataclass(frozen=True)
class AuditVerification:
    required: bool
    matching_events: int = 0
    decision_matches: bool = False
    argument_digest_matches: bool = False
    synthetic_marker_absent: bool = True
    complete: bool = True


@dataclass(frozen=True)
class CaseOutcome:
    observed: dict[str, Any]
    audit: AuditVerification


@dataclass(frozen=True)
class CaseRecord:
    case_id: str
    family: str
    control_ids: list[str]
    mappings: dict[str, list[str]]
    profile: str
    synthetic_case: str
    evidence_source: str
    expected: dict[str, Any]
    observed: dict[str, Any]
    audit: dict[str, Any]
    status: str
    failure_detail: str | None = None


def verify_audit_sink(
    jsonl_text: str,
    *,
    expected_decision: str,
    expected_arguments: dict[str, Any] | None = None,
    correlation_id: str | None = None,
    forbidden_markers: Sequence[str] = (),
) -> AuditVerification:
    """
    Correlate a JSONL audit sink against an expected authorization or taint event.

    Checks required `AuditEvent` fields, exact `args_sha256` digest, decision match, and
    absence of every caller/secret canary marker across the entire sink.
    """
    marker_absent = all(marker not in jsonl_text for marker in forbidden_markers if marker)
    lines = [line for line in jsonl_text.splitlines() if line.strip()]
    parsed_events: list[dict[str, Any]] = []
    schema_valid = True
    for raw in lines:
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            schema_valid = False
            continue
        if not isinstance(obj, dict) or not (REQUIRED_AUDIT_EVENT_KEYS <= obj.keys()):
            schema_valid = False
            continue
        parsed_events.append(obj)

    expected_digest = EMPTY_ARGS_SHA256 if expected_arguments is None else canonical_args_sha256(expected_arguments)

    if correlation_id is not None:
        candidates = [ev for ev in parsed_events if ev.get("audit_id") == correlation_id]
    else:
        candidates = [ev for ev in parsed_events if ev.get("decision") == expected_decision]

    matching_count = len(candidates)
    decision_ok = matching_count >= 1 and all(ev.get("decision") == expected_decision for ev in candidates)
    digest_ok = matching_count >= 1 and all(ev.get("args_sha256") == expected_digest for ev in candidates)
    complete = schema_valid and matching_count >= 1 and decision_ok and digest_ok and marker_absent

    return AuditVerification(
        required=True,
        matching_events=matching_count,
        decision_matches=decision_ok,
        argument_digest_matches=digest_ok,
        synthetic_marker_absent=marker_absent,
        complete=complete,
    )


def non_audit_verification(*, raw_evidence_text: str = "", forbidden_markers: Sequence[str] = ()) -> AuditVerification:
    """Audit applicability descriptor for pre-authorization protocol or static scanner cases."""
    marker_absent = all(marker not in raw_evidence_text for marker in forbidden_markers if marker)
    return AuditVerification(
        required=False,
        matching_events=0,
        decision_matches=False,
        argument_digest_matches=False,
        synthetic_marker_absent=marker_absent,
        complete=marker_absent,
    )


def evaluate_observation(
    spec: CaseSpec,
    outcome: CaseOutcome,
) -> CaseRecord:
    """Compare `spec.expected_summary` and `outcome` to produce a single authoritative `CaseRecord`."""
    expected = dict(spec.expected_summary)
    observed = dict(outcome.observed)
    audit = outcome.audit

    reasons: list[str] = []
    if observed != expected:
        reasons.append(f"expected {expected!r} != observed {observed!r}")
    if audit.required and not audit.complete:
        reasons.append(f"required audit evidence incomplete ({asdict(audit)})")
    if not audit.synthetic_marker_absent:
        reasons.append("synthetic secret/canary marker leaked into evidence")

    status = "pass" if not reasons else "fail"
    return CaseRecord(
        case_id=spec.case_id,
        family=spec.family,
        control_ids=list(spec.control_ids),
        mappings={
            "owasp_llm_2025": list(spec.mappings.owasp_llm_2025),
            "owasp_agentic_2026": list(spec.mappings.owasp_agentic_2026),
            "mitre_atlas": list(spec.mappings.mitre_atlas),
        },
        profile=spec.profile,
        synthetic_case=spec.synthetic_case,
        evidence_source=spec.evidence_source,
        expected=expected,
        observed=observed,
        audit=asdict(audit),
        status=status,
        failure_detail="; ".join(reasons) if reasons else None,
    )


def make_not_run_record(spec: CaseSpec) -> CaseRecord:
    return CaseRecord(
        case_id=spec.case_id,
        family=spec.family,
        control_ids=list(spec.control_ids),
        mappings={
            "owasp_llm_2025": list(spec.mappings.owasp_llm_2025),
            "owasp_agentic_2026": list(spec.mappings.owasp_agentic_2026),
            "mitre_atlas": list(spec.mappings.mitre_atlas),
        },
        profile=spec.profile,
        synthetic_case=spec.synthetic_case,
        evidence_source=spec.evidence_source,
        expected=dict(spec.expected_summary),
        observed={},
        audit=asdict(
            AuditVerification(
                required=spec.evidence_source == "audit_jsonl_and_downstream_spy",
                complete=False,
            )
        ),
        status="not_run",
        failure_detail=None,
    )


def make_error_record(spec: CaseSpec, exc: BaseException) -> CaseRecord:
    return CaseRecord(
        case_id=spec.case_id,
        family=spec.family,
        control_ids=list(spec.control_ids),
        mappings={
            "owasp_llm_2025": list(spec.mappings.owasp_llm_2025),
            "owasp_agentic_2026": list(spec.mappings.owasp_agentic_2026),
            "mitre_atlas": list(spec.mappings.mitre_atlas),
        },
        profile=spec.profile,
        synthetic_case=spec.synthetic_case,
        evidence_source=spec.evidence_source,
        expected=dict(spec.expected_summary),
        observed={"probe_error": type(exc).__name__},
        audit=asdict(
            AuditVerification(
                required=spec.evidence_source == "audit_jsonl_and_downstream_spy",
                complete=False,
            )
        ),
        status="error",
        failure_detail=f"probe raised {type(exc).__name__}",
    )


class EvidenceRecorder:
    """Collects conformance `CaseRecord`s across an execution profile and builds sanitized reports."""

    def __init__(self, *, execution_profile: str, forbidden_markers: Sequence[str] = ()) -> None:
        if execution_profile not in VALID_PROFILES:
            raise ValueError(f"Unsupported execution_profile: {execution_profile!r}")
        self.execution_profile = execution_profile
        self._records: dict[str, CaseRecord] = {}
        self._forbidden_markers: set[str] = {m for m in forbidden_markers if m}

    def register_forbidden_markers(self, markers: Sequence[str]) -> None:
        self._forbidden_markers.update(m for m in markers if m)

    def run_case(self, spec: CaseSpec, fn: Callable[[], CaseOutcome]) -> CaseRecord:
        if spec.profile != self.execution_profile:
            rec = make_not_run_record(spec)
            self._records[spec.case_id] = rec
            return rec
        try:
            outcome = fn()
            rec = evaluate_observation(spec, outcome)
        except Exception as exc:  # noqa: BLE001 - broken probe becomes status="error", never silently passes
            rec = make_error_record(spec, exc)
        self._records[spec.case_id] = rec
        return rec

    def record_direct(self, record: CaseRecord) -> None:
        if record.status not in VALID_STATUSES:
            raise ValueError(f"Invalid case status: {record.status!r}")
        self._records[record.case_id] = record

    @property
    def records(self) -> list[CaseRecord]:
        return list(self._records.values())

    def has_failures_or_errors(self) -> bool:
        return any(r.status in ("fail", "error") for r in self._records.values())


def _git_commit_sha(repo_root: Path = REPO_ROOT) -> str:
    git = shutil.which("git")
    if not git or not (repo_root / ".git").exists():
        return "unknown"
    proc = subprocess.run(  # noqa: S603 - fixed git argv
        [git, "rev-parse", "HEAD"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    sha = proc.stdout.strip()
    return sha if proc.returncode == 0 and re.fullmatch(r"[0-9a-f]{40}", sha) else "unknown"


def compute_policy_bundle_digest(repo_root: Path = REPO_ROOT) -> str:
    """Compute a deterministic SHA-256 over the repository's canonical policy files."""
    h = hashlib.sha256()
    for rel in ("config/mellyn-policy.example.toml", "config/mellyn-self-policy.toml"):
        p = repo_root / rel
        if p.is_file():
            normalized = p.read_text(encoding="utf-8").replace("\r\n", "\n")
            h.update(f"{rel}\0{len(normalized)}\0".encode())
            h.update(normalized.encode("utf-8"))
    return h.hexdigest()


def assert_report_redacted(serialized_text: str, *, extra_forbidden: Sequence[str] = ()) -> None:
    """Fail closed if any synthetic credential/canary marker or host-specific path appears in exported text."""
    temp_root = str(Path(tempfile.gettempdir()).resolve())
    repo_str = str(REPO_ROOT.resolve())
    for forbidden in (repo_str, repo_str.replace("\\", "/"), temp_root, temp_root.replace("\\", "/"), *extra_forbidden):
        if forbidden and len(forbidden) >= 4 and forbidden in serialized_text:
            raise ValueError(f"Exported assurance report leaked forbidden token/path: {forbidden[:24]!r}...")
    for pattern in _MACHINE_PATH_PATTERNS:
        m = pattern.search(serialized_text)
        if m is not None:
            raise ValueError(f"Exported assurance report leaked machine-specific path matching {m.group(0)!r}")


def build_assurance_report(
    records: Sequence[CaseRecord],
    *,
    execution_profile: str,
    generated_at: str | None = None,
    git_commit: str | None = None,
    policy_sha256: str | None = None,
    forbidden_markers: Sequence[str] = (),
) -> dict[str, Any]:
    """Build a versioned, sanitized JSON-serializable Control Assurance Report dictionary."""
    if execution_profile not in VALID_PROFILES:
        raise ValueError(f"Unsupported execution_profile: {execution_profile!r}")

    ordered = list(records)
    by_status: dict[str, list[str]] = {s: [] for s in ("pass", "fail", "error", "not_run")}
    by_profile: dict[str, dict[str, Any]] = {}

    for rec in ordered:
        if rec.status not in VALID_STATUSES:
            raise ValueError(f"Invalid status {rec.status!r} on case {rec.case_id}")
        by_status[rec.status].append(rec.case_id)
        prof_entry = by_profile.setdefault(
            rec.profile,
            {
                "counts": {"pass": 0, "fail": 0, "error": 0, "not_run": 0},
                "case_ids": {"pass": [], "fail": [], "error": [], "not_run": []},
            },
        )
        prof_entry["counts"][rec.status] += 1
        prof_entry["case_ids"][rec.status].append(rec.case_id)

    overall_status = (
        "fail" if (by_status["fail"] or by_status["error"]) else ("pass" if by_status["pass"] else "not_run")
    )

    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": generated_at or dt.datetime.now(dt.UTC).isoformat(),
        "git_commit": git_commit or _git_commit_sha(),
        "policy_sha256": policy_sha256 or compute_policy_bundle_digest(),
        "python_version": platform.python_version(),
        "platform_system": platform.system().lower(),
        "execution_profile": execution_profile,
        "frameworks": {
            "owasp_llm_top_10": "2025",
            "owasp_agentic_top_10": "2026",
            "mitre_atlas": MITRE_ATLAS_EDITION,
        },
        "overall_status": overall_status,
        "summary": {
            "total_cases": len(ordered),
            "counts": {k: len(v) for k, v in by_status.items()},
            "case_ids_by_status": by_status,
            "by_profile": by_profile,
        },
        "out_of_scope_controls": list(OUT_OF_SCOPE_NOTES),
        "cases": [asdict(rec) for rec in ordered],
    }

    serialized = json.dumps(report, indent=2, sort_keys=True)
    assert_report_redacted(serialized, extra_forbidden=forbidden_markers)
    return report


def render_markdown_report(report: dict[str, Any], *, forbidden_markers: Sequence[str] = ()) -> str:
    """Render a human-readable B2B/portfolio Markdown summary strictly from the JSON `report` dict."""
    summary = report["summary"]
    counts = summary["counts"]
    frameworks = report["frameworks"]

    lines: list[str] = [
        "# Mellyn Security — Control Assurance Report",
        "",
        "## 1. Run Metadata",
        "",
        "| Field | Value |",
        "| :--- | :--- |",
        f"| **Schema Version** | `{report['schema_version']}` |",
        f"| **Execution Profile** | `{report['execution_profile']}` |",
        f"| **Overall Result** | **`{report['overall_status'].upper()}`** |",
        f"| **Git Commit** | `{report['git_commit']}` |",
        f"| **Policy SHA-256** | `{report['policy_sha256'][:16]}...` |",
        f"| **Python / OS** | `{report['python_version']}` (`{report['platform_system']}`) |",
        f"| **Generated At (UTC)** | `{report['generated_at']}` |",
        (
            "| **Framework Editions** | "
            f"OWASP LLM Top 10 `{frameworks['owasp_llm_top_10']}` · "
            f"OWASP Agentic `{frameworks['owasp_agentic_top_10']}` · "
            f"MITRE ATLAS `{frameworks['mitre_atlas']}` |"
        ),
        "",
        "## 2. Execution Summary by Profile",
        "",
        f"- **Total Cases Declared**: `{summary['total_cases']}` "
        f"(`pass={counts['pass']}`, `fail={counts['fail']}`, `error={counts['error']}`, `not_run={counts['not_run']}`)",
        "",
        "| Profile | Pass | Fail | Error | Not Run | Executed Case IDs |",
        "| :--- | :---: | :---: | :---: | :---: | :--- |",
    ]

    for prof_name, prof_data in sorted(report["summary"]["by_profile"].items()):
        p_counts = prof_data["counts"]
        executed_ids = prof_data["case_ids"]["pass"] + prof_data["case_ids"]["fail"] + prof_data["case_ids"]["error"]
        executed_label = ", ".join(f"`{cid}`" for cid in executed_ids) if executed_ids else "*(none in this profile)*"
        lines.append(
            f"| `{prof_name}` | {p_counts['pass']} | {p_counts['fail']} | "
            f"{p_counts['error']} | {p_counts['not_run']} | {executed_label} |"
        )

    lines.extend(
        [
            "",
            "## 3. Control Validation Evidence Matrix",
            "",
            "| Case ID | Controls | OWASP / ATLAS | Profile | Evidence Source | Audit Verified | Status |",
            "| :--- | :--- | :--- | :--- | :--- | :---: | :---: |",
        ]
    )

    for case in report["cases"]:
        ctrls = ", ".join(f"`{c}`" for c in case["control_ids"]) or "*(supply-chain)*"
        maps = case["mappings"]
        tags = [*maps.get("owasp_llm_2025", []), *maps.get("owasp_agentic_2026", []), *maps.get("mitre_atlas", [])]
        tag_str = ", ".join(f"`{t}`" for t in tags)
        audit_info = case["audit"]
        if case["status"] == "not_run":
            audit_str = "`n/a (not_run)`"
        elif audit_info["required"]:
            audit_str = "`yes`" if audit_info["complete"] else "**`NO`**"
        else:
            audit_str = "`n/a (non-audit)`"
        lines.append(
            f"| `{case['case_id']}` | {ctrls} | {tag_str} | `{case['profile']}` | "
            f"`{case['evidence_source']}` | {audit_str} | **`{case['status']}`** |"
        )

    failures = [c for c in report["cases"] if c["status"] in ("fail", "error")]
    if failures:
        lines.extend(["", "## 4. Failures & Errors", ""])
        for f_case in failures:
            lines.append(
                f"- **`{f_case['case_id']}`** (`{f_case['status']}`): {f_case.get('failure_detail') or 'failed'}"
            )

    lines.extend(["", "## Scope Boundaries & Unmeasured Risks", ""])
    for note in report["out_of_scope_controls"]:
        lines.append(f"- {note}")
    lines.append("")

    markdown = "\n".join(lines)
    assert_report_redacted(markdown, extra_forbidden=forbidden_markers)
    return markdown


def write_assurance_artifacts(
    report: dict[str, Any],
    *,
    json_path: Path,
    markdown_path: Path,
    forbidden_markers: Sequence[str] = (),
) -> None:
    """Serialize both JSON and Markdown assurance artifacts atomically after redaction checks."""
    json_text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    assert_report_redacted(json_text, extra_forbidden=forbidden_markers)
    md_text = render_markdown_report(report, forbidden_markers=forbidden_markers)

    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json_text, encoding="utf-8", newline="\n")
    markdown_path.write_text(md_text, encoding="utf-8", newline="\n")
