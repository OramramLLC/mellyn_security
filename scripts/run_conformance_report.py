#!/usr/bin/env python3
"""
Execute Mellyn Security's fast conformance profile and emit versioned JSON + Markdown assurance reports.

Always writes the sanitized JSON and Markdown artifacts before exiting, even when one or more
conformance cases fail or error, so CI retains diagnostic evidence on failed runs.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"
for _p in (REPO_ROOT, BACKEND_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from tests.conformance.cases import FORBIDDEN_CONFORMANCE_MARKERS, execute_conformance_profile  # noqa: E402
from tests.conformance.recorder import build_assurance_report, write_assurance_artifacts  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate Mellyn Security Control Assurance Report (fast profile)")
    parser.add_argument("--json-out", type=Path, required=True, help="Output path for versioned JSON assurance report")
    parser.add_argument("--markdown-out", type=Path, required=True, help="Output path for rendered Markdown summary")
    args = parser.parse_args(argv)

    recorder = execute_conformance_profile("fast")
    report = build_assurance_report(
        recorder.records,
        execution_profile="fast",
        forbidden_markers=FORBIDDEN_CONFORMANCE_MARKERS,
    )
    write_assurance_artifacts(
        report,
        json_path=args.json_out,
        markdown_path=args.markdown_out,
        forbidden_markers=FORBIDDEN_CONFORMANCE_MARKERS,
    )

    counts = report["summary"]["counts"]
    print(
        f"Control Assurance Report ({report['execution_profile']}): "
        f"pass={counts['pass']} fail={counts['fail']} error={counts['error']} not_run={counts['not_run']}"
    )
    return 1 if recorder.has_failures_or_errors() else 0


if __name__ == "__main__":
    sys.exit(main())
