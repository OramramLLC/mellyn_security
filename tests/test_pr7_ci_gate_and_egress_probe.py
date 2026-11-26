"""
Regression tests for PR 7 runtime & CI wiring:
  - M11: Controlled outside listener + structured routing-denial classifier in verify_container_stack.py
  - L3: Hash-locked CI lint, test, and container Python environments (--require-hashes)
  - Required check names and baseline Ruff enforcement in .github/workflows/ai-security-gate.yml
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
SRC_DIR = REPO_ROOT / "src"
for p in (SRC_DIR, SCRIPTS_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import verify_container_stack as vcs  # noqa: E402

_SHELL_TRUE_SNIPPET = "import subprocess\n\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n"
GATE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ai-security-gate.yml"


def _find_tool(name: str) -> str | None:
    """The tool next to this interpreter (a venv's Scripts/bin) or on PATH."""
    for candidate in (Path(sys.executable).parent / name, Path(sys.executable).parent / f"{name}.exe"):
        if candidate.is_file():
            return str(candidate)
    return shutil.which(name)


class TestDirectEgressProbeClassifier(unittest.TestCase):
    """M11: Direct-egress probe requires explicit kernel routing denial and fails on all 5 non-isolation classes."""

    def test_classifier_accepts_only_kernel_routing_denial_and_rejects_five_failure_classes(self) -> None:
        for routing_errno in ("ENETUNREACH", "EHOSTUNREACH"):
            line = "PROBE_JSON " + json.dumps(
                {
                    "phase": "connect",
                    "status": "error",
                    "http_status": None,
                    "errno_name": routing_errno,
                    "exc_type": "OSError",
                }
            )
            ok, reason = vcs.classify_direct_egress_probe(line + "\n", 0)
            self.assertTrue(ok, f"Expected {routing_errno} to pass, got: {reason}")
            self.assertIn(routing_errno, reason)

        valid_unreach_line = "PROBE_JSON " + json.dumps(
            {
                "phase": "connect",
                "status": "error",
                "http_status": None,
                "errno_name": "ENETUNREACH",
                "exc_type": "OSError",
            }
        )
        rejected_cases = (
            ("missing-empty", "", 0),
            ("missing-legacy-marker", "OUTCOME OSERROR OSError\n", 0),
            ("missing-nonzero-container-exit", valid_unreach_line, 125),
            ("malformed-json", "PROBE_JSON {not-valid-json\n", 0),
            ("malformed-missing-keys", 'PROBE_JSON {"phase": "connect"}\n', 0),
            ("malformed-duplicate-lines", f"{valid_unreach_line}\n{valid_unreach_line}\n", 0),
            (
                "dns-failure",
                "PROBE_JSON "
                + json.dumps(
                    {
                        "phase": "dns",
                        "status": "error",
                        "http_status": None,
                        "errno_name": "EAI_AGAIN",
                        "exc_type": "gaierror",
                    }
                ),
                0,
            ),
            (
                "tls-failure",
                "PROBE_JSON "
                + json.dumps(
                    {
                        "phase": "tls",
                        "status": "error",
                        "http_status": None,
                        "errno_name": None,
                        "exc_type": "SSLCertVerificationError",
                    }
                ),
                0,
            ),
            (
                "http-allowed-200",
                "PROBE_JSON "
                + json.dumps(
                    {
                        "phase": "http",
                        "status": "allowed",
                        "http_status": 200,
                        "errno_name": None,
                        "exc_type": None,
                    }
                ),
                0,
            ),
            (
                "http-error-403",
                "PROBE_JSON "
                + json.dumps(
                    {
                        "phase": "http",
                        "status": "http_error",
                        "http_status": 403,
                        "errno_name": None,
                        "exc_type": "HTTPError",
                    }
                ),
                0,
            ),
            (
                "connect-refused-reachable-host",
                "PROBE_JSON "
                + json.dumps(
                    {
                        "phase": "connect",
                        "status": "error",
                        "http_status": None,
                        "errno_name": "ECONNREFUSED",
                        "exc_type": "ConnectionRefusedError",
                    }
                ),
                0,
            ),
            (
                "connect-timeout-ambiguous",
                "PROBE_JSON "
                + json.dumps(
                    {
                        "phase": "connect",
                        "status": "error",
                        "http_status": None,
                        "errno_name": "ETIMEDOUT",
                        "exc_type": "TimeoutError",
                    }
                ),
                0,
            ),
        )
        for label, stdout, rc in rejected_cases:
            with self.subTest(case=label):
                ok, _reason = vcs.classify_direct_egress_probe(stdout, rc)
                self.assertFalse(ok, f"Expected {label} to fail direct-egress classification!")


class TestRuntimeCiWorkflowAndLockfiles(unittest.TestCase):
    """Required ruleset check names, SHA-pinned guardrails workflow call, hash-locked installs, and baseline Ruff."""

    def test_required_jobs_keep_the_names_the_main_ruleset_requires(self) -> None:
        workflow = GATE_WORKFLOW.read_text(encoding="utf-8")
        names = re.findall(r"^    name: (.+)$", workflow, flags=re.MULTILINE)
        for required in (
            "Secret scan (Gitleaks)",
            "SAST, lint, agent rules & dependency verification",
            "Tests (Python ${{ matrix.python-version }})",
        ):
            with self.subTest(required=required):
                self.assertIn(required, names)
        self.assertIn('python-version: ["3.12", "3.14"]', workflow)

    def test_ci_workflow_pins_mellyn_guardrails_with_least_privilege_and_fail_closed_gates(self) -> None:
        workflow = GATE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("pull_request_target:", workflow)
        self.assertRegex(
            workflow,
            r"uses:\s+OramramLLC/mellyn-guardrails/\.github/workflows/mellyn-reusable-ai-security-gate\.yml@[0-9a-f]{40}",
        )
        self.assertIn("require-pack-rules: true", workflow)

        checkout_count = workflow.count("uses: actions/checkout@")
        self.assertGreaterEqual(checkout_count, 4)
        self.assertEqual(checkout_count, workflow.count("persist-credentials: false"))

    def test_required_wrapper_jobs_fail_unless_the_guardrails_workflow_succeeded(self) -> None:
        """
        The ruleset requires the wrapper jobs' names, not the reusable workflow's own jobs. The wrappers are the gate:
        each must wait for `guardrails`, run even when it fails, and fail unless its result is exactly "success".
        """
        workflow = GATE_WORKFLOW.read_text(encoding="utf-8")
        jobs_text = workflow.split("\njobs:\n", 1)[1]
        jobs = dict(re.findall(r"^  ([A-Za-z0-9_-]+):\n((?:(?:    .*)?\n)+)", jobs_text, flags=re.MULTILINE))

        guardrails = jobs["guardrails"]
        self.assertNotRegex(guardrails, r"(?m)^    (if|continue-on-error):")

        for job_id in ("secrets", "sast-and-supply-chain"):
            with self.subTest(job=job_id):
                job = jobs[job_id]
                self.assertIn("    needs: [guardrails]\n", job)
                self.assertIn("    if: ${{ always() }}\n", job)
                self.assertNotIn("continue-on-error", job)
                first_step = job.split("\n      - ", 2)[1]
                self.assertIn("GUARDRAILS_RESULT: ${{ needs.guardrails.result }}", first_step)
                self.assertRegex(
                    first_step,
                    r'if \[ "\$GUARDRAILS_RESULT" != "success" \]; then\n(?:.*\n)*?\s+exit 1\n\s+fi',
                )

    def test_every_ci_and_dockerfile_pip_install_requires_hashes_and_intended_lockfile(self) -> None:
        sources = {
            "ai-security-gate.yml": GATE_WORKFLOW.read_text(encoding="utf-8"),
            "Dockerfile": (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8"),
        }
        pip_install_re = re.compile(r"pip\s+install[^\n]*(?:\n\s+-r\s+\S+)?")
        total_installs = 0
        for name, content in sources.items():
            active_text = "\n".join(line for line in content.splitlines() if not line.lstrip().startswith("#"))
            matches = pip_install_re.findall(active_text)
            self.assertGreaterEqual(len(matches), 1, f"Expected at least one pip install in {name}")
            for cmd in matches:
                total_installs += 1
                with self.subTest(file=name, cmd=cmd):
                    self.assertIn("--require-hashes", cmd)
                    self.assertIn("--no-deps", cmd)
                    self.assertRegex(cmd, r"-r\s+\S*requirements(?:-ci-(?:lint|tests))?\.lock|\$lock")
        self.assertGreaterEqual(total_installs, 3)

        lint_lock = (REPO_ROOT / "deploy" / "requirements-ci-lint.lock").read_text(encoding="utf-8")
        self.assertIn("ruff==0.17.1", lint_lock)
        self.assertIn("--hash=sha256:", lint_lock)
        self.assertNotIn("semgrep==", lint_lock)

    def test_gate_runs_ruff_with_the_baseline_config(self) -> None:
        workflow = GATE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("ruff check --config ../baseline/pyproject.toml .", workflow)
        self.assertIn("ruff format --check --config ../baseline/pyproject.toml .", workflow)
        self.assertNotRegex(workflow, r"ruff (check|format --check) candidate")
        sast_job = workflow.split("  sast-and-supply-chain:", 1)[1].split("\n  tests:", 1)[0]
        self.assertRegex(sast_job, r"path: baseline\n\s+sparse-checkout: \|(\n\s+\S+)*\n\s+pyproject\.toml")
        self.assertIn("deploy/requirements-ci-lint.lock", sast_job)

    @unittest.skipUnless(_find_tool("ruff"), "ruff is not installed")
    def test_candidate_per_file_ignores_cannot_silence_ruff_under_the_baseline_config(self) -> None:
        ruff = _find_tool("ruff") or "ruff"
        with tempfile.TemporaryDirectory() as tmp:
            baseline, candidate = Path(tmp) / "baseline", Path(tmp) / "candidate"
            (candidate / "backend").mkdir(parents=True)
            baseline.mkdir()
            shutil.copyfile(REPO_ROOT / "pyproject.toml", baseline / "pyproject.toml")
            weakened = (
                (REPO_ROOT / "pyproject.toml")
                .read_text(encoding="utf-8")
                .replace("[tool.ruff.lint]", '[tool.ruff.lint]\nper-file-ignores = { "backend/*" = ["S"] }', 1)
            )
            (candidate / "pyproject.toml").write_text(weakened, encoding="utf-8")
            (candidate / "backend" / "evil.py").write_text(_SHELL_TRUE_SNIPPET, encoding="utf-8")

            def lint(*extra: str) -> str:
                argv = [ruff, "check", "--output-format", "concise", "--no-cache", *extra, "."]
                done = subprocess.run(argv, cwd=candidate, capture_output=True, text=True, check=False)  # noqa: S603
                return done.stdout.replace("\\", "/")

            self.assertNotIn("S602", lint())
            judged = lint("--config", "../baseline/pyproject.toml")
            self.assertIn("backend/evil.py", judged)


if __name__ == "__main__":
    unittest.main()
