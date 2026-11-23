"""
Regression tests for PR 7:
  - M11: Controlled outside listener + structured routing-denial classifier in verify_container_stack.py
  - M12: Baseline-vs-candidate guardrail gate isolation (PR candidate cannot judge itself)
  - L3: Separate hash-locked CI scanner and API-test Python environments (--require-hashes)
  - KISS #4: Shared trusted CI guardrail helpers (checksummed Gitleaks, base allowlist, Semgrep ignores)
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import shutil
import tarfile
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
BACKEND_DIR = REPO_ROOT / "backend"
import sys  # noqa: E402

for p in (BACKEND_DIR, SCRIPTS_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import ci_guardrails as cg  # noqa: E402
import verify_container_stack as vcs  # noqa: E402
import verify_dependencies as vd  # noqa: E402


def _make_tar_gz(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = 0o755
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class TestDirectEgressProbeClassifier(unittest.TestCase):
    """M11: Direct-egress probe requires explicit kernel routing denial and fails on all 5 non-isolation classes."""

    def test_classifier_accepts_only_kernel_routing_denial_and_rejects_five_failure_classes(self) -> None:
        # Valid expected routing-denial outcomes (ENETUNREACH / EHOSTUNREACH)
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
        # Five required non-isolation / broken-probe classes + non-routing socket outcomes:
        rejected_cases = (
            # 1. Missing outcome (empty stdout, old NO OUTCOME text, or nonzero container exit)
            ("missing-empty", "", 0),
            ("missing-legacy-marker", "OUTCOME OSERROR OSError\n", 0),
            ("missing-nonzero-container-exit", valid_unreach_line, 125),
            # 2. Malformed JSON / missing keys / duplicate probe lines
            ("malformed-json", "PROBE_JSON {not-valid-json\n", 0),
            ("malformed-missing-keys", 'PROBE_JSON {"phase": "connect"}\n', 0),
            ("malformed-duplicate-lines", f"{valid_unreach_line}\n{valid_unreach_line}\n", 0),
            # 3. DNS resolution failure
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
            # 4. TLS handshake failure (proves TCP packet escaped the internal network!)
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
            # 5. HTTP allowed / HTTP error / ECONNREFUSED / ETIMEDOUT
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


class TestBaselineGateVsCandidateGuardrails(unittest.TestCase):
    """M12: Required gate outcome comes strictly from baseline guardrails, not candidate scripts/exemptions."""

    def test_baseline_selection_enforces_baseline_outcome_despite_weakened_candidate_script(self) -> None:
        with tempfile.TemporaryDirectory() as base_tmp, tempfile.TemporaryDirectory() as cand_tmp:
            baseline = Path(base_tmp)
            candidate = Path(cand_tmp)

            for d in (baseline, candidate):
                (d / "scripts").mkdir(parents=True)
                shutil.copyfile(REPO_ROOT / "scripts" / "sync_agent_rules.py", d / "scripts" / "sync_agent_rules.py")

            # Baseline carries the real dependency verifier; candidate replaces its copy with a no-op bypass!
            shutil.copyfile(
                REPO_ROOT / "scripts" / "verify_dependencies.py",
                baseline / "scripts" / "verify_dependencies.py",
            )
            (candidate / "scripts" / "verify_dependencies.py").write_text(
                "import sys\nsys.exit(0)\n",
                encoding="utf-8",
            )
            # Candidate introduces an unpinned dependency AND a self-exemption file
            (candidate / "requirements.txt").write_text("requests>=0\n", encoding="utf-8")
            (candidate / ".mellyn-allowlist.toml").write_text(
                'schema_version = 1\n[[exemptions]]\npackage = "requests"\necosystem = "pypi"\n'
                'reason = "self"\napproved_by = "@attacker"\nexpires = "2027-01-01"\n',
                encoding="utf-8",
            )

            # Required baseline gate MUST fail (uses baseline's verifier + baseline's empty allowlist)
            required_rc = cg.run_guardrail_suite(
                baseline_root=baseline,
                candidate_root=candidate,
                use_candidate_guardrails=False,
                event_name="pull_request",
                check_agent_rules=False,
                quiet=True,
            )
            # Candidate-mode run executes candidate's proposed script separately
            candidate_rc = cg.run_guardrail_suite(
                baseline_root=baseline,
                candidate_root=candidate,
                use_candidate_guardrails=True,
                event_name="pull_request",
                check_agent_rules=False,
                quiet=True,
            )

            self.assertEqual(required_rc, 1)
            self.assertEqual(candidate_rc, 0)

    def test_own_ci_workflow_separates_baseline_gate_from_candidate_self_test_with_least_privilege(self) -> None:
        own_wf = (REPO_ROOT / ".github" / "workflows" / "ai-security-gate.yml").read_text(encoding="utf-8")
        self.assertIn("permissions:\n  contents: read", own_wf)
        self.assertNotIn("contents: write", own_wf)
        self.assertNotIn("pull_request_target:", own_wf)

        checkout_count = own_wf.count("uses: actions/checkout@")
        self.assertGreaterEqual(checkout_count, 5)
        self.assertEqual(checkout_count, own_wf.count("persist-credentials: false"))

        # Baseline jobs check out `baseline` from PR base SHA (or push SHA) and `candidate` separately
        self.assertGreaterEqual(own_wf.count("path: baseline"), 2)
        self.assertGreaterEqual(own_wf.count("path: candidate"), 3)
        self.assertIn("ref: ${{ github.event.pull_request.base.sha || github.sha }}", own_wf)
        # Candidate guardrail self-test exists as its own job
        self.assertIn("candidate-guardrails:", own_wf)
        self.assertIn("--use-candidate-guardrails", own_wf)


class TestHashLockedCiEnvironments(unittest.TestCase):
    """L3: Every CI and container pip install uses --require-hashes against dedicated lockfiles."""

    def test_every_ci_and_dockerfile_pip_install_requires_hashes_and_intended_lockfile(self) -> None:
        sources = {
            "ai-security-gate.yml": (REPO_ROOT / ".github" / "workflows" / "ai-security-gate.yml").read_text(
                encoding="utf-8"
            ),
            "mellyn-reusable-ai-security-gate.yml": (
                REPO_ROOT / ".github" / "workflows" / "mellyn-reusable-ai-security-gate.yml"
            ).read_text(encoding="utf-8"),
            "Dockerfile": (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8"),
        }

        pip_install_re = re.compile(r"pip\s+install[^\n]*(?:\n\s+-r\s+\S+)?")
        total_installs = 0
        for name, content in sources.items():
            # Strip pure comment lines so documentation examples do not confuse command extraction
            active_text = "\n".join(line for line in content.splitlines() if not line.lstrip().startswith("#"))
            matches = pip_install_re.findall(active_text)
            self.assertGreaterEqual(len(matches), 1, f"Expected at least one pip install in {name}")
            for cmd in matches:
                total_installs += 1
                with self.subTest(file=name, cmd=cmd):
                    self.assertIn("--require-hashes", cmd)
                    self.assertIn("--no-deps", cmd)
                    self.assertRegex(cmd, r"-r\s+\S*requirements(?:-ci-(?:scanners|tests))?\.lock|\$lock")
        self.assertGreaterEqual(total_installs, 5)

        # Confirm scanner lock and API-test lock stay strictly separated on OpenTelemetry constraints
        scanners_locked, scanner_issues = vd.parse_requirements_lock(
            REPO_ROOT / "deploy" / "requirements-ci-scanners.lock"
        )
        tests_locked, test_issues = vd.parse_requirements_lock(REPO_ROOT / "deploy" / "requirements-ci-tests.lock")
        self.assertEqual(scanner_issues, [])
        self.assertEqual(test_issues, [])

        scanner_map = {vd.normalize_pypi_name(p.name): p for p in scanners_locked}
        tests_map = {vd.normalize_pypi_name(p.name): p for p in tests_locked}

        self.assertIn("semgrep", scanner_map)
        self.assertIn("ruff", scanner_map)
        self.assertIn("fastapi", tests_map)
        self.assertIn("starlette", tests_map)
        self.assertIn("httpx", tests_map)
        self.assertNotEqual(
            scanner_map["opentelemetry-api"].version,
            tests_map["opentelemetry-api"].version,
        )
        self.assertTrue(all(p.hashes for p in scanners_locked))
        self.assertTrue(all(p.hashes for p in tests_locked))

    def test_synthetic_unhashed_lock_requirement_fails_dependency_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock_dir = Path(tmp) / "deploy"
            lock_dir.mkdir()
            (lock_dir / "requirements-ci-tests.lock").write_text(
                "fastapi==0.159.1 --hash=sha256:" + ("a" * 64) + "\nhttpx==0.28.1\n",
                encoding="utf-8",
            )
            out = io.StringIO()
            with mock.patch("sys.stdout", out):
                rc = vd.main(["--root", tmp])
            self.assertEqual(rc, 1)
            self.assertIn("[MISSING HASH]", out.getvalue())
            self.assertIn("httpx==0.28.1", out.getvalue())


class TestSharedCiGuardrailHelpers(unittest.TestCase):
    """KISS #4: Single-source checksummed Gitleaks installer, .semgrepignore prep, and Gitleaks range modes."""

    def test_install_gitleaks_verifies_sha256_and_refuses_tampered_archive(self) -> None:
        fake_bin = b"#!/bin/sh\necho gitleaks-ok\n"
        archive_bytes = _make_tar_gz({"LICENSE": b"MIT", "gitleaks": fake_bin})
        good_sha = hashlib.sha256(archive_bytes).hexdigest()

        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "bin"
            installed = cg.install_gitleaks(
                dest,
                version="8.30.1",
                expected_sha256=good_sha,
                downloader=lambda _url, target: target.write_bytes(archive_bytes),
            )
            self.assertTrue(installed.is_file())
            self.assertEqual(installed.read_bytes(), fake_bin)
            self.assertEqual(list(dest.glob("*.tar.gz")), [])

            # Tampered archive must raise RuntimeError and never extract a binary
            bad_dest = Path(tmp) / "bad-bin"
            with self.assertRaisesRegex(RuntimeError, "SHA-256 mismatch"):
                cg.install_gitleaks(
                    bad_dest,
                    version="8.30.1",
                    expected_sha256="0" * 64,
                    downloader=lambda _url, target: target.write_bytes(archive_bytes),
                )
            self.assertFalse((bad_dest / "gitleaks").exists())
            self.assertEqual(list(bad_dest.glob("*.tar.gz")), [])

    def test_prepare_semgrepignore_replaces_nested_ignore_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".semgrepignore").write_text("backend/\n", encoding="utf-8")
            (root / "src" / "sub").mkdir(parents=True)
            (root / "src" / "sub" / ".semgrepignore").write_text("*.py\n", encoding="utf-8")

            written = cg.prepare_semgrepignore(root)
            self.assertFalse((root / "src" / "sub" / ".semgrepignore").exists())
            self.assertEqual(written.read_text(encoding="utf-8").splitlines(), list(cg.SAFE_SEMGREPIGNORE_PATTERNS))

    def test_gitleaks_full_vs_caller_range_modes_and_suppression_stripping(self) -> None:
        base_sha = "a" * 40
        head_sha = "b" * 40
        env = {"EVENT_NAME": "pull_request", "PR_BASE_SHA": base_sha, "PR_HEAD_SHA": head_sha}

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            caller = root / "caller"
            guardrails = root / "guardrails"
            empty_ignore = root / "no-ignore"
            caller.mkdir()
            guardrails.mkdir()
            (caller / ".gitleaksignore").write_text("secret-fingerprint\n", encoding="utf-8")
            (guardrails / ".gitleaks.toml").write_text('title = "trusted"\n', encoding="utf-8")

            self.assertIsNone(cg.compute_gitleaks_log_range(caller, mode="full", env=env))
            self.assertEqual(
                cg.compute_gitleaks_log_range(caller, mode="caller-range", env=env), f"{base_sha}..{head_sha}"
            )

            gitleaks_bin = root / "gitleaks"
            full_cmd = cg.build_gitleaks_command(
                gitleaks_bin,
                target_root=caller,
                guardrails_root=guardrails,
                empty_ignore_dir=empty_ignore,
                log_range=None,
            )
            self.assertFalse((caller / ".gitleaksignore").exists())
            self.assertIn("--ignore-gitleaks-allow", full_cmd)
            self.assertIn(str((guardrails / ".gitleaks.toml").resolve()), full_cmd)
            self.assertFalse(any(arg.startswith("--log-opts=") for arg in full_cmd))

            range_cmd = cg.build_gitleaks_command(
                gitleaks_bin,
                target_root=caller,
                guardrails_root=guardrails,
                empty_ignore_dir=empty_ignore,
                log_range=f"{base_sha}..{head_sha}",
            )
            self.assertIn(f"--log-opts={base_sha}..{head_sha}", range_cmd)


_SHELL_TRUE_SNIPPET = "import subprocess\n\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n"
GATE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ai-security-gate.yml"


def _find_tool(name: str) -> str | None:
    """The tool next to this interpreter (a venv's Scripts/bin) or on PATH."""
    for candidate in (Path(sys.executable).parent / name, Path(sys.executable).parent / f"{name}.exe"):
        if candidate.is_file():
            return str(candidate)
    return shutil.which(name)


class TestReviewFixesRequiredNamesAnchoredIgnoresAndBaselineRuff(unittest.TestCase):
    """Regressions found in review of the baseline gate: each is a way the gate could be blocked or bypassed."""

    def test_required_jobs_keep_the_names_the_main_ruleset_requires(self) -> None:
        # Renaming a required job leaves the ruleset waiting forever for a check that never reports.
        names = re.findall(r"^    name: (.+)$", GATE_WORKFLOW.read_text(encoding="utf-8"), flags=re.MULTILINE)
        for required in (
            "Secret scan (Gitleaks)",
            "SAST, lint, agent rules & dependency verification",
            "Tests (Python ${{ matrix.python-version }})",
        ):
            with self.subTest(required=required):
                self.assertIn(required, names)

    def test_semgrep_ignore_patterns_are_root_anchored_and_no_exclude_flag_is_used(self) -> None:
        self.assertTrue(all(p.startswith("/") for p in cg.SAFE_SEMGREPIGNORE_PATTERNS), cg.SAFE_SEMGREPIGNORE_PATTERNS)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plain = cg.build_semgrep_command(target_root=root, guardrails_root=root)
            self.assertNotIn(cg.SELF_FIXTURES_IGNORE_PATTERN, (root / ".semgrepignore").read_text(encoding="utf-8"))
            selfscan = cg.build_semgrep_command(target_root=root, guardrails_root=root, exclude_self_fixtures=True)
            ignore_lines = (root / ".semgrepignore").read_text(encoding="utf-8").splitlines()
            self.assertIn("/.semgrep/", ignore_lines)
            for cmd in (plain, selfscan):
                self.assertNotIn("--exclude", cmd)  # --exclude matches a path segment at any depth
                self.assertIn("--disable-nosem", cmd)

    @unittest.skipUnless(_find_tool("semgrep") and shutil.which("git"), "semgrep or git is not installed")
    def test_semgrep_scans_committed_code_in_nested_build_vendor_and_semgrep_folders(self) -> None:
        import subprocess

        hidden = ("backend/app/build/a.py", "backend/app/vendor/b.py", "backend/app/.semgrep/c.py", "lib/dist/d.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel in (*hidden, ".semgrep/fixture.py", "node_modules/dep/e.py"):
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text(_SHELL_TRUE_SNIPPET, encoding="utf-8")
            git = ["git", "-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false"]
            subprocess.run([*git, "init", "-q"], cwd=root, check=True)  # noqa: S603 - fixed argv
            subprocess.run([*git, "add", "-A", "-f"], cwd=root, check=True)  # noqa: S603 - fixed argv
            subprocess.run([*git, "commit", "-qm", "c"], cwd=root, check=True)  # noqa: S603 - fixed argv
            cmd = cg.build_semgrep_command(target_root=root, guardrails_root=REPO_ROOT, exclude_self_fixtures=True)
            cmd = [_find_tool("semgrep") or "semgrep", *cmd[1:], "--json", "--quiet"]
            res = subprocess.run(cmd, cwd=root, capture_output=True, text=True, check=False)  # noqa: S603
            report = json.loads(res.stdout)
            flagged = {Path(r["path"]).as_posix() for r in report["results"]}
            self.assertEqual(flagged, set(hidden))  # root fixtures and root node_modules only are skipped

    def test_gate_runs_ruff_with_the_baseline_config_and_the_config_anchors_its_exclude(self) -> None:
        workflow = GATE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("ruff check --config ../baseline/pyproject.toml .", workflow)
        self.assertIn("ruff format --check --config ../baseline/pyproject.toml .", workflow)
        self.assertNotRegex(workflow, r"ruff (check|format --check) candidate")
        sast_job = workflow.split("  sast-and-supply-chain:", 1)[1].split("\n  candidate-guardrails:", 1)[0]
        self.assertRegex(sast_job, r"path: baseline\n\s+sparse-checkout: \|(\n\s+\S+)*\n\s+pyproject\.toml")
        ruff_cfg = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["ruff"]
        self.assertEqual(ruff_cfg["extend-exclude"], ["./.semgrep"])

    @unittest.skipUnless(_find_tool("ruff"), "ruff is not installed")
    def test_candidate_per_file_ignores_cannot_silence_ruff_under_the_baseline_config(self) -> None:
        import subprocess

        ruff = _find_tool("ruff") or "ruff"
        with tempfile.TemporaryDirectory() as tmp:
            baseline, candidate = Path(tmp) / "baseline", Path(tmp) / "candidate"
            (candidate / "backend" / "app" / ".semgrep").mkdir(parents=True)
            baseline.mkdir()
            shutil.copyfile(REPO_ROOT / "pyproject.toml", baseline / "pyproject.toml")
            weakened = (
                (REPO_ROOT / "pyproject.toml")
                .read_text(encoding="utf-8")
                .replace("[tool.ruff.lint]", '[tool.ruff.lint]\nper-file-ignores = { "backend/*" = ["S"] }', 1)
            )
            (candidate / "pyproject.toml").write_text(weakened, encoding="utf-8")
            (candidate / "backend" / "evil.py").write_text(_SHELL_TRUE_SNIPPET, encoding="utf-8")
            (candidate / "backend" / "app" / ".semgrep" / "hidden.py").write_text(_SHELL_TRUE_SNIPPET, encoding="utf-8")

            def lint(*extra: str) -> str:
                argv = [ruff, "check", "--output-format", "concise", "--no-cache", *extra, "."]
                done = subprocess.run(argv, cwd=candidate, capture_output=True, text=True, check=False)  # noqa: S603
                return done.stdout.replace("\\", "/")

            self.assertNotIn("S602", lint())  # the PR's own config silences it: why the gate must not use it
            judged = lint("--config", "../baseline/pyproject.toml")
            self.assertIn("backend/evil.py", judged)
            self.assertIn("backend/app/.semgrep/hidden.py", judged)  # only the root .semgrep is excluded


if __name__ == "__main__":
    unittest.main()
