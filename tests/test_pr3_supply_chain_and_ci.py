"""Regression tests for PR 3: Transitive Lockfiles, Version-Age Cooldown, Audited Allowlist & CI Container Harness."""

from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import re
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"
SCRIPTS_DIR = REPO_ROOT / "scripts"
for p in (BACKEND_DIR, SCRIPTS_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import verify_container_stack as vcs  # noqa: E402
import verify_dependencies as vd  # noqa: E402
from mellyn.egress_proxy import generate_squid_config  # noqa: E402
from mellyn.policy_loader import load_policy_file  # noqa: E402

NOW = dt.datetime(2026, 11, 22, tzinfo=dt.UTC)


class TestLockfileVerification(unittest.TestCase):
    def test_deploy_requirements_lock_parses_cleanly_with_hashes(self) -> None:
        locked, issues = vd.parse_requirements_lock(REPO_ROOT / "deploy" / "requirements.lock")
        self.assertEqual(issues, [])
        names = {pkg.name for pkg in locked}
        self.assertIn("fastapi", names)
        self.assertIn("starlette", names)
        self.assertIn("uvicorn", names)
        self.assertIn("pydantic_core", names)

    def test_requirements_lock_rejects_missing_hashes_unpinned_versions_and_extra_indexes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "requirements.lock"
            bad.write_text(
                "--extra-index-url https://evil.example/simple\n"
                "fastapi>=0.159.1 --hash=sha256:" + ("a" * 64) + "\n"
                "uvicorn==0.34.0\n",
                encoding="utf-8",
            )
            _locked, issues = vd.parse_requirements_lock(bad)
            joined = "\n".join(issues)
            self.assertIn("NON-REGISTRY SOURCE", joined)
            self.assertIn("UNPINNED LOCK", joined)
            self.assertIn("MISSING HASH", joined)

    def test_uv_lock_parses_registry_packages_and_rejects_git_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            uv = Path(tmp) / "uv.lock"
            uv.write_text(
                "version = 1\n\n"
                '[[package]]\nname = "mellyn-security"\nversion = "0.1.0"\nsource = { virtual = "." }\n\n'
                '[[package]]\nname = "httpx"\nversion = "0.28.1"\nsource = { registry = "https://pypi.org/simple" }\n\n'
                '[[package]]\nname = "sneaky"\nversion = "0.1.0"\nsource = { git = "https://evil.example/x.git" }\n',
                encoding="utf-8",
            )
            locked, issues = vd.parse_uv_lock(uv)
            self.assertEqual([(p.name, p.version) for p in locked], [("httpx", "0.28.1")])
            self.assertTrue(any("NON-REGISTRY SOURCE" in i and "sneaky" in i for i in issues))

    def test_package_lock_json_checks_transitive_deps_and_rejects_non_registry_tarballs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "package-lock.json"
            lock.write_text(
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"name": "app", "version": "1.0.0"},
                            "node_modules/zod": {
                                "version": "3.23.8",
                                "resolved": "https://registry.npmjs.org/zod/-/zod-3.23.8.tgz",
                            },
                            "node_modules/a/node_modules/openai-sdk": {
                                "version": "1.0.0",
                                "resolved": "https://registry.npmjs.org/openai-sdk/-/openai-sdk-1.0.0.tgz",
                            },
                            "node_modules/backdoor": {
                                "version": "1.0.0",
                                "resolved": "https://evil.example/backdoor.tgz",
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            locked, issues = vd.parse_package_lock_json(lock)
            self.assertIn(("zod", "3.23.8"), [(p.name, p.version) for p in locked])
            self.assertTrue(any("NON-REGISTRY SOURCE" in i and "backdoor" in i for i in issues))
            # Transitive slopsquat name caught by hygiene check
            hygiene = vd._check_locked_packages(locked, "npm", False, 90, frozenset(), 14)
            self.assertTrue(any("SLOPSQUAT ALERT" in i and "openai-sdk" in i for i in hygiene))


class TestReleaseCooldownAndAuditedAllowlist(unittest.TestCase):
    def test_dormant_package_with_brand_new_version_upload_is_flagged(self) -> None:
        old_pkg_time = NOW - dt.timedelta(days=1500)
        fresh_ver_time = NOW - dt.timedelta(days=1)
        with (
            mock.patch.object(vd, "pypi_first_release", return_value=old_pkg_time),
            mock.patch.object(vd, "pypi_version_release", return_value=fresh_ver_time),
        ):
            issues = vd.verify_registry(
                "established-pkg",
                "pypi",
                90,
                frozenset(),
                now=NOW,
                pinned_version="9.9.9",
                min_release_age_days=14,
            )
        self.assertTrue(any("FRESH RELEASE" in i for i in issues), issues)

    def test_nonexistent_pinned_version_fails_closed(self) -> None:
        old_pkg_time = NOW - dt.timedelta(days=1500)
        with (
            mock.patch.object(vd, "pypi_first_release", return_value=old_pkg_time),
            mock.patch.object(vd, "pypi_version_release", return_value=None),
        ):
            issues = vd.verify_registry(
                "established-pkg",
                "pypi",
                90,
                frozenset(),
                now=NOW,
                pinned_version="99.99.99",
                min_release_age_days=14,
            )
        self.assertTrue(any("MISSING VERSION" in i for i in issues), issues)

    def test_audited_allowlist_honors_active_exemptions_and_rejects_expired_or_malformed_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            active_path = Path(tmp) / "active.toml"
            active_path.write_text(
                "schema_version = 1\n"
                "[[exemptions]]\n"
                'package = "New_Vetted_SDK"\n'
                'ecosystem = "pypi"\n'
                'reason = "Audited commit abc123"\n'
                'approved_by = "@OramramLLC"\n'
                'expires = "2027-01-15"\n',
                encoding="utf-8",
            )
            exempt, issues = vd.load_allowlist_file(active_path, now=NOW)
            self.assertEqual(issues, [])
            self.assertIn("pypi:new-vetted-sdk", exempt)

            # Active exemption permits a 2-day-old package
            with mock.patch.object(vd, "pypi_first_release", return_value=NOW - dt.timedelta(days=2)):
                res = vd.verify_registry("New_Vetted_SDK", "pypi", 90, exempt, now=NOW)
                self.assertEqual(res, [])

            # Expired exemption fails closed!
            expired_path = Path(tmp) / "expired.toml"
            expired_path.write_text(
                "schema_version = 1\n"
                "[[exemptions]]\n"
                'package = "old-exemption"\n'
                'ecosystem = "npm"\n'
                'reason = "Temporary waiver"\n'
                'approved_by = "@OramramLLC"\n'
                'expires = "2026-10-01"\n',
                encoding="utf-8",
            )
            _exempt2, exp_issues = vd.load_allowlist_file(expired_path, now=NOW)
            self.assertTrue(any("ALLOWLIST EXPIRED" in i for i in exp_issues))


class TestPyprojectAndContainerCiWiring(unittest.TestCase):
    def test_pyproject_declares_no_unused_runtime_dependencies(self) -> None:
        data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        deps = [re.split(r"[<>=!~\[\s]", d)[0] for d in data["project"]["dependencies"]]
        self.assertNotIn("pydantic-settings", deps)
        codebase = "\n".join(
            p.read_text(encoding="utf-8")
            for folder in ("backend", "tests", "scripts")
            for p in (REPO_ROOT / folder).rglob("*.py")
        )
        # uvicorn is invoked as the container ASGI server in Dockerfile
        dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        combined = codebase + "\n" + dockerfile
        for pkg in deps:
            mod = pkg.replace("-", "_")
            self.assertIn(mod, combined, f"Declared dependency '{pkg}' is not referenced anywhere!")

    def test_ci_workflow_runs_container_and_egress_harness(self) -> None:
        ci_yaml = (REPO_ROOT / ".github" / "workflows" / "ai-security-gate.yml").read_text(encoding="utf-8")
        self.assertIn("container-and-egress:", ci_yaml)
        self.assertIn("python scripts/verify_container_stack.py", ci_yaml)

        # Confirm the harness renders a valid Squid config for its isolated CI subnet
        policy = load_policy_file(REPO_ROOT / "config" / "mellyn-policy.example.toml")
        rendered = generate_squid_config(policy, client_cidrs=(vcs.INTERNAL_SUBNET,))
        self.assertIn(f"acl mellyn_clients src {vcs.INTERNAL_SUBNET}", rendered)
        harness_src = (REPO_ROOT / "scripts" / "verify_container_stack.py").read_text(encoding="utf-8")
        self.assertIn("private.docs.python.org:127.0.0.1", harness_src)


class TestLockfileSourceAndHashIntegrity(unittest.TestCase):
    """Regression tests for the bypasses found in review: index switching, unverified hashes, self-exemption."""

    def write(self, name: str, text: str) -> Path:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        path = Path(self._tmp.name) / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_lockfile_cannot_switch_the_index_or_include_files(self) -> None:
        good = "fastapi==0.159.1 --hash=sha256:" + "a" * 64 + "\n"
        for option in (
            "--index-url https://evil.example/simple",
            "-i https://evil.example/simple",
            "-ihttps://evil.example/simple",
            "--extra-index-url https://evil.example/simple",
            "--find-links https://evil.example/wheels",
            "--trusted-host evil.example",
            "-r other.txt",
            "-c constraints.txt",
            "--pre",
        ):
            with self.subTest(option=option):
                _locked, issues = vd.parse_requirements_lock(self.write("requirements.lock", f"{option}\n{good}"))
                self.assertTrue(issues, option)
        _locked, issues = vd.parse_requirements_lock(
            self.write("requirements.lock", f"--require-hashes\n--index-url https://pypi.org/simple\n{good}")
        )
        self.assertEqual(issues, [])

    def test_locked_hashes_must_be_published_by_the_registry(self) -> None:
        real = "sha256:" + "a" * 64
        pkg_ok = vd.LockedPackage("fastapi", "0.159.1", (real,))
        pkg_bad = vd.LockedPackage("fastapi", "0.159.1", (real, "sha256:" + "0" * 64))
        with mock.patch.object(vd, "pypi_release_sha256s", return_value={real}):
            self.assertEqual(vd.verify_locked_hashes(pkg_ok, "pypi"), [])
            self.assertTrue(any("HASH MISMATCH" in i for i in vd.verify_locked_hashes(pkg_bad, "pypi")))
        self.assertTrue(any("MISSING HASH" in i for i in vd.verify_locked_hashes(vd.LockedPackage("x", "1"), "pypi")))
        with mock.patch.object(vd, "npm_release_integrity", return_value="sha512-REAL"):
            ok = vd.verify_locked_hashes(vd.LockedPackage("zod", "3.23.8", ("sha512-REAL",)), "npm")
            bad = vd.verify_locked_hashes(vd.LockedPackage("zod", "3.23.8", ("sha512-FAKE",)), "npm")
        self.assertEqual(ok, [])
        self.assertTrue(any("HASH MISMATCH" in i for i in bad))

    def test_uv_lock_artifacts_must_come_from_pypi_files(self) -> None:
        uv = self.write(
            "uv.lock",
            'version = 1\n[[package]]\nname = "httpx"\nversion = "0.28.1"\n'
            'source = { registry = "https://pypi.org/simple" }\n'
            'wheels = [{ url = "https://evil.example/httpx.whl", hash = "sha256:' + "b" * 64 + '" }]\n',
        )
        locked, issues = vd.parse_uv_lock(uv)
        self.assertEqual(locked, [])
        self.assertTrue(any("evil.example" in i for i in issues))

    def test_npm_alias_is_checked_under_its_real_name(self) -> None:
        lock = {
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/lodash": {
                    "name": "evil-lodash",
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/evil-lodash/-/evil-lodash-1.0.0.tgz",
                    "integrity": "sha512-X",
                },
                "node_modules/lodash2": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/evil-lodash/-/evil-lodash-1.0.0.tgz",
                },
            },
        }
        locked, issues = vd.parse_package_lock_json(self.write("package-lock.json", json.dumps(lock)))
        self.assertEqual([(p.name, p.alias) for p in locked], [("evil-lodash", "lodash")])
        self.assertTrue(any("lodash2" in i and "resolves from" in i for i in issues))  # tarball of another package

    def test_exemptions_cover_only_listed_versions_and_expire_within_180_days(self) -> None:
        entry = (
            'schema_version = 1\n[[exemptions]]\npackage = "vetted"\necosystem = "pypi"\n'
            'reason = "Reviewed"\napproved_by = "@OramramLLC"\nexpires = "2027-01-15"\n'
        )
        exempt, issues = vd.load_allowlist_file(self.write("a.toml", entry), now=NOW)
        self.assertEqual(issues, [])
        with (
            mock.patch.object(vd, "pypi_first_release", return_value=NOW - dt.timedelta(days=2)),
            mock.patch.object(vd, "pypi_version_release", return_value=NOW - dt.timedelta(days=1)),
        ):
            fresh = vd.verify_registry("vetted", "pypi", 90, exempt, now=NOW, pinned_version="9.9.9")
            self.assertTrue(any("FRESH RELEASE" in i for i in fresh), fresh)
            exempt_v, _ = vd.load_allowlist_file(self.write("b.toml", entry + 'versions = ["9.9.9"]\n'), now=NOW)
            self.assertEqual(vd.verify_registry("vetted", "pypi", 90, exempt_v, now=NOW, pinned_version="9.9.9"), [])
            other = vd.verify_registry("vetted", "pypi", 90, exempt_v, now=NOW, pinned_version="9.9.10")
            self.assertTrue(any("FRESH RELEASE" in i for i in other), other)
        _, far = vd.load_allowlist_file(self.write("c.toml", entry.replace("2027-01-15", "2099-12-31")), now=NOW)
        self.assertTrue(any("more than 180 days" in i for i in far))

    def test_allowlist_option_overrides_the_repository_copy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("brand-new==1.0.0\n", encoding="utf-8")
            (root / ".mellyn-allowlist.toml").write_text(
                'schema_version = 1\n[[exemptions]]\npackage = "brand-new"\necosystem = "pypi"\n'
                'reason = "self-approved"\napproved_by = "@pr-author"\nexpires = "2027-01-01"\n'
                'versions = ["1.0.0"]\n',
                encoding="utf-8",
            )
            with (
                mock.patch.object(vd, "pypi_first_release", return_value=dt.datetime.now(dt.UTC)),
                mock.patch.object(vd, "pypi_version_release", return_value=dt.datetime.now(dt.UTC)),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(vd.main(["--root", tmp, "--online"]), 0)  # the repo's own file is used
                missing = str(root / "base-commit-has-none.toml")
                self.assertEqual(vd.main(["--root", tmp, "--online", "--allowlist", missing]), 1)

    def test_workflows_take_the_allowlist_from_the_pull_requests_base(self) -> None:
        helper_text = (REPO_ROOT / "scripts" / "ci_guardrails.py").read_text(encoding="utf-8")
        self.assertIn("HEAD^1:.mellyn-allowlist.toml", helper_text)
        self.assertIn('"--allowlist"', helper_text)
        for workflow in ("ai-security-gate.yml", "mellyn-reusable-ai-security-gate.yml"):
            text = (REPO_ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
            with self.subTest(workflow=workflow):
                self.assertIn("ci_guardrails.py", text)
                self.assertIn("fetch-depth: 2", text)


if __name__ == "__main__":
    unittest.main()
