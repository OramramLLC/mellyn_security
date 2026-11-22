"""Regression tests for scripts/verify_dependencies.py (runs under pytest or `python -m unittest`)."""

from __future__ import annotations

import datetime as dt
import json
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import verify_dependencies as vd  # noqa: E402

NOW = dt.datetime(2026, 11, 21, tzinfo=dt.UTC)


class PythonSpecTests(unittest.TestCase):
    def issues(self, spec: str) -> list[str]:
        return vd.parse_python_spec(spec, "pyproject.toml")[1]

    def test_reasonable_floors_pass(self):
        for spec in ("fastapi>=0.115.0", "pydantic==2.10.0", "httpx~=0.28", "uvicorn[standard]>=0.32.0"):
            self.assertEqual(self.issues(spec), [], spec)

    def test_markers_are_ignored(self):
        self.assertEqual(self.issues('tomli>=2.0; python_version < "3.11"'), [])

    def test_missing_or_zero_floor_fails(self):
        for spec in ("requests", "requests>=0", "requests>=0.0.0", "requests<3"):
            self.assertTrue(any("UNPINNED" in i for i in self.issues(spec)), spec)

    def test_url_and_vcs_sources_fail(self):
        for spec in ("evil @ https://example.invalid/evil.whl", "evil @ git+https://example.invalid/evil.git"):
            self.assertTrue(any("NON-REGISTRY" in i for i in self.issues(spec)), spec)


class NpmSpecTests(unittest.TestCase):
    def test_normal_ranges_pass(self):
        for spec in ("^15.0.3", "~3.23.8", "1.2.3", ">=1.4.0 <2", "workspace:*"):
            self.assertEqual(vd.check_npm_spec("pkg", spec, "package.json"), [], spec)

    def test_wildcards_and_zero_floors_fail(self):
        for spec in ("*", "latest", "", "x", ">=0.0.0", "<2.0.0"):
            self.assertTrue(vd.check_npm_spec("pkg", spec, "package.json"), spec)

    def test_non_registry_sources_fail(self):
        specs = ("git+https://example.invalid/x.git", "github:user/repo", "user/repo", "file:../x", "https://x/y.tgz")
        for spec in specs:
            issues = vd.check_npm_spec("pkg", spec, "package.json")
            self.assertTrue(any("NON-REGISTRY" in i for i in issues), spec)


class NameHygieneTests(unittest.TestCase):
    def test_known_hallucinated_name_normalized(self):
        self.assertTrue(vd.check_package_name_hygiene("OpenAI_SDK", "pypi"))

    def test_invalid_names_rejected_before_any_url_is_built(self):
        for name in ("../../etc", "a/b", "x?y=1", "-leading"):
            self.assertTrue(any("INVALID NAME" in i for i in vd.check_package_name_hygiene(name, "pypi")), name)
        self.assertTrue(vd.check_package_name_hygiene("UPPER", "npm"))
        self.assertEqual(vd.check_package_name_hygiene("@types/node", "npm"), [])


class RegistryTests(unittest.TestCase):
    def verify(self, first_release, **kwargs):
        with mock.patch.object(vd, "pypi_first_release", return_value=first_release):
            return vd.verify_registry("somepkg", "pypi", 90, frozenset(kwargs.get("allow", ())), now=NOW)

    def test_old_package_passes(self):
        self.assertEqual(self.verify(NOW - dt.timedelta(days=2000)), [])

    def test_freshly_registered_package_fails(self):
        self.assertTrue(any("NEW PACKAGE" in i for i in self.verify(NOW - dt.timedelta(days=3))))

    def test_allow_new_exempts_vetted_package(self):
        self.assertEqual(self.verify(NOW - dt.timedelta(days=3), allow={"somepkg"}), [])

    def test_missing_package_reported_as_hallucination(self):
        err = urllib.error.HTTPError("u", 404, "Not Found", None, None)
        with mock.patch.object(vd, "pypi_first_release", side_effect=err):
            self.assertTrue(any("HALLUCINATION" in i for i in vd.verify_registry("x", "pypi", 90, frozenset())))

    def test_network_failure_fails_closed(self):
        with mock.patch.object(vd, "npm_first_release", side_effect=urllib.error.URLError("offline")):
            self.assertTrue(any("failing closed" in i for i in vd.verify_registry("x", "npm", 90, frozenset())))

    def test_fetch_refuses_non_registry_hosts(self):
        with self.assertRaises(ValueError):
            vd._fetch_json("http://169.254.169.254/latest/meta-data/", 1)


class EndToEndTests(unittest.TestCase):
    def run_main(self, files: dict[str, str]) -> int:
        with tempfile.TemporaryDirectory() as tmp:
            for rel, content in files.items():
                path = Path(tmp, rel)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            with mock.patch("builtins.print"):
                return vd.main(["--root", tmp])

    def test_repository_manifest_passes(self):
        with mock.patch("builtins.print"):
            self.assertEqual(vd.main(["--root", str(Path(__file__).resolve().parents[1])]), 0)

    def test_weak_manifests_fail(self):
        self.assertEqual(self.run_main({"requirements.txt": "requests>=0\n"}), 1)
        self.assertEqual(self.run_main({"requirements-dev.txt": "-e git+https://example.invalid/x.git\n"}), 1)
        self.assertEqual(self.run_main({"package.json": json.dumps({"dependencies": {"x": "latest"}})}), 1)
        self.assertEqual(self.run_main({"frontend/package.json": json.dumps({"devDependencies": {"x": "a/b"}})}), 1)

    def test_nested_manifests_and_build_system_requires_are_verified(self):
        nested_pyproject = '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["requests>=0"]\n'
        self.assertEqual(self.run_main({"services/demo/pyproject.toml": nested_pyproject}), 1)

        weak_build_sys = (
            '[build-system]\nrequires = ["setuptools"]\nbuild-backend = "setuptools.build_meta"\n'
            '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["httpx>=0.28.0"]\n'
        )
        self.assertEqual(self.run_main({"pyproject.toml": weak_build_sys}), 1)

        valid_nested = (
            '[build-system]\nrequires = ["setuptools>=75.0.0"]\nbuild-backend = "setuptools.build_meta"\n'
            '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["httpx>=0.28.0"]\n'
        )
        ignored_venv = '[project]\nname = "ignored"\ndependencies = ["requests"]\n'
        self.assertEqual(
            self.run_main(
                {
                    "services/demo/pyproject.toml": valid_nested,
                    ".venv/Lib/site-packages/pkg/pyproject.toml": ignored_venv,
                    "node_modules/bad/package.json": json.dumps({"dependencies": {"x": "*"}}),
                }
            ),
            0,
        )

    def test_requirements_options_and_hashes_are_handled(self):
        reqs = "-r base.txt\n--index-url https://pypi.org/simple\nhttpx==0.28.1 --hash=sha256:abc \\\n# comment\n"
        self.assertEqual(self.run_main({"requirements.txt": reqs, "base.txt": "anyio>=4.0\n"}), 0)

    def test_requirements_cannot_switch_the_index_or_include_unchecked_files(self):
        for reqs, files in (
            ("--index-url https://evil.example/simple\nhttpx==0.28.1\n", {}),
            ("-ihttps://evil.example/simple\nhttpx==0.28.1\n", {}),
            ("--extra-index-url https://evil.example/simple\nhttpx==0.28.1\n", {}),
            ("--find-links https://evil.example/wheels\nhttpx==0.28.1\n", {}),
            ("-r https://evil.example/reqs.txt\n", {}),
            ("-r missing.txt\n", {}),
            ("-r base.txt\n", {"base.txt": "requests\n"}),  # the included file is verified too
        ):
            with self.subTest(reqs=reqs):
                self.assertEqual(self.run_main({"requirements.txt": reqs, **files}), 1)


if __name__ == "__main__":
    unittest.main()
