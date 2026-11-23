"""
Regression tests: the self-policy drift check accepts EXTRA protected paths.

CI judges a pull request with the copy of `scripts/sync_agent_rules.py` on `main`. With an exact-match drift check,
a PR that adds a path to SELF_PROTECTED_PATHS and to `config/mellyn-self-policy.toml` could never pass, because
`main`'s copy does not know the new path yet (seen on the `src/` addition in the mcp_airlock PR). Extra entries only
add write protection, so they are allowed; every required entry must still be present, and the rest of the file
must still match the example policy exactly.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import sync_agent_rules as sar  # noqa: E402

# An example EXTRA protected path. It must not be a required entry, or the tests would write it twice (PR #13 made
# "src/" required, which broke the original choice of "src/" here).
EXTRA_PATH = "docs/extra-protected.md"


class TestSelfPolicyExtraProtectedPaths(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        for rel in (sar.CANONICAL, sar.CLAUDE_MD, *sar.GENERATED, sar.SELF_POLICY_SOURCE, sar.SELF_POLICY_TARGET):
            dst = self.root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO_ROOT / rel, dst)
        self.policy = self.root / sar.SELF_POLICY_TARGET

    def _check(self) -> int:
        with mock.patch("builtins.print"):
            return sar.main(["--root", str(self.root), "--check"])

    def _write_paths(self, paths: tuple[str, ...]) -> None:
        self.policy.write_text(sar.render_self_policy(self.root, paths), encoding="utf-8", newline="\n")

    def _paths_on_disk(self) -> list[str]:
        return list(tomllib.loads(self.policy.read_text(encoding="utf-8"))["protected_paths"])

    def test_example_extra_path_is_not_required(self) -> None:
        self.assertNotIn(EXTRA_PATH, sar.SELF_PROTECTED_PATHS)

    def test_extra_path_anywhere_in_the_list_passes(self) -> None:
        required = sar.SELF_PROTECTED_PATHS
        self._write_paths((*required, EXTRA_PATH))
        self.assertEqual(self._check(), 0)
        self._write_paths((required[0], EXTRA_PATH, *required[1:]))  # extra entry in the middle, as a PR may add it
        self.assertEqual(self._check(), 0)

    def test_missing_required_path_is_drift_and_regeneration_restores_it(self) -> None:
        required = sar.SELF_PROTECTED_PATHS
        self._write_paths((*required[1:], EXTRA_PATH))
        self.assertEqual(self._check(), 1)
        with mock.patch("builtins.print"):
            self.assertEqual(sar.main(["--root", str(self.root)]), 0)
        self.assertEqual(self._paths_on_disk(), [*required, EXTRA_PATH])  # required restored, extra kept
        self.assertEqual(self._check(), 0)

    def test_other_edits_are_still_drift(self) -> None:
        self._write_paths((*sar.SELF_PROTECTED_PATHS, EXTRA_PATH))
        self.policy.write_text(self.policy.read_text(encoding="utf-8") + "\n# manual edit\n", encoding="utf-8")
        self.assertEqual(self._check(), 1)

    def test_unsafe_or_duplicate_extra_entries_are_drift(self) -> None:
        required = sar.SELF_PROTECTED_PATHS
        for label, extras in (
            ("duplicate", (required[0],)),
            ("empty", ("",)),
            ("space", ("my dir/",)),
            ("quote", ('a"b',)),
        ):
            with self.subTest(label):
                text = sar.render_self_policy(self.root, (*required, *extras))
                if label == "quote":  # the renderer does not escape; write valid TOML by hand
                    text = text.replace('"a"b"', '"a\\"b"')
                self.policy.write_text(text, encoding="utf-8", newline="\n")
                self.assertEqual(self._check(), 1)

    def test_self_policy_paths_contract(self) -> None:
        required = sar.SELF_PROTECTED_PATHS
        self.assertEqual(sar.self_policy_paths(None), required)
        self.assertEqual(sar.self_policy_paths("not = [valid toml"), required)
        self.assertEqual(sar.self_policy_paths("protected_paths = 3\n"), required)


if __name__ == "__main__":
    unittest.main()
