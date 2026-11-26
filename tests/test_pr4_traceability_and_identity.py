"""Regression tests for PR 4: Threat-to-Test Traceability Matrix, Doc Tree Accuracy & Single Package Identity."""

from __future__ import annotations

import ast
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from mellyn.legacy_env import LEGACY_ENV_PREFIX, LegacyConfigError, check_no_legacy_env, legacy_env_names  # noqa: E402
from mellyn.mcp_gateway import downstream_environment  # noqa: E402
from mellyn.mcp_gateway import main as gateway_main  # noqa: E402

THREAT_MODEL = REPO_ROOT / "docs" / "THREAT_MODEL.md"
ARCHITECTURE = REPO_ROOT / "docs" / "ARCHITECTURE.md"

_TM_ROW_RE = re.compile(r"^\|\s*\*\*(TM-\d{2})\*\*\s*\|.*\|([^|]+)\|\s*$")
_TEST_REF_RE = re.compile(r"`(tests/test_[A-Za-z0-9_]+\.py)::([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)`")

# Directories that are never part of the repository's content, for when git is unavailable.
_SKIP_DIRS = frozenset(
    {".git", "__pycache__", ".ruff_cache", ".pytest_cache", ".venv", "venv", "node_modules", ".claude"}
)


def repository_files() -> list[Path]:
    """
    Files that belong to the repository: tracked files plus new, non-ignored ones (`git ls-files -co
    --exclude-standard`). Local-only content such as `.venv/` or a developer's `.env` is never read. Falls back
    to a directory walk that skips _SKIP_DIRS and `.env*` files when git is not available.
    """
    git = shutil.which("git")
    if git and (REPO_ROOT / ".git").exists():
        listing = subprocess.run(  # noqa: S603 - fixed argv, test only
            [git, "ls-files", "-co", "--exclude-standard", "-z"],
            cwd=REPO_ROOT,
            capture_output=True,
            check=True,
        ).stdout.decode("utf-8")
        return [REPO_ROOT / rel for rel in listing.split("\0") if rel and (REPO_ROOT / rel).is_file()]
    return [
        path
        for path in REPO_ROOT.rglob("*")
        if path.is_file()
        and not any(part in _SKIP_DIRS for part in path.relative_to(REPO_ROOT).parts)
        and not (path.name.startswith(".env") and path.name != ".env.example")
    ]


class TestThreatModelTraceability(unittest.TestCase):
    def setUp(self) -> None:
        self.text = THREAT_MODEL.read_text(encoding="utf-8")

    def test_threat_ids_are_strictly_sequential_with_no_gaps_or_stale_pre_gateway_claims(self) -> None:
        self.assertNotIn("until the gateway mode exists", self.text)
        rows = [m for line in self.text.splitlines() if (m := _TM_ROW_RE.match(line))]
        self.assertGreaterEqual(len(rows), 16)
        actual_ids = [m.group(1) for m in rows]
        expected_ids = [f"TM-{i:02d}" for i in range(1, len(rows) + 1)]
        self.assertEqual(actual_ids, expected_ids, "Threat IDs in THREAT_MODEL.md must be sequential (TM-01..TM-NN)!")

    def test_every_threat_cites_real_existing_test_methods(self) -> None:
        ast_cache: dict[str, dict[str, set[str]]] = {}

        def methods_in(rel_file: str) -> dict[str, set[str]]:
            if rel_file not in ast_cache:
                path = REPO_ROOT / rel_file
                self.assertTrue(path.is_file(), f"Cited test file does not exist: {rel_file}")
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel_file)
                ast_cache[rel_file] = {
                    node.name: {
                        fn.name for fn in node.body if isinstance(fn, ast.FunctionDef) and fn.name.startswith("test_")
                    }
                    for node in tree.body
                    if isinstance(node, ast.ClassDef)
                }
            return ast_cache[rel_file]

        rows = [m for line in self.text.splitlines() if (m := _TM_ROW_RE.match(line))]
        for match in rows:
            tm_id, verified_col = match.group(1), match.group(2)
            refs = _TEST_REF_RE.findall(verified_col)
            self.assertGreaterEqual(len(refs), 1, f"{tm_id} must cite at least one automated test!")
            for rel_file, cls_name, method_name in refs:
                with self.subTest(threat=tm_id, ref=f"{rel_file}::{cls_name}.{method_name}"):
                    classes = methods_in(rel_file)
                    self.assertIn(cls_name, classes, f"{tm_id} cites missing test class {cls_name} in {rel_file}")
                    self.assertIn(
                        method_name,
                        classes[cls_name],
                        f"{tm_id} cites missing test method {cls_name}.{method_name} in {rel_file}",
                    )


class TestUnifiedMellynIdentityAndDocs(unittest.TestCase):
    def test_zero_legacy_package_or_env_identifiers_remain(self) -> None:
        # Constructed via concatenation so this test file does not match its own scan.
        forbidden = (
            "aegis" + "_ai",
            "aegis" + "_",
            "AEGIS" + "_",
            "X-Aegis" + "-API-Key",
            "Aegis" + "AI",
            "aegis-ai" + "-security",
        )
        self.assertFalse((REPO_ROOT / "backend").exists())
        self.assertFalse((REPO_ROOT / "src" / "mcp_airlock").exists())
        self.assertFalse((REPO_ROOT / "src" / ("aegis" + "_ai")).exists())
        self.assertTrue((REPO_ROOT / "src" / "mellyn").is_dir())

        for path in repository_files():
            try:
                content = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            rel = path.relative_to(REPO_ROOT).as_posix()
            for token in forbidden:
                self.assertNotIn(token, content, f"Legacy identifier '{token}' found in {rel}")

    def test_architecture_directory_tree_entries_exist_on_disk(self) -> None:
        arch_text = ARCHITECTURE.read_text(encoding="utf-8")
        tree_block = arch_text.split("## 4. Repository Directory Structure", 1)[1].split("```text\n", 1)[1]
        tree_block = tree_block.split("```", 1)[0]

        stack: list[str] = []
        checked = 0
        tree_line_re = re.compile(r"^([│ ]*)(?:├── |└── )([^\s#]+)")
        for raw_line in tree_block.splitlines():
            m = tree_line_re.match(raw_line)
            if not m:
                continue
            prefix, name = m.group(1), m.group(2)
            depth = len(prefix) // 4
            stack = stack[:depth]
            rel_parts = [*stack, name.rstrip("/")]
            candidate = REPO_ROOT.joinpath(*rel_parts)
            with self.subTest(path="/".join(rel_parts)):
                self.assertTrue(candidate.exists(), f"Documented tree path does not exist: {candidate}")
            checked += 1
            if name.endswith("/"):
                stack.append(name.rstrip("/"))

        self.assertGreaterEqual(checked, 35)


class TestHalfMigratedDeployments(unittest.TestCase):
    """Variables with the pre-rename prefix must stop startup, and must never reach MCP servers."""

    def legacy(self, name: str) -> str:
        return LEGACY_ENV_PREFIX + name

    def test_names_are_found_and_values_are_never_reported(self) -> None:
        env = {self.legacy("API_KEY_PEPPER"): "s3cret-value", "MELLYN_POLICY_PATH": "/p", "PATH": "/bin"}
        self.assertEqual(legacy_env_names(env), [self.legacy("API_KEY_PEPPER")])
        with self.assertRaises(LegacyConfigError) as ctx:
            check_no_legacy_env(env)
        self.assertIn("MELLYN_API_KEY_PEPPER", str(ctx.exception))
        self.assertNotIn("s3cret-value", str(ctx.exception))
        check_no_legacy_env({"MELLYN_API_KEY_PEPPER": "x", "PATH": "/bin"})  # clean: no error

    def test_both_prefixes_are_stripped_from_mcp_server_environments(self) -> None:
        env = {self.legacy("API_KEY_PEPPER"): "p", "MELLYN_APPROVER_KEY_DIGEST": "d", "PATH": "/bin", "HOME": "/h"}
        self.assertEqual(downstream_environment(env), {"PATH": "/bin", "HOME": "/h"})

    def test_gateway_refuses_to_start_with_old_prefixed_variables(self) -> None:
        import contextlib
        import io
        from unittest import mock

        err = io.StringIO()
        with mock.patch.dict("os.environ", {self.legacy("APPROVER_KEY_DIGEST"): "d"}), contextlib.redirect_stderr(err):
            code = gateway_main(["--config", "unused.toml", "--audit-log", "unused.jsonl"])
        self.assertEqual(code, 2)
        self.assertIn("MELLYN_APPROVER_KEY_DIGEST", err.getvalue())
        self.assertFalse(Path("unused.jsonl").exists())  # refused before creating anything


if __name__ == "__main__":
    unittest.main()
