"""E2E regression test running the 28-scenario adversarial red-team scorecard."""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
BACKEND_DIR = REPO_ROOT / "backend"
for _path in (REPO_ROOT, SRC_DIR, BACKEND_DIR):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

if importlib.util.find_spec("pydantic") is None and os.environ.get("MELLYN_REQUIRE_API_TESTS") != "1":
    raise unittest.SkipTest("pydantic is not installed; adversarial evaluation tests skipped")

from examples.adversarial_eval.run_redteam import run_all_attacks  # noqa: E402


class TestAdversarialRedTeamSuite(unittest.TestCase):
    def test_all_28_adversarial_scenarios_pass(self) -> None:
        outcomes = run_all_attacks()
        self.assertEqual(len(outcomes), 28)
        for outcome in outcomes:
            with self.subTest(case_id=outcome.case_id):
                self.assertTrue(outcome.passed, f"{outcome.case_id} failed: {outcome.observed}")
