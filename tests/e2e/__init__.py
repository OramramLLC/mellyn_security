"""End-to-end subprocess tests for `mcp_airlock.airlock.proxy`.

Makes `tests/e2e` a package so `python -m unittest discover -s tests` collects it and puts `src/` on `sys.path`.
Skips gracefully when `pydantic` is absent (bare pre-commit venv) unless `MELLYN_REQUIRE_API_TESTS=1` is set.
"""

import importlib.util
import os
import sys
import unittest
from pathlib import Path

_SRC_DIR = Path(__file__).resolve().parents[2] / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

if importlib.util.find_spec("pydantic") is None and os.environ.get("MELLYN_REQUIRE_API_TESTS") != "1":
    raise unittest.SkipTest("pydantic is not installed; mcp_airlock E2E tests skipped")
