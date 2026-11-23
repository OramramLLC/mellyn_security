"""Unit tests for the `mcp_airlock` package under `src/`.

This file makes `tests/unit` a package so `python -m unittest discover -s tests` (the CI command) collects it,
and puts `src/` on `sys.path` the same way the older suites put `backend/` there.

`mcp_airlock` needs pydantic. Like the API tests, this package is skipped when pydantic is not installed (the
pre-commit hook's bare environment), unless MELLYN_REQUIRE_API_TESTS=1 is set (as in CI), in which case a missing
pydantic fails the run instead of silently skipping it.
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
    raise unittest.SkipTest("pydantic is not installed; mcp_airlock unit tests skipped")
