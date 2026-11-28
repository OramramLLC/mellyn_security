"""
Python 3.13-safe Promptfoo provider shim.

Promptfoo's `persistent_wrapper.py` executes the configured provider script with
`exec_module` without registering it in `sys.modules` first, which breaks
`@dataclass` on Python 3.13. Keeping this top-level shim dataclass-free and
importing `mellyn_mcp_provider` cleanly fixes both imports and `sys.modules`.
"""

import sys
from pathlib import Path

_REPO_ROOT = str(Path(__file__).resolve().parents[2])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from evals.promptfoo.mellyn_mcp_provider import call_api  # noqa: E402, F401
