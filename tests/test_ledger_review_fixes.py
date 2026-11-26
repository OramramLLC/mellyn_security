"""Regression tests for review fixes to the unified audit ledger (Phase 2, Pass 2C).

- An agent cannot touch the ledger's siblings: its `.lock` file, or the `.v1-*` / `.pre-chain-*` files older
  ledgers are moved aside to.
- The gateway/authorizer writer keeps its ledger and lock file open between appends, without losing any check:
  a swapped file is re-verified, a symlink is refused, and `close()` releases both handles.
"""

from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from mellyn import mcp_gateway  # noqa: E402
from mellyn.audit import AuditChainError, AuditLogger, verify_gateway_audit_file  # noqa: E402
from mellyn.authorizer import Authorizer  # noqa: E402
from mellyn.core import audit as core_audit  # noqa: E402
from mellyn.egress.guards import WorkspacePathGuard  # noqa: E402
from mellyn.models import ToolCallRequest  # noqa: E402

LEDGER = "mellyn-audit.jsonl"


class _TempDir(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)


class TestLedgerSiblingsAreProtected(_TempDir):
    def test_the_sibling_pattern_covers_exactly_name_dot_suffix(self) -> None:
        guard = WorkspacePathGuard(self.root, (LEDGER, f"{LEDGER}.*", "logs/gw.jsonl.*"))
        protected = [
            LEDGER,
            f"{LEDGER}.lock",
            f"{LEDGER}.v1-20261126T000000Z",
            f"{LEDGER.upper()}.PRE-CHAIN-20261126T000000Z",
            "logs/gw.jsonl.lock",
            "logs",  # the folder holding a protected file cannot be moved away either
        ]
        open_paths = [f"{LEDGER}x", "mellyn-audit.json", "other/gw.jsonl.lock", "logs/gw.jsonl2", "notes.txt"]
        for path in protected:
            with self.subTest(path=path):
                self.assertTrue(guard.is_protected(path))
                self.assertFalse(guard.validate_path(path, is_write=True)[0])
        for path in open_paths:
            with self.subTest(path=path):
                self.assertFalse(guard.is_protected(path))

    def test_the_gateway_protects_its_ledgers_siblings(self) -> None:
        ws = self.root / "ws"
        ws.mkdir()
        config = self.root / "mellyn.toml"
        config.write_text(
            'schema_version = 2\n[[servers]]\nname = "fs"\ntransport = "stdio"\npreset = "mcp-filesystem"\n'
            'command = ["mcp-fs"]\n',
            encoding="utf-8",
        )
        built: list[Authorizer] = []

        def build(**kwargs: Any) -> Any:
            built.append(Authorizer(**kwargs))  # the real one, with the gateway's ledger and declared files
            raise RuntimeError("stop once the authorizer is built")

        argv = ["--config", str(config), "--workspace", str(ws), "--audit-log", str(ws / LEDGER)]
        with (
            mock.patch.object(mcp_gateway, "StdioDownstream", return_value=mock.MagicMock()),
            mock.patch.object(mcp_gateway, "Authorizer", side_effect=build),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            mcp_gateway.main(argv)
        self.assertEqual(len(built), 1)
        authorizer = built[0]
        # The gateway closed its ledger on the way out; record these decisions in memory instead. The path guard
        # was fixed when the Authorizer was built, from the ledger the gateway opened.
        authorizer.audit = AuditLogger()
        # Before the fix only the ledger itself was protected, so an approved write could plant a directory at
        # `<ledger>.lock` (every restart then failed) or delete a moved-aside `.v1-*` ledger.
        sid = authorizer.create_session()
        for tool, args in (
            ("write_file", {"path": f"{LEDGER}.lock", "content": "x"}),
            ("create_directory", {"path": f"{LEDGER}.lock"}),
            ("move_file", {"source": f"{LEDGER}.v1-20261126T000000Z", "destination": "gone.txt"}),
        ):
            with self.subTest(tool=tool):
                decision = authorizer.authorize(ToolCallRequest(sid, tool, args, mcp_server="fs")).decision
                self.assertEqual(decision.value, "deny")


class TestHeldLedgerHandles(_TempDir):
    def _open(self, name: str = LEDGER) -> tuple[AuditLogger, Any]:
        logger, handle = AuditLogger.open_chained(self.root / name)
        self.addCleanup(handle.close)
        return logger, handle

    def test_appends_do_not_reopen_the_ledger_or_the_lock_file(self) -> None:
        logger, _ = self._open()
        logger.record_taint(session_id="s", taint_count=1, taint_sources=("t",))  # first append opens both
        real_open = os.open
        with mock.patch.object(core_audit.os, "open", side_effect=real_open) as opened:
            for i in range(5):
                logger.record_taint(session_id="s", taint_count=i, taint_sources=("t",))
        # Before the fix every append opened the lock file and the ledger (twice); about 4 ms per open on Windows.
        self.assertEqual(opened.call_count, 0)
        self.assertTrue(verify_gateway_audit_file(self.root / LEDGER).valid)

    def test_a_replaced_ledger_is_re_verified_not_written_through_a_stale_handle(self) -> None:
        logger, _ = self._open()
        logger.record_taint(session_id="s", taint_count=1, taint_sources=("t",))
        path = self.root / LEDGER
        good = path.read_bytes()
        # Swap in a different file under the same name: here a tampered copy.
        tampered = good.replace(b'"taint_count":1', b'"taint_count":9')
        swapped = self.root / "swap.jsonl"
        swapped.write_bytes(tampered)
        os.replace(swapped, path) if os.name != "nt" else self._replace_on_windows(logger, swapped, path)
        with self.assertRaises(AuditChainError):
            logger.record_taint(session_id="s", taint_count=2, taint_sources=("t",))

    def _replace_on_windows(self, logger: AuditLogger, src: Path, dst: Path) -> None:
        # Windows will not replace a file another handle holds open; close ours first, as a separate process
        # appending to (or rotating) the file would observe it. The next append must reopen and re-verify.
        held = logger._core._held_ledger  # noqa: SLF001 - white-box: the handle under test
        self.assertIsNotNone(held)
        if held is not None:
            held.close()
        os.replace(src, dst)

    def test_a_lock_file_swapped_for_a_symlink_is_refused(self) -> None:
        if os.name == "nt":
            self.skipTest("creating symlinks needs privileges on Windows")
        logger, _ = self._open()
        logger.record_taint(session_id="s", taint_count=1, taint_sources=("t",))
        lock = self.root / f"{LEDGER}.lock"
        target = self.root / "elsewhere"
        target.write_text("")
        lock.unlink()
        lock.symlink_to(target)
        with self.assertRaises(AuditChainError) as ctx:
            logger.record_taint(session_id="s", taint_count=2, taint_sources=("t",))
        # Refused by the explicit check, not only by O_NOFOLLOW (which Windows does not have).
        self.assertIn("Refusing symlink", str(ctx.exception))

    def test_close_releases_both_handles(self) -> None:
        logger, handle = self._open()
        logger.record_taint(session_id="s", taint_count=1, taint_sources=("t",))
        handle.close()
        core = logger._core  # noqa: SLF001
        for held in (core._held_ledger, core._held_lock):  # noqa: SLF001
            self.assertIsNotNone(held)
            if held is not None:
                self.assertIsNone(held.fd)
        # And the file can be moved, which Windows refuses while a handle is open.
        os.replace(self.root / LEDGER, self.root / "moved.jsonl")

    def test_appends_stay_fast(self) -> None:
        logger, _ = self._open()
        with mock.patch.object(core_audit.os, "fsync", lambda _fd: None):  # time the writer, not the disk
            start = time.perf_counter()
            for i in range(100):
                logger.record_taint(session_id="s", taint_count=i, taint_sources=("t",))
            per_append = (time.perf_counter() - start) / 100
        self.assertLess(per_append, 0.02)


if __name__ == "__main__":
    unittest.main()
