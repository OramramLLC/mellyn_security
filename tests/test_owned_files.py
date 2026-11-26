"""Regression tests: every component protects the files that configure or record its own enforcement.

Before this fix the gateway listed its own files by hand, and the authorizer service (`mellyn.api`) and the Airlock
protected none of theirs: with the policy, ledger or state database inside the workspace, an approved write could
rewrite the policy, truncate the ledger, plant a directory at the ledger's lock path, or reset taint. Now the audit
logger and state store declare their files, the Authorizer protects them, and each entry point adds its config.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import io
import os
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from mellyn import mcp_gateway  # noqa: E402
from mellyn.audit import AuditLogger  # noqa: E402
from mellyn.authorizer import Authorizer  # noqa: E402
from mellyn.egress.guards import (  # noqa: E402
    LEDGER_FILE_SUFFIXES,
    SQLITE_FILE_SUFFIXES,
    owned_file_entries,
)
from mellyn.models import ToolCallRequest  # noqa: E402
from mellyn.state_store import SqliteStateStore  # noqa: E402
from mellyn.unified_config import render_unified_config  # noqa: E402

HAS_FASTAPI = all(importlib.util.find_spec(name) is not None for name in ("fastapi", "httpx"))
# The Airlock needs pydantic, which the bare-stdlib pre-commit venv lacks; CI sets MELLYN_REQUIRE_API_TESTS=1.
HAS_PYDANTIC = importlib.util.find_spec("pydantic") is not None or os.environ.get("MELLYN_REQUIRE_API_TESTS") == "1"
STAMP = "20261126T000000Z"
LEDGER_SIBLINGS = ("audit.jsonl", "audit.jsonl.lock", f"audit.jsonl.v1-{STAMP}", f"audit.jsonl.pre-chain-{STAMP}")
STATE_FILES = ("state.db", "state.db-wal", "state.db-shm", "state.db-journal")


class _Workspace(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.ws = self.root / "ws"
        self.ws.mkdir()

    def assert_write_denied(self, authorizer: Authorizer, paths: tuple[str, ...]) -> None:
        for path in paths:
            with self.subTest(path=path):
                self.assertFalse(authorizer.path_guard.validate_path(path, is_write=True)[0])
        self.assertTrue(authorizer.path_guard.validate_path("notes.txt", is_write=True)[0])


class TestOwnedFileEntries(_Workspace):
    def test_entries_cover_files_inside_the_workspace_only(self) -> None:
        entries = owned_file_entries(
            self.ws,
            (
                (self.ws / "logs" / "audit.jsonl", LEDGER_FILE_SUFFIXES),
                (self.ws / "state.db", SQLITE_FILE_SUFFIXES),
                (self.root / "outside.toml", ("",)),  # the guard already denies every path outside the workspace
                (self.ws, ("",)),  # the workspace itself is never an owned file
                (self.ws / "logs" / ".." / "logs" / "audit.jsonl", LEDGER_FILE_SUFFIXES),  # duplicate once resolved
            ),
        )
        self.assertEqual(
            entries,
            (
                "logs/audit.jsonl",
                "logs/audit.jsonl.*",
                "state.db",
                "state.db-wal",
                "state.db-shm",
                "state.db-journal",
            ),
        )


class TestAuthorizerProtectsDeclaredFiles(_Workspace):
    def test_ledger_and_state_database_files_are_protected(self) -> None:
        logger, handle = AuditLogger.open_chained(self.ws / "audit.jsonl", source="authorizer")
        self.addCleanup(handle.close)
        store = SqliteStateStore(self.ws / "state.db")
        self.addCleanup(store.close)
        authorizer = Authorizer(workspace_root=self.ws, audit_logger=logger, state_store=store)
        self.assert_write_denied(authorizer, (*LEDGER_SIBLINGS, *STATE_FILES))

    def test_in_memory_and_undeclared_components_add_nothing(self) -> None:
        class _CustomStore(mock.MagicMock):
            owned_files = None  # a third-party store without the method still works

        plain = Authorizer(workspace_root=self.ws)
        custom = Authorizer(workspace_root=self.ws, state_store=_CustomStore())
        self.assertEqual(custom.path_guard.protected_paths, plain.path_guard.protected_paths)


@unittest.skipUnless(HAS_FASTAPI, "fastapi and httpx are not installed")
class TestAuthorizerServiceProtectsItsFiles(_Workspace):
    def _build_service(self) -> Authorizer:
        from mellyn import api as api_module

        (self.ws / "mellyn.toml").write_text(render_unified_config(["mcp-filesystem"]), encoding="utf-8")
        env = {
            "MELLYN_WORKSPACE_ROOT": str(self.ws),
            "MELLYN_REQUIRE_WORKSPACE_MOUNT": "0",
            "MELLYN_POLICY_PATH": str(self.ws / "mellyn.toml"),
            "MELLYN_AUDIT_LOG_PATH": str(self.ws / "audit.jsonl"),
            "MELLYN_STATE_DB_PATH": str(self.ws / "state.db"),
        }
        built: list[Authorizer] = []

        def build(**kwargs: Any) -> Authorizer:
            built.append(Authorizer(**kwargs))
            return built[-1]

        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(api_module, "Authorizer", build):
            app = api_module.create_app_from_env()
        self.assertEqual(len(built), 1)

        async def shutdown() -> None:
            async with app.router.lifespan_context(app):
                pass

        self.addCleanup(lambda: asyncio.run(shutdown()))  # closes the ledger and state database
        return built[0]

    def test_policy_ledger_and_state_database_are_protected(self) -> None:
        authorizer = self._build_service()
        # Before the fix the service protected none of these.
        self.assert_write_denied(authorizer, ("mellyn.toml", *LEDGER_SIBLINGS, *STATE_FILES))

    def test_an_approved_style_write_to_the_ledger_is_denied(self) -> None:
        authorizer = self._build_service()
        sid = authorizer.create_session()
        server = next(iter(tomllib.loads(render_unified_config(["mcp-filesystem"]))["servers"]))["name"]

        def decide(path: str) -> str:
            req = ToolCallRequest(sid, "write_file", {"path": path, "content": "x"}, mcp_server=server)
            return authorizer.authorize(req).decision.value

        self.assertNotEqual(decide("notes.txt"), "deny")  # control: an ordinary write is not refused outright
        for path in ("audit.jsonl", "audit.jsonl.lock", "state.db-wal", "mellyn.toml"):
            with self.subTest(path=path):
                self.assertEqual(decide(path), "deny")


class TestGatewayDeclaresItsConfig(_Workspace):
    def test_gateway_protects_config_ledger_and_state_database(self) -> None:
        config = self.ws / "mellyn.toml"
        config.write_text(
            'schema_version = 2\n[runtime]\nstate_db = "state.db"\n[[servers]]\nname = "fs"\ntransport = "stdio"\n'
            'preset = "mcp-filesystem"\ncommand = ["mcp-fs"]\n',
            encoding="utf-8",
        )
        built: list[Authorizer] = []

        def build(**kwargs: Any) -> Authorizer:
            built.append(Authorizer(**kwargs))
            raise RuntimeError("stop once the authorizer is built")

        argv = ["--config", str(config), "--workspace", str(self.ws), "--audit-log", str(self.ws / "audit.jsonl")]
        with (
            mock.patch.object(mcp_gateway, "StdioDownstream", return_value=mock.MagicMock()),
            mock.patch.object(mcp_gateway, "Authorizer", side_effect=build),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            mcp_gateway.main(argv)
        self.assertEqual(len(built), 1)
        self.addCleanup(built[0].close)
        self.assert_write_denied(built[0], ("mellyn.toml", *LEDGER_SIBLINGS, *STATE_FILES))


@unittest.skipUnless(HAS_PYDANTIC, "the Airlock needs pydantic")
class TestAirlockProtectsItsFiles(_Workspace):
    def _policy(self) -> Any:
        from mellyn.airlock.models import AirlockPolicy

        return AirlockPolicy(
            allowed_tools=["write_file"],
            workspace_roots=[str(self.ws)],
            allow_resources_read=True,
            tool_rules={"write_file": {"name": "write_file", "path_arg_names": ["path"]}},
        )

    @staticmethod
    def _write(path: Path) -> Any:
        from mellyn.airlock.models import JsonRpcRequest

        params = {"name": "write_file", "arguments": {"path": str(path), "content": "x"}}
        return JsonRpcRequest(jsonrpc="2.0", id=1, method="tools/call", params=params)

    def test_proxy_startup_declares_its_policy_and_ledger(self) -> None:
        from mellyn.airlock import proxy as airlock_proxy

        policy_file = self.ws / "airlock.toml"
        policy_file.write_text(f"workspace_roots = [{str(self.ws)!r}]\n", encoding="utf-8")
        seen: dict[str, Any] = {}

        async def run(**kwargs: Any) -> int:
            seen.update(kwargs)
            return 0

        argv = ["--policy", str(policy_file), "--audit-log", str(self.ws / "audit.jsonl"), "--", sys.executable]
        with mock.patch.object(airlock_proxy, "_run_cli_async", run):
            self.assertEqual(airlock_proxy.main(argv), 0)
        self.assertEqual(
            seen["policy"].owned_files,
            ((policy_file, ("",)), (self.ws / "audit.jsonl", LEDGER_FILE_SUFFIXES)),
        )

    def test_tool_calls_and_resource_reads_cannot_write_owned_files(self) -> None:
        from mellyn.airlock.engine import evaluate_resource_read, evaluate_tool_call
        from mellyn.airlock.models import JsonRpcRequest

        bare = self._policy()
        owned_files = ((self.ws / "airlock.toml", ("",)), (self.ws / "audit.jsonl", LEDGER_FILE_SUFFIXES))
        owned = bare.with_owned_files(owned_files)
        self.assertEqual(bare.owned_files, ())  # the copy is new; the loaded policy is unchanged
        for name in ("airlock.toml", *LEDGER_SIBLINGS):
            with self.subTest(name=name):
                self.assertTrue(evaluate_tool_call(self._write(self.ws / name), bare).verdict_allow)  # control
                self.assertFalse(evaluate_tool_call(self._write(self.ws / name), owned).verdict_allow)
        self.assertTrue(evaluate_tool_call(self._write(self.ws / "notes.txt"), owned).verdict_allow)
        read = JsonRpcRequest(
            jsonrpc="2.0", id=2, method="resources/read", params={"uri": (self.ws / "audit.jsonl").as_uri()}
        )
        # resources/read is checked as a guardrail write, so an owned file is refused there too.
        self.assertFalse(evaluate_resource_read(read, owned).verdict_allow)


if __name__ == "__main__":
    unittest.main()
