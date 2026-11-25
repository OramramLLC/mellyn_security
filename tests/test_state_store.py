"""Regression tests for durable fail-closed Authorizer SQLite state persistence."""

from __future__ import annotations

import os
import sqlite3
import stat
import sys
import tempfile
import threading
import unittest
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from mellyn import (  # noqa: E402
    Authorizer,
    Decision,
    InMemoryStateStore,
    PolicyConfig,
    RiskSignals,
    RiskTier,
    SessionLimitError,
    SqliteStateStore,
    StateStoreError,
    TaintSource,
    ToolCallRequest,
    ToolCapability,
)


class TestSqliteStateStorePersistence(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self._tmpdir.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        (self.workspace / "app.py").write_text("print('ok')\n", encoding="utf-8")
        self.db_path = self.root / "state" / "authorizer.db"

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_session_taint_and_grants_survive_authorizer_restart(self) -> None:
        t0 = datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC)
        with Authorizer(workspace_root=self.workspace, state_store=SqliteStateStore(self.db_path)) as auth1:
            sid = auth1.create_session(now=t0)
            auth1.mark_tainted(
                sid,
                TaintSource(source_type="issue_body", origin="https://example.com/issue/1", recorded_at=t0),
                now=t0 + timedelta(seconds=1),
            )
            grant = auth1.issue_grant(
                session_id=sid,
                tool_name="git_push",
                arguments={"branch": "feature/persist"},
                approved_by="reviewer@mellyn.security",
                max_uses=1,
                now=t0 + timedelta(seconds=2),
            )

        # Restart 1: new Authorizer + SqliteStateStore on the same database file
        with Authorizer(workspace_root=self.workspace, state_store=SqliteStateStore(self.db_path)) as auth2:
            self.assertTrue(auth2.has_session(sid, now=t0 + timedelta(seconds=10)))
            self.assertTrue(auth2.is_tainted(sid))
            self.assertEqual(auth2.get_taint_count(sid), 1)
            self.assertEqual([src.origin for src in auth2.get_taint_sources(sid)], ["https://example.com/issue/1"])

            # Taint must persist across restart: MEDIUM workspace_write still requires approval
            write_res = auth2.authorize(
                ToolCallRequest(sid, "workspace_write", {"path": "app.py"}),
                now=t0 + timedelta(seconds=11),
            )
            self.assertEqual(write_res.decision, Decision.REQUIRE_APPROVAL)
            self.assertTrue(write_res.tainted)

            # Wrong arguments cannot use the persisted grant
            wrong_args = auth2.authorize(
                ToolCallRequest(sid, "git_push", {"branch": "main"}),
                now=t0 + timedelta(seconds=12),
            )
            self.assertEqual(wrong_args.decision, Decision.REQUIRE_APPROVAL)

            # Exact arguments spend the single-use grant once
            allowed = auth2.authorize(
                ToolCallRequest(sid, "git_push", {"branch": "feature/persist"}),
                now=t0 + timedelta(seconds=13),
            )
            self.assertEqual(allowed.decision, Decision.ALLOW)
            self.assertEqual(allowed.grant_id, grant.grant_id)

        # Restart 2: consumed single-use grant must never replay
        with Authorizer(workspace_root=self.workspace, state_store=SqliteStateStore(self.db_path)) as auth3:
            replay = auth3.authorize(
                ToolCallRequest(sid, "git_push", {"branch": "feature/persist"}),
                now=t0 + timedelta(seconds=20),
            )
            self.assertEqual(replay.decision, Decision.REQUIRE_APPROVAL)
            self.assertIsNone(replay.grant_id)

    def test_taint_sample_bounded_while_taint_count_exact_across_restart(self) -> None:
        t0 = datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC)
        synthetic_secret = "sk-proj-" + ("A" * 24)
        with Authorizer(
            workspace_root=self.workspace,
            max_taint_sample=3,
            state_store=SqliteStateStore(self.db_path),
        ) as auth1:
            sid = auth1.create_session(now=t0)
            for idx in range(5):
                origin = f"https://example.com/page/{idx}?token={synthetic_secret}" if idx == 4 else f"origin/{idx}"
                auth1.mark_tainted(
                    sid,
                    TaintSource(source_type="web_page", origin=origin, recorded_at=t0 + timedelta(seconds=idx)),
                    now=t0 + timedelta(seconds=idx),
                )

        with Authorizer(
            workspace_root=self.workspace,
            max_taint_sample=3,
            state_store=SqliteStateStore(self.db_path),
        ) as auth2:
            self.assertEqual(auth2.get_taint_count(sid), 5)
            sources = auth2.get_taint_sources(sid)
            self.assertEqual(len(sources), 3)
            self.assertEqual(sources[0].origin, "origin/2")
            self.assertEqual(sources[1].origin, "origin/3")
            self.assertIn("[REDACTED_SECRET]", sources[2].origin)
            self.assertNotIn(synthetic_secret, sources[2].origin)

        # Verify raw secret was never written to SQLite bytes either
        raw_db_bytes = self.db_path.read_bytes()
        self.assertNotIn(synthetic_secret.encode("ascii"), raw_db_bytes)

    def test_session_ttl_expiry_and_cascade_grant_purge_across_restart(self) -> None:
        t0 = datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC)
        with Authorizer(
            workspace_root=self.workspace,
            session_ttl_seconds=60,
            state_store=SqliteStateStore(self.db_path),
        ) as auth1:
            sid = auth1.create_session(now=t0)
            auth1.issue_grant(
                session_id=sid,
                tool_name="git_push",
                arguments={"branch": "feature/ttl"},
                approved_by="reviewer@mellyn.security",
                now=t0,
            )

        with Authorizer(
            workspace_root=self.workspace,
            session_ttl_seconds=60,
            state_store=SqliteStateStore(self.db_path),
        ) as auth2:
            self.assertTrue(auth2.has_session(sid, now=t0 + timedelta(seconds=30)))
            denied = auth2.authorize(
                ToolCallRequest(sid, "workspace_read", {"path": "app.py"}),
                now=t0 + timedelta(seconds=61),
            )
            self.assertEqual(denied.decision, Decision.DENY)
            self.assertFalse(auth2.has_session(sid, now=t0 + timedelta(seconds=61)))
            self.assertEqual(len(auth2._grants), 0)

    def test_max_sessions_enforced_across_restart_without_evicting_active_sessions(self) -> None:
        t0 = datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC)
        with Authorizer(
            workspace_root=self.workspace,
            max_sessions=2,
            session_ttl_seconds=60,
            state_store=SqliteStateStore(self.db_path),
        ) as auth1:
            s1 = auth1.create_session(now=t0)
            auth1.create_session(now=t0 + timedelta(seconds=1))

        with Authorizer(
            workspace_root=self.workspace,
            max_sessions=2,
            session_ttl_seconds=60,
            state_store=SqliteStateStore(self.db_path),
        ) as auth2:
            with self.assertRaises(SessionLimitError):
                auth2.create_session(now=t0 + timedelta(seconds=2))
            self.assertEqual(
                auth2.authorize(
                    ToolCallRequest(s1, "workspace_read", {"path": "app.py"}),
                    now=t0 + timedelta(seconds=2),
                ).decision,
                Decision.ALLOW,
            )

    def test_grant_not_consumed_when_risk_signal_escalates_and_remains_usable(self) -> None:
        t0 = datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC)
        with Authorizer(workspace_root=self.workspace, state_store=SqliteStateStore(self.db_path)) as auth1:
            sid = auth1.create_session(now=t0)
            auth1.issue_grant(
                session_id=sid,
                tool_name="git_push",
                arguments={"branch": "feature/sig"},
                approved_by="reviewer@mellyn.security",
                max_uses=1,
                now=t0,
            )
            escalated = auth1.authorize(
                ToolCallRequest(
                    sid,
                    "git_push",
                    {"branch": "feature/sig"},
                    signals=RiskSignals(dlp_secret_detected=True),
                ),
                now=t0 + timedelta(seconds=1),
            )
            self.assertEqual(escalated.decision, Decision.DENY)
            self.assertIsNone(escalated.grant_id)

        with Authorizer(workspace_root=self.workspace, state_store=SqliteStateStore(self.db_path)) as auth2:
            clean_retry = auth2.authorize(
                ToolCallRequest(sid, "git_push", {"branch": "feature/sig"}),
                now=t0 + timedelta(seconds=2),
            )
            self.assertEqual(clean_retry.decision, Decision.ALLOW)

    def test_tool_result_auto_taint_and_deferred_taint_persist_across_restart(self) -> None:
        t0 = datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC)
        policy = PolicyConfig(
            allowed_mcp_servers=frozenset({"ext"}),
            tool_risk_tiers={"ext/fetch_issue": RiskTier.LOW},
            tool_capabilities={"ext/fetch_issue": ToolCapability(pure=True)},
        )
        with Authorizer(
            workspace_root=self.workspace,
            policy_config=policy,
            state_store=SqliteStateStore(self.db_path),
        ) as auth1:
            sid1 = auth1.create_session(now=t0)
            res1 = auth1.authorize(ToolCallRequest(sid1, "fetch_issue", {}, mcp_server="ext"), now=t0)
            self.assertEqual(res1.decision, Decision.ALLOW)

            sid2 = auth1.create_session(now=t0)
            deferred_req = ToolCallRequest(sid2, "fetch_issue", {}, mcp_server="ext")
            res2 = auth1.authorize(deferred_req, now=t0, record_taint_on_allow=False)
            self.assertEqual(res2.decision, Decision.ALLOW)
            self.assertFalse(auth1.is_tainted(sid2))
            self.assertTrue(auth1.record_tool_result_taint(deferred_req, now=t0 + timedelta(seconds=1)))

        with Authorizer(
            workspace_root=self.workspace,
            policy_config=policy,
            state_store=SqliteStateStore(self.db_path),
        ) as auth2:
            self.assertTrue(auth2.is_tainted(sid1))
            self.assertTrue(auth2.is_tainted(sid2))
            self.assertEqual(auth2.get_taint_count(sid1), 1)
            self.assertEqual(auth2.get_taint_count(sid2), 1)


class TestSqliteStateStoreConcurrency(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self._tmpdir.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.db_path = self.root / "concurrent.db"

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_concurrent_single_use_grant_allows_exactly_once_across_two_authorizer_instances(self) -> None:
        t0 = datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC)
        with (
            Authorizer(workspace_root=self.workspace, state_store=SqliteStateStore(self.db_path)) as auth1,
            Authorizer(workspace_root=self.workspace, state_store=SqliteStateStore(self.db_path)) as auth2,
        ):
            sid = auth1.create_session(now=t0)
            auth1.issue_grant(
                session_id=sid,
                tool_name="git_push",
                arguments={"branch": "feature/race"},
                approved_by="reviewer@mellyn.security",
                max_uses=1,
                now=t0,
            )

            workers = 8
            barrier = threading.Barrier(workers)
            results: list[Decision] = []
            results_lock = threading.Lock()

            def _worker(idx: int) -> None:
                auth = auth1 if idx % 2 == 0 else auth2
                barrier.wait(timeout=10)
                res = auth.authorize(
                    ToolCallRequest(sid, "git_push", {"branch": "feature/race"}),
                    now=t0 + timedelta(seconds=1),
                )
                with results_lock:
                    results.append(res.decision)

            threads = [threading.Thread(target=_worker, args=(i,)) for i in range(workers)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=15)
                self.assertFalse(t.is_alive())

            self.assertEqual(results.count(Decision.ALLOW), 1)
            self.assertEqual(results.count(Decision.REQUIRE_APPROVAL), workers - 1)

    def test_concurrent_session_creation_respects_max_sessions(self) -> None:
        t0 = datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC)
        with (
            Authorizer(
                workspace_root=self.workspace, max_sessions=3, state_store=SqliteStateStore(self.db_path)
            ) as auth1,
            Authorizer(
                workspace_root=self.workspace, max_sessions=3, state_store=SqliteStateStore(self.db_path)
            ) as auth2,
        ):
            workers = 8
            barrier = threading.Barrier(workers)
            created: list[str] = []
            limited: list[SessionLimitError] = []
            outcome_lock = threading.Lock()

            def _worker(idx: int) -> None:
                auth = auth1 if idx % 2 == 0 else auth2
                barrier.wait(timeout=10)
                try:
                    sid = auth.create_session(now=t0)
                    with outcome_lock:
                        created.append(sid)
                except SessionLimitError as exc:
                    with outcome_lock:
                        limited.append(exc)

            threads = [threading.Thread(target=_worker, args=(i,)) for i in range(workers)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=15)
                self.assertFalse(t.is_alive())

            self.assertEqual(len(created), 3)
            self.assertEqual(len(limited), workers - 3)


class TestSqliteStateStoreFailClosed(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_corrupt_or_unknown_schema_db_fails_closed(self) -> None:
        corrupt_path = self.root / "corrupt.db"
        corrupt_bytes = b"not a valid sqlite database payload!!"
        corrupt_path.write_bytes(corrupt_bytes)
        with self.assertRaises(StateStoreError):
            SqliteStateStore(corrupt_path)
        self.assertEqual(corrupt_path.read_bytes(), corrupt_bytes)

        alien_path = self.root / "alien.db"
        with closing(sqlite3.connect(str(alien_path))) as conn:
            conn.execute("CREATE TABLE alien (id INTEGER PRIMARY KEY)")
            conn.commit()
        with self.assertRaises(StateStoreError):
            SqliteStateStore(alien_path)

        bad_version_path = self.root / "bad_version.db"
        store = SqliteStateStore(bad_version_path)
        store.close()
        with closing(sqlite3.connect(str(bad_version_path))) as conn:
            conn.execute("UPDATE schema_meta SET value = '99' WHERE key = 'schema_version'")
            conn.commit()
        with self.assertRaises(StateStoreError):
            SqliteStateStore(bad_version_path)

        missing_table_path = self.root / "missing_table.db"
        store2 = SqliteStateStore(missing_table_path)
        store2.close()
        with closing(sqlite3.connect(str(missing_table_path))) as conn:
            conn.execute("DROP TABLE grants")
            conn.commit()
        with self.assertRaises(StateStoreError):
            SqliteStateStore(missing_table_path)

    def test_empty_and_directory_paths_rejected_fail_closed(self) -> None:
        for bad in ("", "   ", self.root):
            with self.subTest(bad=bad), self.assertRaises(StateStoreError):
                SqliteStateStore(bad)

    def test_closed_store_fails_closed_on_subsequent_calls(self) -> None:
        t0 = datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC)
        store = SqliteStateStore(self.root / "closed.db")
        store.close()
        store.close()  # closing twice is safe and idempotent
        with self.assertRaises(StateStoreError):
            store.create_session("ses_after_close", now=t0, session_ttl_seconds=60, max_sessions=10)
        with self.assertRaises(StateStoreError):
            store.has_session("ses_after_close", now=t0, session_ttl_seconds=60)

    def test_symlink_db_path_rejected_fail_closed(self) -> None:
        real_target = self.root / "real.db"
        link_path = self.root / "link.db"
        try:
            os.symlink(real_target, link_path)
        except OSError as exc:
            self.skipTest(f"OS environment does not allow symlink creation: {exc}")
        with self.assertRaises(StateStoreError):
            SqliteStateStore(link_path)

    def test_posix_file_permissions_are_0600(self) -> None:
        if os.name != "posix":
            self.skipTest("POSIX 0600 mode check applies only on POSIX filesystems.")
        db_path = self.root / "perms.db"
        with SqliteStateStore(db_path):
            pass
        mode = stat.S_IMODE(db_path.stat().st_mode)
        self.assertEqual(mode, 0o600)


class TestSqliteStateStoreReviewFixes(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self._tmpdir.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_triggers_views_and_extra_indexes_fail_closed(self) -> None:
        planted = {
            "trigger": "CREATE TRIGGER clear_taint AFTER UPDATE ON sessions BEGIN UPDATE sessions SET tainted = 0; END",
            "view": "CREATE VIEW clean_sessions AS SELECT session_id FROM sessions WHERE tainted = 0",
            "extra index": "CREATE INDEX idx_extra ON grants (tool_name)",
            "extra table": "CREATE TABLE notes (body TEXT)",
        }
        for label, ddl in planted.items():
            with self.subTest(planted=label):
                path = self.root / f"{label.replace(' ', '_')}.db"
                SqliteStateStore(path).close()
                SqliteStateStore(path).close()  # an untouched database reopens cleanly
                with closing(sqlite3.connect(str(path))) as conn:
                    conn.execute(ddl)
                    conn.commit()
                with self.assertRaises(StateStoreError):
                    SqliteStateStore(path)

        # A database holding only a view has no tables, so it must not be mistaken for a fresh one.
        view_only = self.root / "view_only.db"
        with closing(sqlite3.connect(str(view_only))) as conn:
            conn.execute("CREATE VIEW v AS SELECT 1 AS one")
            conn.commit()
        with self.assertRaises(StateStoreError):
            SqliteStateStore(view_only)

    def test_new_state_files_are_private_from_the_moment_they_exist(self) -> None:
        if os.name != "posix":
            self.skipTest("POSIX file modes only.")
        seen: dict[str, int] = {}
        original = SqliteStateStore._enforce_posix_permissions

        def record_then_enforce(store: SqliteStateStore) -> None:
            for candidate in store._sidecar_paths():
                if candidate.exists() and candidate.name not in seen:
                    seen[candidate.name] = stat.S_IMODE(candidate.stat().st_mode)
            original(store)

        old_umask = os.umask(0o022)  # the usual default on a Linux host
        self.addCleanup(os.umask, old_umask)
        db_path = self.root / "fresh" / "state.db"
        with mock.patch.object(SqliteStateStore, "_enforce_posix_permissions", record_then_enforce):
            SqliteStateStore(db_path).close()

        self.assertEqual(stat.S_IMODE(db_path.parent.stat().st_mode), 0o700)
        self.assertIn("state.db", seen)
        # Modes as first seen, before the store's own chmod: already private, so no window where they are not.
        for name, mode in seen.items():
            with self.subTest(file=name):
                self.assertEqual(mode, 0o600)

    def test_spent_and_expired_grants_are_deleted_not_kept_on_disk(self) -> None:
        t0 = datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC)
        db_path = self.root / "grants.db"
        stores = {"sqlite": SqliteStateStore(db_path), "memory": InMemoryStateStore()}
        for label, store in stores.items():
            with self.subTest(store=label), Authorizer(workspace_root=self.workspace, state_store=store) as az:
                sid = az.create_session(now=t0)
                az.issue_grant(
                    session_id=sid, tool_name="git_push", arguments={"branch": "spent"}, approved_by="a", now=t0
                )
                az.issue_grant(
                    session_id=sid,
                    tool_name="git_push",
                    arguments={"branch": "short"},
                    approved_by="a",
                    ttl_seconds=60,
                    now=t0,
                )
                result = az.authorize(
                    ToolCallRequest(session_id=sid, tool_name="git_push", arguments={"branch": "spent"}),
                    now=t0 + timedelta(seconds=120),
                )
                self.assertEqual(result.decision, Decision.ALLOW)
                # One grant is used up and the other has expired: neither can authorize anything any more.
                self.assertEqual(az._grants, {})
        with closing(sqlite3.connect(str(db_path))) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM grants").fetchone(), (0,))


class TestDeploymentPersistenceWiring(unittest.TestCase):
    def test_dockerfile_configures_state_db_dir_and_env(self) -> None:
        dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("MELLYN_STATE_DB_PATH=/var/lib/mellyn/state.db", dockerfile)
        self.assertIn("chmod 0700 /var/lib/mellyn", dockerfile)
        self.assertIn("chmod 0700 /var/log/mellyn", dockerfile)

    def test_compose_isolates_authorizer_state_volume(self) -> None:
        compose = (REPO_ROOT / "deploy" / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("MELLYN_STATE_DB_PATH: /var/lib/mellyn/state.db", compose)
        self.assertIn("mellyn-authorizer-state:/var/lib/mellyn", compose)

        gateway_section = compose.split("mellyn-gateway:", 1)[1].split("mellyn-approval-relay:", 1)[0]
        relay_section = compose.split("mellyn-approval-relay:", 1)[1].split("mellyn-egress:", 1)[0]
        egress_section = compose.split("mellyn-egress:", 1)[1].split("networks:", 1)[0]
        for section in (gateway_section, relay_section, egress_section):
            self.assertNotIn("mellyn-authorizer-state", section)


if __name__ == "__main__":
    unittest.main()
