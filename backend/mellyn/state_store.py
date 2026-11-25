"""Durable fail-closed state store backends for the Mellyn Security Authorizer."""

from __future__ import annotations

import os
import sqlite3
import threading
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from mellyn.models import ApprovalGrant, TaintSource

STATE_SCHEMA_VERSION = 2
_UTC_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

_V1_SESSION_COLUMNS: frozenset[str] = frozenset(
    {"session_id", "created_at_us", "last_seen_at_us", "tainted", "taint_count"}
)
_REQUIRED_SCHEMA_COLUMNS: dict[str, frozenset[str]] = {
    "schema_meta": frozenset({"key", "value"}),
    "sessions": frozenset(
        {"session_id", "created_at_us", "last_seen_at_us", "tainted", "taint_count", "owner_subject"}
    ),
    "session_taints": frozenset({"id", "session_id", "source_type", "origin", "recorded_at_us", "formatted_entry"}),
    "grants": frozenset(
        {
            "grant_id",
            "session_id",
            "tool_name",
            "mcp_server",
            "mcp_method",
            "arguments_json",
            "approved_by",
            "expires_at_us",
            "max_uses",
            "uses",
        }
    ),
}

_SQL_CREATE_SCHEMA_META = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
)
"""

_SQL_CREATE_SESSIONS = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    created_at_us INTEGER NOT NULL,
    last_seen_at_us INTEGER NOT NULL,
    tainted INTEGER NOT NULL CHECK (tainted IN (0, 1)),
    taint_count INTEGER NOT NULL CHECK (taint_count >= 0),
    owner_subject TEXT
)
"""

_SQL_CREATE_SESSION_TAINTS = """
CREATE TABLE IF NOT EXISTS session_taints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    source_type TEXT NOT NULL,
    origin TEXT NOT NULL,
    recorded_at_us INTEGER NOT NULL,
    formatted_entry TEXT NOT NULL
)
"""

_SQL_CREATE_SESSION_TAINTS_IDX = """
CREATE INDEX IF NOT EXISTS idx_session_taints_session_id
ON session_taints (session_id, id)
"""

_SQL_CREATE_GRANTS = """
CREATE TABLE IF NOT EXISTS grants (
    grant_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    mcp_server TEXT,
    mcp_method TEXT,
    arguments_json TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    expires_at_us INTEGER NOT NULL,
    max_uses INTEGER NOT NULL CHECK (max_uses >= 1),
    uses INTEGER NOT NULL CHECK (uses >= 0 AND uses <= max_uses)
)
"""

_SQL_CREATE_GRANTS_IDX = """
CREATE INDEX IF NOT EXISTS idx_grants_session_id
ON grants (session_id)
"""


# Indexes this module creates, by name. SQLite's own `sqlite_autoindex_*` (for TEXT primary keys) and the
# `sqlite_sequence` table (for AUTOINCREMENT) are also expected; nothing else is.
_EXPECTED_INDEXES: frozenset[str] = frozenset({"idx_session_taints_session_id", "idx_grants_session_id"})


def _is_expected_object(kind: str, name: str, table: str) -> bool:
    if kind == "table":
        return name in _REQUIRED_SCHEMA_COLUMNS or name == "sqlite_sequence"
    if kind == "index":
        if table not in _REQUIRED_SCHEMA_COLUMNS:
            return False
        return name in _EXPECTED_INDEXES or name.startswith("sqlite_autoindex_")
    return False  # triggers and views are never part of the schema


class StateStoreError(RuntimeError):
    """Raised when persistent authorizer state is corrupt, incompatible, unwritable, or closed (fail closed)."""


class SessionLimitError(RuntimeError):
    """The authorizer already holds max_sessions active sessions. Existing sessions are not evicted."""


@dataclass(frozen=True)
class SessionSnapshot:
    """Immutable snapshot of a session and its bounded taint history."""

    session_id: str
    created_at: datetime
    last_seen_at: datetime
    tainted: bool
    taint_count: int
    taint_sample: tuple[TaintSource, ...]
    taint_entries: tuple[str, ...]
    owner_subject: str | None = None


def _dt_to_us(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() is None:
        raise StateStoreError("Naive datetime without timezone is not permitted in authorizer state.")
    delta = value.astimezone(UTC) - _UTC_EPOCH
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


def _us_to_dt(micros: int) -> datetime:
    return _UTC_EPOCH + timedelta(microseconds=micros)


class AuthorizerStateStore(Protocol):
    """Storage abstraction for sessions, taint history, and single-use human grants."""

    def create_session(
        self,
        session_id: str,
        *,
        now: datetime,
        session_ttl_seconds: int | None,
        max_sessions: int,
        owner_subject: str | None = None,
    ) -> None: ...

    def delete_session(self, session_id: str) -> bool: ...

    def has_session(
        self,
        session_id: str,
        *,
        now: datetime,
        session_ttl_seconds: int | None,
    ) -> bool: ...

    def touch_session(
        self,
        session_id: str,
        *,
        now: datetime,
        session_ttl_seconds: int | None,
    ) -> SessionSnapshot | None: ...

    def record_taint(
        self,
        session_id: str,
        source: TaintSource,
        formatted_entry: str,
        *,
        now: datetime,
        session_ttl_seconds: int | None,
        max_taint_sample: int,
        missing_ok: bool = False,
    ) -> tuple[int, tuple[str, ...]] | None: ...

    def get_session_snapshot(self, session_id: str) -> SessionSnapshot | None: ...

    def issue_grant(
        self,
        grant: ApprovalGrant,
        *,
        now: datetime,
        session_ttl_seconds: int | None,
    ) -> None: ...

    def list_usable_grants(self, session_id: str, *, now: datetime) -> list[ApprovalGrant]: ...

    def consume_grant(self, grant_id: str, *, now: datetime) -> bool: ...

    def active_grants_snapshot(self) -> dict[str, ApprovalGrant]: ...

    def close(self) -> None: ...


@dataclass
class _InMemorySessionRecord:
    created_at: datetime
    last_seen_at: datetime
    tainted: bool = False
    taint_count: int = 0
    taint_sample: deque[TaintSource] = field(default_factory=deque)
    taint_entries: deque[str] = field(default_factory=deque)
    owner_subject: str | None = None


class InMemoryStateStore:
    """Thread-safe ephemeral state store keeping sessions, taint, and grants in process memory."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, _InMemorySessionRecord] = {}
        self._grants: dict[str, ApprovalGrant] = {}
        self._grant_uses: dict[str, int] = {}

    def _evict_session_locked(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
        stale_grants = [gid for gid, grant in self._grants.items() if grant.session_id == session_id]
        for gid in stale_grants:
            del self._grants[gid]
            self._grant_uses.pop(gid, None)

    def _prune_sessions_locked(self, now: datetime, session_ttl_seconds: int | None) -> None:
        if session_ttl_seconds is None:
            return
        cutoff = now - timedelta(seconds=session_ttl_seconds)
        expired = [sid for sid, state in self._sessions.items() if state.last_seen_at < cutoff]
        for sid in expired:
            self._evict_session_locked(sid)

    def _prune_grants_locked(self, now: datetime) -> None:
        for grant_id in [g.grant_id for g in self._grants.values() if not g.is_valid(now)]:
            del self._grants[grant_id]
            del self._grant_uses[grant_id]

    @staticmethod
    def _to_snapshot(session_id: str, state: _InMemorySessionRecord) -> SessionSnapshot:
        return SessionSnapshot(
            session_id=session_id,
            created_at=state.created_at,
            last_seen_at=state.last_seen_at,
            tainted=state.tainted,
            taint_count=state.taint_count,
            taint_sample=tuple(state.taint_sample),
            taint_entries=tuple(state.taint_entries),
            owner_subject=state.owner_subject,
        )

    def create_session(
        self,
        session_id: str,
        *,
        now: datetime,
        session_ttl_seconds: int | None,
        max_sessions: int,
        owner_subject: str | None = None,
    ) -> None:
        with self._lock:
            self._prune_sessions_locked(now, session_ttl_seconds)
            # Refuse rather than evict: evicting active sessions would enable DoS across callers.
            if len(self._sessions) >= max_sessions:
                raise SessionLimitError(f"Session limit ({max_sessions}) reached; try again later.")
            self._sessions[session_id] = _InMemorySessionRecord(
                created_at=now,
                last_seen_at=now,
                owner_subject=owner_subject,
            )

    def delete_session(self, session_id: str) -> bool:
        with self._lock:
            existed = session_id in self._sessions
            self._evict_session_locked(session_id)
            return existed

    def has_session(
        self,
        session_id: str,
        *,
        now: datetime,
        session_ttl_seconds: int | None,
    ) -> bool:
        with self._lock:
            self._prune_sessions_locked(now, session_ttl_seconds)
            return session_id in self._sessions

    def touch_session(
        self,
        session_id: str,
        *,
        now: datetime,
        session_ttl_seconds: int | None,
    ) -> SessionSnapshot | None:
        with self._lock:
            self._prune_sessions_locked(now, session_ttl_seconds)
            state = self._sessions.get(session_id)
            if state is None:
                return None
            state.last_seen_at = now
            return self._to_snapshot(session_id, state)

    def record_taint(
        self,
        session_id: str,
        source: TaintSource,
        formatted_entry: str,
        *,
        now: datetime,
        session_ttl_seconds: int | None,
        max_taint_sample: int,
        missing_ok: bool = False,
    ) -> tuple[int, tuple[str, ...]] | None:
        with self._lock:
            self._prune_sessions_locked(now, session_ttl_seconds)
            state = self._sessions.get(session_id)
            if state is None:
                if missing_ok:
                    return None
                raise KeyError(f"Unknown session '{session_id}'.")
            if state.taint_sample.maxlen != max_taint_sample:
                state.taint_sample = deque(state.taint_sample, maxlen=max_taint_sample)
            if state.taint_entries.maxlen != max_taint_sample:
                state.taint_entries = deque(state.taint_entries, maxlen=max_taint_sample)
            state.last_seen_at = now
            state.tainted = True
            state.taint_count += 1
            state.taint_sample.append(source)
            state.taint_entries.append(formatted_entry)
            return state.taint_count, tuple(state.taint_entries)

    def get_session_snapshot(self, session_id: str) -> SessionSnapshot | None:
        with self._lock:
            state = self._sessions.get(session_id)
            if state is None:
                return None
            return self._to_snapshot(session_id, state)

    def issue_grant(
        self,
        grant: ApprovalGrant,
        *,
        now: datetime,
        session_ttl_seconds: int | None,
    ) -> None:
        with self._lock:
            self._prune_sessions_locked(now, session_ttl_seconds)
            state = self._sessions.get(grant.session_id)
            if state is None:
                raise KeyError(f"Unknown session '{grant.session_id}'.")
            state.last_seen_at = now
            self._prune_grants_locked(now)
            self._grants[grant.grant_id] = grant
            self._grant_uses[grant.grant_id] = 0

    def list_usable_grants(self, session_id: str, *, now: datetime) -> list[ApprovalGrant]:
        with self._lock:
            return [
                grant
                for grant in self._grants.values()
                if grant.session_id == session_id
                and self._grant_uses.get(grant.grant_id, grant.max_uses) < grant.max_uses
                and grant.is_valid(now)
            ]

    def consume_grant(self, grant_id: str, *, now: datetime) -> bool:
        with self._lock:
            grant = self._grants.get(grant_id)
            if grant is None or not grant.is_valid(now):
                return False
            uses = self._grant_uses.get(grant_id, grant.max_uses)
            if uses >= grant.max_uses:
                return False
            self._grant_uses[grant_id] = uses + 1
            if uses + 1 >= grant.max_uses:
                del self._grants[grant_id]
                del self._grant_uses[grant_id]
            self._prune_grants_locked(now)
            return True

    def active_grants_snapshot(self) -> dict[str, ApprovalGrant]:
        with self._lock:
            return dict(self._grants)

    def close(self) -> None:
        return None


class SqliteStateStore:
    """
    Fail-closed SQLite state backend persisting sessions, bounded taint history, and grants.

    Uses WAL mode, strict foreign-key cascades, `PRAGMA quick_check` startup verification, schema
    version enforcement, atomic `BEGIN IMMEDIATE` grant consumption, and `0600` file permissions
    on POSIX. Any database corruption, alien schema, symlink target, or closed state raises
    `StateStoreError` instead of resetting state cleanly in memory.
    """

    def __init__(self, db_path: Path | str) -> None:
        raw = str(db_path).strip()
        if not raw:
            raise StateStoreError("State database path must not be empty.")
        self._db_path = Path(raw)
        self._lock = threading.Lock()
        self._closed = False
        self._conn: sqlite3.Connection | None = None

        self._reject_symlink_targets()
        self._prepare_parent_dir()
        self._conn = self._open_and_verify()

    @property
    def db_path(self) -> Path:
        return self._db_path

    def _sidecar_paths(self) -> tuple[Path, ...]:
        base = str(self._db_path)
        return (self._db_path, Path(f"{base}-wal"), Path(f"{base}-shm"), Path(f"{base}-journal"))

    def _reject_symlink_targets(self) -> None:
        for candidate in self._sidecar_paths():
            try:
                if candidate.is_symlink():
                    raise StateStoreError(f"State database path '{candidate}' must not be a symlink.")
            except OSError as exc:
                raise StateStoreError(f"Unable to inspect state database path '{candidate}': {exc}") from exc

    def _prepare_parent_dir(self) -> None:
        try:
            if self._db_path.is_dir():
                raise StateStoreError(f"State database path '{self._db_path}' is a directory.")
            if self._db_path.parent.is_symlink():
                raise StateStoreError(f"State database parent '{self._db_path.parent}' must not be a symlink.")
            # A folder this store creates is private (0700 on POSIX). An existing folder is left as the operator set it.
            self._db_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._precreate_private_db_file()
        except OSError as exc:
            raise StateStoreError(f"Failed to prepare directory for '{self._db_path}': {exc}") from exc

    def _precreate_private_db_file(self) -> None:
        """
        Create a new database file as 0600 before SQLite opens it.

        Left to SQLite, the file starts out with the process umask (usually 0644) and only reaches 0600 after
        startup, and anyone who opens it in between keeps a readable handle. SQLite creates the -wal and -shm
        files with the same mode as the database file, so they start out private too.
        """
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self._db_path, flags, 0o600)
        except FileExistsError:
            return  # an existing database keeps its file; _enforce_posix_permissions still narrows it to 0600
        os.close(fd)

    def _enforce_posix_permissions(self) -> None:
        if os.name != "posix":
            return
        for candidate in self._sidecar_paths():
            try:
                if candidate.exists() and not candidate.is_symlink():
                    os.chmod(candidate, 0o600)
            except OSError as exc:
                raise StateStoreError(f"Failed to set 0600 permissions on '{candidate}': {exc}") from exc

    @staticmethod
    def _rollback_quietly(conn: sqlite3.Connection) -> None:
        try:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    def _open_and_verify(self) -> sqlite3.Connection:
        try:
            conn = sqlite3.connect(
                str(self._db_path),
                timeout=10.0,
                isolation_level=None,
                check_same_thread=False,
            )
        except (OSError, sqlite3.Error) as exc:
            raise StateStoreError(f"Failed to open state database '{self._db_path}': {exc}") from exc

        try:
            conn.execute("PRAGMA busy_timeout = 10000")
            qc_rows = conn.execute("PRAGMA quick_check").fetchall()
            if qc_rows != [("ok",)]:
                raise StateStoreError(f"State database '{self._db_path}' failed integrity check: {qc_rows!r}")

            conn.execute("PRAGMA foreign_keys = ON")
            fk_row = conn.execute("PRAGMA foreign_keys").fetchone()
            if fk_row != (1,):
                raise StateStoreError("SQLite foreign key enforcement is unavailable (fail closed).")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = FULL")
            conn.execute("PRAGMA secure_delete = ON")

            self._init_or_verify_schema(conn)
            self._enforce_posix_permissions()
            return conn
        except Exception as exc:
            self._rollback_quietly(conn)
            try:
                conn.close()
            except sqlite3.Error:
                pass
            if isinstance(exc, StateStoreError):
                raise
            raise StateStoreError(f"State database initialization failed for '{self._db_path}': {exc}") from exc

    def _init_or_verify_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute("BEGIN IMMEDIATE")
        objects = conn.execute("SELECT type, name, tbl_name FROM sqlite_master").fetchall()
        if not objects:
            conn.execute(_SQL_CREATE_SCHEMA_META)
            conn.execute(_SQL_CREATE_SESSIONS)
            conn.execute(_SQL_CREATE_SESSION_TAINTS)
            conn.execute(_SQL_CREATE_SESSION_TAINTS_IDX)
            conn.execute(_SQL_CREATE_GRANTS)
            conn.execute(_SQL_CREATE_GRANTS_IDX)
            conn.execute(
                "INSERT INTO schema_meta (key, value) VALUES (?, ?)",
                ("schema_version", str(STATE_SCHEMA_VERSION)),
            )
            conn.execute("COMMIT")
            return

        # Every object must be one this module creates. A trigger, view, or extra index would otherwise survive
        # every restart and could keep rewriting taint or grants long after whoever planted it lost access.
        unexpected = sorted(
            f"{kind} '{name}'" for kind, name, table in objects if not _is_expected_object(kind, name, table)
        )
        if unexpected:
            raise StateStoreError(
                f"State database '{self._db_path}' contains objects this authorizer did not create: "
                f"{', '.join(unexpected)}."
            )

        tables = {name for kind, name, _table in objects if kind == "table" and not name.startswith("sqlite_")}
        expected_tables = set(_REQUIRED_SCHEMA_COLUMNS)
        if tables != expected_tables:
            raise StateStoreError(
                f"State database '{self._db_path}' has unexpected tables {sorted(tables)}; "
                f"expected {sorted(expected_tables)}."
            )

        version_row = conn.execute("SELECT value FROM schema_meta WHERE key = ?", ("schema_version",)).fetchone()
        version_str = None if version_row is None else version_row[0]
        if version_str == "1":
            self._verify_table_columns(conn, sessions_override=_V1_SESSION_COLUMNS)
            cols = {row[1] for row in conn.execute("PRAGMA table_info(sessions)").fetchall()}
            if "owner_subject" not in cols:
                conn.execute("ALTER TABLE sessions ADD COLUMN owner_subject TEXT")
            conn.execute(
                "UPDATE schema_meta SET value = ? WHERE key = ?",
                (str(STATE_SCHEMA_VERSION), "schema_version"),
            )
            self._verify_table_columns(conn)
        elif version_str == str(STATE_SCHEMA_VERSION):
            self._verify_table_columns(conn)
        else:
            raise StateStoreError(
                f"Unsupported state schema_version {version_str!r}; expected '{STATE_SCHEMA_VERSION}'."
            )
        conn.execute("COMMIT")

    @staticmethod
    def _verify_table_columns(
        conn: sqlite3.Connection,
        *,
        sessions_override: frozenset[str] | None = None,
    ) -> None:
        pragma_queries = (
            ("schema_meta", "PRAGMA table_info(schema_meta)"),
            ("sessions", "PRAGMA table_info(sessions)"),
            ("session_taints", "PRAGMA table_info(session_taints)"),
            ("grants", "PRAGMA table_info(grants)"),
        )
        for table_name, pragma_sql in pragma_queries:
            cols = {row[1] for row in conn.execute(pragma_sql).fetchall()}
            expected = (
                sessions_override
                if table_name == "sessions" and sessions_override is not None
                else _REQUIRED_SCHEMA_COLUMNS[table_name]
            )
            if not expected <= cols:
                missing = sorted(expected - cols)
                raise StateStoreError(f"State table '{table_name}' is missing required columns: {missing}")

    def _require_open(self) -> sqlite3.Connection:
        if self._closed or self._conn is None:
            raise StateStoreError("Authorizer state store is closed.")
        return self._conn

    @contextmanager
    def _write_tx(self) -> Iterator[sqlite3.Connection]:
        conn = self._require_open()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.execute("COMMIT")
        except (StateStoreError, KeyError, SessionLimitError):
            self._rollback_quietly(conn)
            raise
        except (sqlite3.Error, OSError) as exc:
            self._rollback_quietly(conn)
            raise StateStoreError(f"State database write failed: {exc}") from exc
        self._enforce_posix_permissions()

    @staticmethod
    def _prune_sessions_conn(conn: sqlite3.Connection, now: datetime, session_ttl_seconds: int | None) -> None:
        if session_ttl_seconds is None:
            return
        cutoff_us = _dt_to_us(now - timedelta(seconds=session_ttl_seconds))
        conn.execute("DELETE FROM sessions WHERE last_seen_at_us < ?", (cutoff_us,))

    @staticmethod
    def _load_snapshot_conn(conn: sqlite3.Connection, session_id: str) -> SessionSnapshot | None:
        row = conn.execute(
            "SELECT created_at_us, last_seen_at_us, tainted, taint_count, owner_subject "
            "FROM sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        if row is None:
            return None
        taint_rows = conn.execute(
            "SELECT source_type, origin, recorded_at_us, formatted_entry "
            "FROM session_taints WHERE session_id = ? ORDER BY id ASC",
            (session_id,),
        ).fetchall()
        sample = tuple(TaintSource(source_type=r[0], origin=r[1], recorded_at=_us_to_dt(r[2])) for r in taint_rows)
        entries = tuple(r[3] for r in taint_rows)
        return SessionSnapshot(
            session_id=session_id,
            created_at=_us_to_dt(row[0]),
            last_seen_at=_us_to_dt(row[1]),
            tainted=bool(row[2]),
            taint_count=int(row[3]),
            taint_sample=sample,
            taint_entries=entries,
            owner_subject=None if row[4] is None else str(row[4]),
        )

    def create_session(
        self,
        session_id: str,
        *,
        now: datetime,
        session_ttl_seconds: int | None,
        max_sessions: int,
        owner_subject: str | None = None,
    ) -> None:
        now_us = _dt_to_us(now)
        with self._lock, self._write_tx() as conn:
            self._prune_sessions_conn(conn, now, session_ttl_seconds)
            count_row = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()
            active = int(count_row[0]) if count_row is not None else 0
            if active >= max_sessions:
                raise SessionLimitError(f"Session limit ({max_sessions}) reached; try again later.")
            conn.execute(
                "INSERT INTO sessions "
                "(session_id, created_at_us, last_seen_at_us, tainted, taint_count, owner_subject) "
                "VALUES (?, ?, ?, 0, 0, ?)",
                (session_id, now_us, now_us, owner_subject),
            )

    def delete_session(self, session_id: str) -> bool:
        with self._lock, self._write_tx() as conn:
            cur = conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
            return cur.rowcount == 1

    def has_session(
        self,
        session_id: str,
        *,
        now: datetime,
        session_ttl_seconds: int | None,
    ) -> bool:
        with self._lock:
            if session_ttl_seconds is not None:
                with self._write_tx() as conn:
                    self._prune_sessions_conn(conn, now, session_ttl_seconds)
                    row = conn.execute("SELECT 1 FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
                    return row is not None
            conn = self._require_open()
            try:
                row = conn.execute("SELECT 1 FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
                return row is not None
            except sqlite3.Error as exc:
                raise StateStoreError(f"State database read failed: {exc}") from exc

    def touch_session(
        self,
        session_id: str,
        *,
        now: datetime,
        session_ttl_seconds: int | None,
    ) -> SessionSnapshot | None:
        now_us = _dt_to_us(now)
        with self._lock, self._write_tx() as conn:
            self._prune_sessions_conn(conn, now, session_ttl_seconds)
            snapshot = self._load_snapshot_conn(conn, session_id)
            if snapshot is None:
                return None
            conn.execute("UPDATE sessions SET last_seen_at_us = ? WHERE session_id = ?", (now_us, session_id))
            return snapshot

    def record_taint(
        self,
        session_id: str,
        source: TaintSource,
        formatted_entry: str,
        *,
        now: datetime,
        session_ttl_seconds: int | None,
        max_taint_sample: int,
        missing_ok: bool = False,
    ) -> tuple[int, tuple[str, ...]] | None:
        now_us = _dt_to_us(now)
        recorded_us = _dt_to_us(source.recorded_at)
        with self._lock, self._write_tx() as conn:
            self._prune_sessions_conn(conn, now, session_ttl_seconds)
            exists = conn.execute("SELECT 1 FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
            if exists is None:
                if missing_ok:
                    return None
                raise KeyError(f"Unknown session '{session_id}'.")

            conn.execute(
                "INSERT INTO session_taints (session_id, source_type, origin, recorded_at_us, formatted_entry) "
                "VALUES (?, ?, ?, ?, ?)",
                (session_id, source.source_type, source.origin, recorded_us, formatted_entry),
            )
            conn.execute(
                "UPDATE sessions SET last_seen_at_us = ?, tainted = 1, taint_count = taint_count + 1 "
                "WHERE session_id = ?",
                (now_us, session_id),
            )
            conn.execute(
                "DELETE FROM session_taints WHERE session_id = ? "
                "AND id NOT IN (SELECT id FROM session_taints WHERE session_id = ? ORDER BY id DESC LIMIT ?)",
                (session_id, session_id, max_taint_sample),
            )
            count_row = conn.execute("SELECT taint_count FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
            taint_count = int(count_row[0]) if count_row is not None else 0
            entries = tuple(
                row[0]
                for row in conn.execute(
                    "SELECT formatted_entry FROM session_taints WHERE session_id = ? ORDER BY id ASC",
                    (session_id,),
                ).fetchall()
            )
            return taint_count, entries

    def get_session_snapshot(self, session_id: str) -> SessionSnapshot | None:
        with self._lock:
            conn = self._require_open()
            try:
                return self._load_snapshot_conn(conn, session_id)
            except sqlite3.Error as exc:
                raise StateStoreError(f"State database read failed: {exc}") from exc

    def issue_grant(
        self,
        grant: ApprovalGrant,
        *,
        now: datetime,
        session_ttl_seconds: int | None,
    ) -> None:
        now_us = _dt_to_us(now)
        expires_us = _dt_to_us(grant.expires_at)
        with self._lock, self._write_tx() as conn:
            self._prune_sessions_conn(conn, now, session_ttl_seconds)
            exists = conn.execute("SELECT 1 FROM sessions WHERE session_id = ?", (grant.session_id,)).fetchone()
            if exists is None:
                raise KeyError(f"Unknown session '{grant.session_id}'.")
            conn.execute(
                "UPDATE sessions SET last_seen_at_us = ? WHERE session_id = ?",
                (now_us, grant.session_id),
            )
            conn.execute("DELETE FROM grants WHERE expires_at_us <= ?", (now_us,))
            conn.execute(
                "INSERT INTO grants (grant_id, session_id, tool_name, mcp_server, mcp_method, "
                "arguments_json, approved_by, expires_at_us, max_uses, uses) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
                (
                    grant.grant_id,
                    grant.session_id,
                    grant.tool_name,
                    grant.mcp_server,
                    grant.mcp_method,
                    grant.arguments_json,
                    grant.approved_by,
                    expires_us,
                    grant.max_uses,
                ),
            )

    @staticmethod
    def _row_to_grant(row: tuple[Any, ...]) -> ApprovalGrant:
        return ApprovalGrant(
            grant_id=str(row[0]),
            session_id=str(row[1]),
            tool_name=str(row[2]),
            mcp_server=None if row[3] is None else str(row[3]),
            mcp_method=None if row[4] is None else str(row[4]),
            arguments_json=str(row[5]),
            approved_by=str(row[6]),
            expires_at=_us_to_dt(int(row[7])),
            max_uses=int(row[8]),
        )

    def list_usable_grants(self, session_id: str, *, now: datetime) -> list[ApprovalGrant]:
        now_us = _dt_to_us(now)
        with self._lock:
            conn = self._require_open()
            try:
                rows = conn.execute(
                    "SELECT grant_id, session_id, tool_name, mcp_server, mcp_method, "
                    "arguments_json, approved_by, expires_at_us, max_uses "
                    "FROM grants WHERE session_id = ? AND uses < max_uses AND expires_at_us > ? "
                    "ORDER BY rowid ASC",
                    (session_id, now_us),
                ).fetchall()
            except sqlite3.Error as exc:
                raise StateStoreError(f"State database read failed: {exc}") from exc
            return [self._row_to_grant(row) for row in rows]

    def consume_grant(self, grant_id: str, *, now: datetime) -> bool:
        now_us = _dt_to_us(now)
        with self._lock, self._write_tx() as conn:
            cur = conn.execute(
                "UPDATE grants SET uses = uses + 1 WHERE grant_id = ? AND uses < max_uses AND expires_at_us > ?",
                (grant_id, now_us),
            )
            consumed = cur.rowcount == 1
            # Spent and expired grants can never authorize anything again, so do not keep their exact approved
            # arguments and approver on disk until the session expires.
            conn.execute("DELETE FROM grants WHERE uses >= max_uses OR expires_at_us <= ?", (now_us,))
            return consumed

    def active_grants_snapshot(self) -> dict[str, ApprovalGrant]:
        with self._lock:
            conn = self._require_open()
            try:
                rows = conn.execute(
                    "SELECT grant_id, session_id, tool_name, mcp_server, mcp_method, "
                    "arguments_json, approved_by, expires_at_us, max_uses "
                    "FROM grants ORDER BY rowid ASC"
                ).fetchall()
            except sqlite3.Error as exc:
                raise StateStoreError(f"State database read failed: {exc}") from exc
            return {grant.grant_id: grant for grant in (self._row_to_grant(row) for row in rows)}

    def close(self) -> None:
        with self._lock:
            self._closed = True
            if self._conn is not None:
                try:
                    self._conn.close()
                finally:
                    self._conn = None

    def __enter__(self) -> SqliteStateStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
