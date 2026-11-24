"""
Async fail-closed MCP stdio proxy with Automatic Activation Device (AAD) containment kill switch.

Architectural invariants (per AGENTS.md):
  - Imports ONLY from `mcp_airlock.core`, `mcp_airlock.egress`, and `mcp_airlock.airlock.{engine,models}`.
  - Stdio wire purity: NEVER writes logs, warnings, or tracebacks to `sys.stdout`. All diagnostics and sanitized
    downstream `stderr` lines go exclusively to `err_stream` (default `sys.stderr`) or `core.audit.AuditLedger`.
  - Subprocess isolation: spawns downstream MCP server via `asyncio.create_subprocess_exec(..., start_new_session=True)`
    with an explicit allowlisted `env` dict—never inherits ambient `os.environ`.
  - Bounded line framing: reads fixed chunks without calling `StreamReader.readline()` so oversized single-line JSON
    bombs fail closed in bounded memory.
  - AAD kill sequence: synchronously flushes redacted `AAD_FIRE` event to `AuditLedger`, emits terminal JSON-RPC
    `-32099` (`AAD_CONTAINMENT_SEVERED`) when an `rpc_id` is active, closes downstream pipes, sends `SIGKILL` to the
    downstream process group / process and awaits exit (zero zombies), and exits with code `78`. The kill and
    shutdown still happen if the audit write fails.
  - Supervised tasks: an unexpected exception in any proxy task shuts the whole session down fail-closed (kill the
    downstream, abort in-flight requests, exit `70`) instead of leaving the proxy half-running.
  - Pinned content only: `tools/call` is refused until a `tools/list` response has passed AgBOM pin verification in
    this session, `tools/list` results are rebuilt from the verified tool definitions (plus a checked `nextCursor`),
    and `initialize` `instructions` are forwarded only when they match `AirlockPolicy.instructions_sha256`.

Known containment limits: `SIGKILL` reaches the downstream's process group, so a descendant that calls `setsid()`
escapes it, and on Windows only the direct child is killed. Full containment needs a cgroup, job object or container.
"""

from __future__ import annotations

import argparse
import asyncio
import ctypes
import hashlib
import math
import os
import queue
import re
import secrets
import signal
import sys
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, Literal, Protocol, TextIO, cast

from pydantic import ValidationError

from mcp_airlock.airlock.engine import (
    MAX_OPAQUE_TOKEN_CHARS,
    compute_instructions_pin,
    evaluate_resource_read,
    evaluate_tool_call,
    evaluate_tool_response,
    rpc_id_problem,
    scan_opaque_token,
    scan_rpc_id,
    verify_tools_list,
)
from mcp_airlock.airlock.models import (
    AirlockPolicy,
    JsonRpcErrorResponse,
    JsonRpcNotification,
    JsonRpcRequest,
    JsonRpcSuccessResponse,
    ToolDefinition,
    parse_airlock_policy_toml,
    parse_jsonrpc_bytes,
)
from mcp_airlock.core.audit import AuditLedger, redact_core_secrets
from mcp_airlock.core.normalize import JsonObject, JsonValue, exact_json_bytes, has_invisible_unicode, strip_invisible
from mcp_airlock.core.schemas import (
    AAD_CONTAINMENT_CONFIRMED_RULE_ID,
    SESSION_STARTED_RULE_ID,
    RedactionRecord,
    Severity,
    Verdict,
    ZoneEvent,
)
from mcp_airlock.egress.scanner import scan_payload

AAD_EXIT_CODE = 78
INTERNAL_FAULT_EXIT_CODE = 70  # EX_SOFTWARE: a proxy task raised; the session was shut down fail-closed

JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_INTERNAL_ERROR = -32603
JSONRPC_POLICY_VIOLATION = -32000
JSONRPC_REQUEST_TIMEOUT = -32001
JSONRPC_AAD_CONTAINMENT_SEVERED = -32099

DEFAULT_REQUEST_TIMEOUT_SECONDS = 30.0
# How long one write to the client may take before the client is treated as gone (it stopped reading stdout).
DEFAULT_CLIENT_WRITE_TIMEOUT_SECONDS = 5.0
DEFAULT_CLI_STDIN_READ_CHUNK_BYTES = 4096
DEFAULT_CLI_STDIN_READAHEAD_BYTES = 65_536
MAX_STDERR_LINE_BYTES = 4096
# Ids of requests that timed out are remembered (bounded) so a late answer is dropped instead of firing AAD as a
# "spoofed" id, and so the client cannot reuse such an id and receive the old request's late answer.
MAX_EXPIRED_ID_TOMBSTONES = 4096
# `nextCursor` values the server returned on verified `tools/list` pages; only these may be sent back as `cursor`.
MAX_ISSUED_CURSORS = 256
MAX_RECORDED_REDACTED_PAYLOAD_BYTES = 16_384
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

_ALLOWED_CLIENT_REQUEST_METHODS: frozenset[str] = frozenset({"initialize", "ping", "tools/list"})
_ALLOWED_CLIENT_NOTIFICATIONS: frozenset[str] = frozenset({"notifications/initialized", "notifications/cancelled"})
_HARD_ENFORCED_CALL_RULES: frozenset[str] = frozenset(
    {
        "airlock.request_canonicalization_error",
        "airlock.unsupported_method",
        "airlock.invalid_tool_call_params",
        "airlock.payload_too_large",
        "airlock.invalid_request_id",
    }
)
_HARD_ENFORCED_RESPONSE_RULES: frozenset[str] = frozenset(
    {
        "airlock.response_canonicalization_error",
        "airlock.response_too_large",
        "airlock.invalid_response_id",
    }
)
_STDERR_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

_POSIX_DEFAULT_ENV_KEYS: tuple[str, ...] = ("PATH", "LANG", "LC_ALL", "TMPDIR", "TZ")
_WIN32_DEFAULT_ENV_KEYS: tuple[str, ...] = ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")

type RpcId = int | str
type EnforcementMode = Literal["enforce", "observe"]


class AsyncByteReader(Protocol):
    """Minimal async byte-stream protocol satisfied by `asyncio.StreamReader` and `BoundedStdinReader`."""

    async def read(self, n: int = -1) -> bytes: ...


class ClientWriter(Protocol):
    """Minimal async writer protocol satisfied by `asyncio.StreamWriter` and in-memory stdio harnesses."""

    def write(self, data: bytes) -> None: ...

    async def drain(self) -> None: ...


@dataclass(frozen=True)
class InFlightRequest:
    """Correlation record for one active client-to-server JSON-RPC request."""

    rpc_id: RpcId
    method: str
    started_monotonic: float
    tool_name: str | None = None
    # True for a `tools/list` request that sent a `cursor` (a later page of a paginated listing).
    paginated: bool = False


def build_minimal_subprocess_env(
    *,
    allowed_keys: Sequence[str] | None = None,
    extra_env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """
    Build an explicit minimal environment dictionary for the downstream MCP server.

    Never copies ambient `os.environ`; only explicitly allowlisted keys (such as `PATH` or `TMPDIR`) are carried over.
    """
    defaults = _WIN32_DEFAULT_ENV_KEYS if sys.platform == "win32" else _POSIX_DEFAULT_ENV_KEYS
    keys = defaults if allowed_keys is None else tuple(allowed_keys)
    env: dict[str, str] = {}
    for key in keys:
        val = os.environ.get(key)
        if val is not None:
            env[key] = val
    env.setdefault("PYTHONUTF8", "1")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    if extra_env is not None:
        env.update(extra_env)
    return env


class BoundedLineReader:
    """
    Chunked newline-delimited async reader that enforces `max_bytes` before buffering or JSON decoding.

    Avoids `asyncio.StreamReader.readline()` so an attacker cannot trigger `LimitOverrunError` or unbounded heap growth
    via single-line JSON bombs.
    """

    def __init__(self, reader: AsyncByteReader, *, max_bytes: int) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive.")
        self._reader = reader
        self._max_bytes = max_bytes
        self._chunk_size = max(64, min(65_536, max_bytes + 2))
        self._buf = bytearray()

    async def read_frame(self) -> tuple[bytes | None, bool]:
        """
        Return `(frame_bytes, oversized)`.

        - `(None, False)` on clean EOF with no pending partial frame.
        - `(None, True)` if a line exceeds `max_bytes` (after draining through its terminating `\\n` or EOF).
        - `(frame_bytes, False)` for a valid frame within `max_bytes` (trailing `\\r` stripped).
        """
        oversized = False
        while True:
            nl_idx = self._buf.find(b"\n")
            if nl_idx != -1:
                raw_line = bytes(self._buf[:nl_idx])
                del self._buf[: nl_idx + 1]
                if oversized:
                    return None, True
                frame = raw_line[:-1] if raw_line.endswith(b"\r") else raw_line
                if len(frame) > self._max_bytes:
                    return None, True
                return frame, False

            if not oversized and len(self._buf) > self._max_bytes + 1:
                oversized = True
                self._buf.clear()

            chunk = await self._reader.read(self._chunk_size)
            if not chunk:
                if oversized:
                    return None, True
                if not self._buf:
                    return None, False
                frame = bytes(self._buf[:-1] if self._buf.endswith(b"\r") else self._buf)
                self._buf.clear()
                if len(frame) > self._max_bytes:
                    return None, True
                return frame, False

            if oversized:
                chunk_nl = chunk.find(b"\n")
                if chunk_nl != -1:
                    self._buf.extend(chunk[chunk_nl + 1 :])
                    return None, True
            else:
                self._buf.extend(chunk)


if sys.platform == "win32":
    from ctypes import wintypes

    class _BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            (name, ctypes.c_uint64) for name in ("Reads", "Writes", "Other", "ReadBytes", "WriteBytes", "OtherBytes")
        ]

    class _ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimitInformation),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    _kernel32.SetInformationJobObject.restype = wintypes.BOOL
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    _kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _kernel32.TerminateJobObject.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL


class _WindowsJob:
    """
    A Windows Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. Every process in the job (the downstream and the
    children it starts after being assigned) is terminated when the last handle closes, which includes the proxy
    itself being killed. `terminate()` kills the whole tree on AAD. Raises `OSError` if the job cannot be set up.
    """

    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
    _PROCESS_SET_QUOTA = 0x0100
    _PROCESS_TERMINATE = 0x0001

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise OSError("Job Objects exist only on Windows.")
        handle = _kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        info = _ExtendedLimitInformation()
        info.BasicLimitInformation.LimitFlags = self._JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not _kernel32.SetInformationJobObject(
            handle, self._JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(info), ctypes.sizeof(info)
        ):
            err = ctypes.WinError(ctypes.get_last_error())
            _kernel32.CloseHandle(handle)
            raise err
        self._handle: int | None = handle

    def assign(self, pid: int) -> None:
        if sys.platform != "win32" or self._handle is None:
            raise OSError("Job Object is not open.")
        proc_handle = _kernel32.OpenProcess(self._PROCESS_SET_QUOTA | self._PROCESS_TERMINATE, False, pid)
        if not proc_handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not _kernel32.AssignProcessToJobObject(self._handle, proc_handle):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            _kernel32.CloseHandle(proc_handle)

    def terminate(self) -> None:
        if sys.platform == "win32" and self._handle is not None:
            _kernel32.TerminateJobObject(self._handle, 1)

    def close(self) -> None:
        if sys.platform == "win32" and self._handle is not None:
            _kernel32.CloseHandle(self._handle)
            self._handle = None


def _linux_parent_death_preexec() -> Callable[[], None] | None:
    """
    On Linux, return a `preexec_fn` that sets `PR_SET_PDEATHSIG(SIGKILL)` in the child, so the downstream is killed
    if the proxy dies for any reason (including SIGKILL, which no handler can catch). Returns None elsewhere.

    Note: the signal fires when the *thread* that spawned the child exits; the proxy spawns from its event-loop thread.
    """
    if not sys.platform.startswith("linux"):
        return None
    try:
        prctl = ctypes.CDLL(None, use_errno=True).prctl
    except (OSError, AttributeError):
        return None
    parent_pid = os.getpid()
    sigkill = int(getattr(signal, "SIGKILL", 9))

    def _set_parent_death_signal() -> None:
        prctl(1, sigkill, 0, 0, 0)  # PR_SET_PDEATHSIG
        if os.getppid() != parent_pid:  # the proxy died before the signal was armed
            os._exit(1)

    return _set_parent_death_signal


async def spawn_contained_subprocess(
    command: Sequence[str],
    *,
    env: Mapping[str, str],
    cwd: str | None = None,
    stderr: int = asyncio.subprocess.PIPE,
) -> tuple[asyncio.subprocess.Process, _WindowsJob | None]:
    """
    Spawn an untrusted MCP server so it cannot outlive the proxy: its own session/process group (POSIX), the
    parent-death signal (Linux), and a kill-on-close Job Object (Windows). Fails closed: if the Windows job cannot be
    set up, the child is killed and `OSError` is raised. Processes the child starts before it is assigned to the job,
    or that leave the process group with `setsid()` on POSIX, are not covered.
    """
    proc = await asyncio.create_subprocess_exec(  # noqa: S603 - explicit argv list, never a shell
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=stderr,
        start_new_session=True,
        env=dict(env),
        cwd=cwd,
        preexec_fn=_linux_parent_death_preexec(),
    )
    job: _WindowsJob | None = None
    if sys.platform == "win32":
        try:
            job = _WindowsJob()
            job.assign(proc.pid)
        except OSError:
            if job is not None:
                job.close()
            await _hard_kill_subprocess(proc)
            raise
    return proc, job


async def _hard_kill_subprocess(proc: asyncio.subprocess.Process, *, job: _WindowsJob | None = None) -> None:
    """Forcefully terminate `proc` (its Windows job, or its process group via `SIGKILL` on POSIX) and reap it."""
    if job is not None:
        job.terminate()
    if proc.returncode is None:
        killed_group = False
        if os.name == "posix":
            killpg_fn = getattr(os, "killpg", None)
            sigkill = getattr(signal, "SIGKILL", None)
            if callable(killpg_fn) and isinstance(sigkill, int):
                try:
                    killpg_fn(proc.pid, sigkill)
                    killed_group = True
                except ProcessLookupError:
                    killed_group = True
                except OSError:
                    killed_group = False
        if not killed_group and proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            except OSError:
                pass
    await proc.wait()


def _jsonrpc_error_bytes(
    rpc_id: RpcId | None,
    code: int,
    message: str,
    data: JsonObject | None = None,
) -> bytes:
    err_obj: JsonObject = {"code": code, "message": message}
    if data is not None:
        err_obj["data"] = data
    envelope: JsonObject = {"jsonrpc": "2.0", "id": rpc_id, "error": err_obj}
    return exact_json_bytes(envelope) + b"\n"


def _remember[K](bounded: OrderedDict[K, None], key: K, limit: int) -> None:
    """Insert `key` as most recent, evicting the oldest entries beyond `limit`."""
    bounded[key] = None
    bounded.move_to_end(key)
    while len(bounded) > limit:
        bounded.popitem(last=False)


def _parse_tools_list_result(result: JsonValue) -> list[ToolDefinition]:
    if not isinstance(result, dict):
        raise ValueError("tools/list result must be a JSON object.")
    raw_tools = result.get("tools")
    if not isinstance(raw_tools, list):
        raise ValueError("tools/list result must include a 'tools' array.")
    defs: list[ToolDefinition] = []
    seen_names: set[str] = set()
    for item in raw_tools:
        if not isinstance(item, dict):
            raise ValueError("Each tools/list entry must be a JSON object.")
        tool = ToolDefinition.model_validate(item)
        if tool.name in seen_names:
            raise ValueError(f"Duplicate tool definition name '{tool.name}' in tools/list.")
        seen_names.add(tool.name)
        defs.append(tool)
    return defs


class AirlockProxy:
    """
    Fail-closed async MCP stdio airlock between an MCP client and a single isolated downstream MCP server.
    """

    def __init__(
        self,
        *,
        command: Sequence[str],
        policy: AirlockPolicy,
        ledger: AuditLedger,
        client_reader: AsyncByteReader,
        client_writer: ClientWriter,
        request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
        allowed_env_keys: Sequence[str] | None = None,
        extra_env: Mapping[str, str] | None = None,
        cwd: Path | None = None,
        err_stream: TextIO | None = None,
        aad_on_malformed_server_frame: bool = False,
        session_id: str | None = None,
        client_write_timeout_seconds: float = DEFAULT_CLIENT_WRITE_TIMEOUT_SECONDS,
        mode: EnforcementMode = "enforce",
        record_redacted_payloads: bool = False,
        opaque_policy_errors: bool = False,
    ) -> None:
        if not command:
            raise ValueError("AirlockProxy requires a non-empty command.")
        if not math.isfinite(request_timeout_seconds) or request_timeout_seconds <= 0:
            raise ValueError("request_timeout_seconds must be a finite positive number.")
        if not math.isfinite(client_write_timeout_seconds) or client_write_timeout_seconds <= 0:
            raise ValueError("client_write_timeout_seconds must be a finite positive number.")
        if session_id is not None and not session_id.strip():
            raise ValueError("session_id cannot be blank.")
        if mode not in ("enforce", "observe"):
            raise ValueError(f"Unsupported enforcement mode: {mode!r}")
        if mode == "observe" and not policy.allow_observe_mode:
            # Observe mode forwards every violation; it needs the reviewed policy's consent, not just a launch flag.
            raise ValueError("Observe mode requires `allow_observe_mode = true` in the AirlockPolicy.")

        self._command = tuple(command)
        self._policy = policy
        self._ledger = ledger
        self._client_reader = client_reader
        self._client_writer = client_writer
        self._request_timeout_seconds = float(request_timeout_seconds)
        self._client_write_timeout_seconds = float(client_write_timeout_seconds)
        self._allowed_env_keys = None if allowed_env_keys is None else tuple(allowed_env_keys)
        self._extra_env = dict(extra_env) if extra_env is not None else None
        self._cwd = cwd
        self._err_stream: TextIO = sys.stderr if err_stream is None else err_stream
        self._aad_on_malformed_server_frame = aad_on_malformed_server_frame
        self._session_id = session_id if session_id is not None else f"sess-{secrets.token_hex(8)}"
        self._mode: EnforcementMode = mode
        self._record_redacted_payloads = bool(record_redacted_payloads)
        self._opaque_policy_errors = bool(opaque_policy_errors)

        max_client_frame = max(
            [
                self._policy.max_payload_bytes,
                *(
                    rule.max_payload_bytes
                    for rule in self._policy.tool_rules.values()
                    if rule.max_payload_bytes is not None
                ),
            ]
        )
        self._client_frames = BoundedLineReader(self._client_reader, max_bytes=max_client_frame)

        self._proc: asyncio.subprocess.Process | None = None
        self._in_flight: dict[RpcId, InFlightRequest] = {}
        self._client_write_lock = asyncio.Lock()
        self._downstream_write_lock = asyncio.Lock()
        self._stop_event = asyncio.Event()
        self._idle_event = asyncio.Event()
        self._idle_event.set()
        self._aad_fired = False
        self._aad_trigger_event_id: str | None = None
        self._aad_trigger_artifact_sha256 = _EMPTY_SHA256
        self._aad_trigger_rpc_id: RpcId | None = None
        self._aad_trigger_tool_name: str | None = None
        self._aad_containment_recorded = False
        self._faulted = False
        self._exit_code = 0
        self._downstream_stdin_closed = False
        self._client_stalled = False
        # Windows Job Object (kill-on-close) holding the downstream; None elsewhere.
        self._job: _WindowsJob | None = None
        self._expired_ids: OrderedDict[RpcId, None] = OrderedDict()
        self._issued_cursors: OrderedDict[str, None] = OrderedDict()
        # Tool names from tools/list responses that passed AgBOM verification; None until the first one does.
        self._verified_tool_names: set[str] | None = None

    @property
    def downstream_pid(self) -> int | None:
        return None if self._proc is None else self._proc.pid

    @property
    def downstream_returncode(self) -> int | None:
        return None if self._proc is None else self._proc.returncode

    @property
    def aad_fired(self) -> bool:
        return self._aad_fired

    @property
    def exit_code(self) -> int:
        return self._exit_code

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def mode(self) -> EnforcementMode:
        return self._mode

    def _observe_metadata(self, extra: JsonObject | None = None, *, would_terminate: bool = False) -> JsonObject:
        meta: JsonObject = {
            "enforcement_mode": "observe",
            "would_block": True,
            "would_terminate": would_terminate,
        }
        if extra:
            meta.update(extra)
        return meta

    def _with_redacted_payload(self, metadata: JsonObject | None, payload: JsonValue) -> JsonObject | None:
        if not self._record_redacted_payloads or payload is None:
            return metadata
        encoded = exact_json_bytes(payload)
        merged: JsonObject = dict(metadata) if metadata else {}
        if len(encoded) <= MAX_RECORDED_REDACTED_PAYLOAD_BYTES:
            merged["redacted_payload"] = payload
        else:
            merged["redacted_payload"] = "[TRUNCATED_REDACTED_PAYLOAD]"
            merged["redacted_payload_bytes"] = len(encoded)
        return merged

    def _log_err(self, message: str) -> None:
        """Write sanitized diagnostic text strictly to `err_stream` (never `stdout`)."""
        clean = _STDERR_CTRL_RE.sub("", strip_invisible(message)).rstrip("\r\n")
        sanitized = redact_core_secrets(clean, canary_tokens=tuple(self._policy.canary_tokens))
        try:
            self._err_stream.write(sanitized + "\n")
            self._err_stream.flush()
        except OSError:
            pass

    def _record_event(
        self,
        *,
        action: str,
        verdict_allow: bool,
        severity: Severity,
        rule_id: str,
        reason: str,
        artifact_sha256: str,
        tool_name: str | None = None,
        request_id: RpcId | None = None,
        redactions: Sequence[RedactionRecord] = (),
        metadata: JsonObject | None = None,
    ) -> str:
        merged_metadata: JsonObject = {"session_id": self._session_id}
        if metadata:
            merged_metadata.update(metadata)
        event = ZoneEvent(
            event_id=f"air-{secrets.token_hex(8)}",
            timestamp_utc=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            zone="airlock",
            action=action,
            verdict_allow=verdict_allow,
            severity=severity,
            rule_id=rule_id,
            reason=reason,
            artifact_sha256=artifact_sha256,
            tool_name=tool_name,
            request_id=request_id,
            redactions=list(redactions),
            metadata=merged_metadata,
        )
        self._ledger.record(event)
        return event.event_id

    async def _write_client_bytes(self, payload: bytes, *, allow_during_aad: bool = False) -> None:
        async with self._client_write_lock:
            if self._client_stalled:
                return
            if (self._aad_fired or self._faulted) and not allow_during_aad:
                return
            try:
                self._client_writer.write(payload)
                await asyncio.wait_for(self._client_writer.drain(), timeout=self._client_write_timeout_seconds)
            except TimeoutError:
                self._handle_client_stall()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

    def _handle_client_stall(self) -> None:
        """The client stopped reading stdout: drop further output and end the session (the downstream is killed)."""
        self._client_stalled = True
        self._log_err(
            f"[airlock] client did not read stdout within {self._client_write_timeout_seconds}s; ending session"
        )
        try:
            self._record_event(
                action="client/write",
                verdict_allow=False,
                severity="BLOCK",
                rule_id="airlock.client_write_stalled",
                reason="Client stopped reading the proxy's stdout; session ended.",
                artifact_sha256=_EMPTY_SHA256,
            )
        except Exception as rec_exc:
            self._log_err(f"[airlock] could not record client stall: {type(rec_exc).__name__}")
        self._request_stop()

    async def _emit_client_error(
        self,
        *,
        rpc_id: RpcId | None,
        code: int,
        message: str,
        data: JsonObject | None = None,
        allow_during_aad: bool = False,
    ) -> None:
        wire_message = message
        wire_data = data
        if self._opaque_policy_errors and self._mode == "enforce" and code == JSONRPC_POLICY_VIOLATION:
            wire_message = "Policy violation: request denied."
            wire_data = None
        frame = _jsonrpc_error_bytes(rpc_id, code, wire_message, data=wire_data)
        await self._write_client_bytes(frame, allow_during_aad=allow_during_aad)

    async def _write_downstream_bytes(self, payload: bytes) -> bool:
        proc = self._proc
        if proc is None or proc.stdin is None or self._downstream_stdin_closed or self._aad_fired or self._faulted:
            return False
        async with self._downstream_write_lock:
            if proc.stdin is None or self._downstream_stdin_closed or self._aad_fired or self._faulted:
                return False
            try:
                proc.stdin.write(payload)
                await proc.stdin.drain()
                return True
            except (BrokenPipeError, ConnectionResetError, OSError):
                return False

    def _close_downstream_stdin(self) -> None:
        if self._downstream_stdin_closed:
            return
        self._downstream_stdin_closed = True
        proc = self._proc
        if proc is not None and proc.stdin is not None:
            try:
                proc.stdin.close()
            except OSError:
                pass

    def _add_in_flight(self, req: InFlightRequest) -> None:
        self._in_flight[req.rpc_id] = req
        self._idle_event.clear()

    def _pop_in_flight(self, rpc_id: RpcId) -> InFlightRequest | None:
        req = self._in_flight.pop(rpc_id, None)
        if not self._in_flight:
            self._idle_event.set()
        return req

    async def _fail_closed_on_fault(self, task_name: str, exc: BaseException) -> None:
        """
        Shut the whole session down after an unexpected exception in a proxy task: record it (best effort), abort
        in-flight requests, kill the downstream and stop. A half-running airlock (one pump dead, the others still
        going) would silently stop answering, so every task fault ends the session with `INTERNAL_FAULT_EXIT_CODE`.
        """
        if self._faulted or self._aad_fired:
            return  # the kill-switch or fault sequence already running sets the stop event when it finishes
        self._faulted = True
        self._exit_code = INTERNAL_FAULT_EXIT_CODE
        try:
            self._log_err(f"[airlock FAULT] task={task_name} raised {type(exc).__name__}; failing closed")
            try:
                self._record_event(
                    action="airlock/fault",
                    verdict_allow=False,
                    severity="BLOCK",
                    rule_id="airlock.internal_fault",
                    reason=f"Proxy task '{task_name}' raised {type(exc).__name__}; session shut down fail-closed.",
                    artifact_sha256=_EMPTY_SHA256,
                )
            except Exception as rec_exc:  # the ledger itself may be what failed
                self._log_err(f"[airlock FAULT] could not record fault event: {type(rec_exc).__name__}")
            pending = list(self._in_flight)
            self._in_flight.clear()
            self._idle_event.set()
            # Contain before notifying: a client that has stopped reading must not delay the kill.
            await self._contain_downstream()
            for rpc_id in pending:
                await self._emit_client_error(
                    rpc_id=rpc_id,
                    code=JSONRPC_INTERNAL_ERROR,
                    message="Airlock internal fault; request aborted and session closed.",
                    allow_during_aad=True,
                )
        finally:
            await self._contain_downstream()
            self._stop_event.set()

    async def _contain_downstream(self) -> bool:
        """Sever the downstream input pipe, hard-kill its process group (or job, on Windows) and reap it."""
        self._close_downstream_stdin()
        if self._proc is None:
            return False
        await _hard_kill_subprocess(self._proc, job=self._job)
        return self._proc.returncode is not None

    def _record_aad_containment_confirmed(self) -> None:
        """
        Append one idempotent post-reap confirmation event linked to the triggering AAD_FIRE event.

        Only writes after a real downstream process has exited (`returncode is not None`) and never prevents
        shutdown if the audit write itself fails.
        """
        if (
            self._aad_containment_recorded
            or not self._aad_fired
            or self._aad_trigger_event_id is None
            or self._proc is None
            or self._proc.returncode is None
        ):
            return
        self._aad_containment_recorded = True
        try:
            self._record_event(
                action="airlock/containment",
                verdict_allow=False,
                severity="INFO",
                rule_id=AAD_CONTAINMENT_CONFIRMED_RULE_ID,
                reason="Downstream MCP server process terminated and reaped after AAD_FIRE.",
                artifact_sha256=self._aad_trigger_artifact_sha256,
                tool_name=self._aad_trigger_tool_name,
                request_id=self._aad_trigger_rpc_id,
                metadata={
                    "trigger_event_id": self._aad_trigger_event_id,
                    "downstream_returncode": self._proc.returncode,
                },
            )
        except Exception as rec_exc:
            self._log_err(f"[airlock AAD_FIRE] containment confirmation write failed ({type(rec_exc).__name__})")

    async def _supervised(self, task_name: str, work: Awaitable[None]) -> None:
        try:
            await work
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # any fault must end the session, never leave a pump silently dead
            await self._fail_closed_on_fault(task_name, exc)

    async def _trigger_aad(
        self,
        *,
        action: str,
        rule_id: str,
        reason: str,
        artifact_sha256: str,
        rpc_id: RpcId | None = None,
        tool_name: str | None = None,
        redactions: Sequence[RedactionRecord] = (),
        metadata: JsonObject | None = None,
    ) -> None:
        """
        Execute the AAD containment kill switch sequence:
          1. Synchronously flush & fsync `AAD_FIRE` event to `AuditLedger` (a failed write does not stop step 2).
          2. Close downstream stdin, `SIGKILL` the downstream process group (Windows: terminate its job), reap it,
             and append the linked `airlock.aad_containment_confirmed` completion receipt once reaped.
          3. Only then emit terminal `-32099` (`AAD_CONTAINMENT_SEVERED`) error frames for active `rpc_id`s, each
             bounded by the client write timeout, so a client that stopped reading cannot delay containment.
          4. Stop proxy loop with deterministic exit code `78`.
        """
        if self._aad_fired:
            return
        self._aad_fired = True
        self._exit_code = AAD_EXIT_CODE

        try:
            # 1. Synchronous tamper-evident ledger record first (redacted + fsynced). A failed write must not stop
            #    containment, so it is reported on stderr and the kill sequence continues.
            try:
                self._aad_trigger_event_id = self._record_event(
                    action=action,
                    verdict_allow=False,
                    severity="AAD_FIRE",
                    rule_id=rule_id,
                    reason=reason,
                    artifact_sha256=artifact_sha256,
                    tool_name=tool_name,
                    request_id=rpc_id,
                    redactions=redactions,
                    metadata=metadata,
                )
                self._aad_trigger_artifact_sha256 = artifact_sha256
                self._aad_trigger_rpc_id = rpc_id
                self._aad_trigger_tool_name = tool_name
            except Exception as rec_exc:
                self._log_err(f"[airlock AAD_FIRE] audit write failed ({type(rec_exc).__name__}); containing anyway")
            self._log_err(f"[airlock AAD_FIRE] rule={rule_id} reason={reason}")

            active_ids: list[RpcId] = []
            if rpc_id is not None:
                active_ids.append(rpc_id)
            for pending_id in list(self._in_flight):
                if pending_id not in active_ids:
                    active_ids.append(pending_id)
            self._in_flight.clear()
            self._idle_event.set()

            # 2. Contain first: kill and reap the downstream before any client write that could block.
            if await self._contain_downstream():
                self._record_aad_containment_confirmed()

            # 3. Emit terminal -32099 error frame(s).
            for target_id in active_ids:
                await self._emit_client_error(
                    rpc_id=target_id,
                    code=JSONRPC_AAD_CONTAINMENT_SEVERED,
                    message="AAD_CONTAINMENT_SEVERED",
                    data={"rule_id": rule_id},
                    allow_during_aad=True,
                )
        finally:
            # Containment is guaranteed even if anything above raised (no-op if already done).
            if await self._contain_downstream():
                self._record_aad_containment_confirmed()
            # 4. Signal proxy shutdown.
            self._stop_event.set()

    async def _scan_outbound_envelope(
        self,
        *,
        params: JsonObject,
        request_id: RpcId | None,
    ) -> tuple[bool, bool, str, list[RedactionRecord]]:
        """Return `(ok, is_aad, reason, findings)` for non-`tools/call` outbound requests/notifications."""
        findings: list[RedactionRecord] = []
        canary_hit = False
        blocked_or_secret = False

        p_scan = scan_payload(
            params,
            canary_tokens=self._policy.canary_tokens,
            blocked_patterns=self._policy.blocked_patterns,
            entropy_threshold=self._policy.entropy_threshold,
            min_entropy_length=self._policy.min_entropy_length,
        )
        findings.extend(p_scan.findings)
        canary_hit = canary_hit or p_scan.canary_matched
        blocked_or_secret = blocked_or_secret or (not p_scan.clean)

        # Same id scan as the engine uses for tools/call: no high-entropy check, so random string ids pass.
        id_scan = scan_rpc_id(request_id, self._policy)
        if id_scan is not None:
            findings.extend(id_scan.findings)
            canary_hit = canary_hit or id_scan.canary_matched
            blocked_or_secret = blocked_or_secret or (not id_scan.clean)

        if canary_hit:
            return False, True, "Planted canary token detected in outbound MCP frame.", findings
        if has_invisible_unicode(params) or (isinstance(request_id, str) and has_invisible_unicode(request_id)):
            return False, False, "Invisible Unicode format/tag characters detected in outbound MCP frame.", findings
        if blocked_or_secret:
            return False, False, "Egress scanner detected secret or blocked pattern in outbound MCP frame.", findings
        return True, False, "Outbound MCP frame permitted.", findings

    def _check_next_cursor(self, value: JsonValue) -> tuple[bool, bool, str, list[RedactionRecord]]:
        """Return `(ok, is_aad, reason, findings)` for a server-supplied `tools/list` `nextCursor`."""
        if not isinstance(value, str) or not value or len(value) > MAX_OPAQUE_TOKEN_CHARS:
            return False, False, f"nextCursor must be a non-empty string of at most {MAX_OPAQUE_TOKEN_CHARS} chars.", []
        if _CONTROL_CHARS_RE.search(value) or has_invisible_unicode(value):
            return False, False, "nextCursor contains control or invisible Unicode characters.", []
        scan = scan_opaque_token(value, self._policy, field_path="$.result.nextCursor")
        if scan.canary_matched:
            return False, True, "Planted canary token detected in tools/list nextCursor.", list(scan.findings)
        if not scan.clean:
            return False, False, "Secret or blocked pattern detected in tools/list nextCursor.", list(scan.findings)
        return True, False, "nextCursor permitted.", []

    async def _handle_oversized_client_frame(self) -> None:
        sha = hashlib.sha256(b"").hexdigest()
        self._record_event(
            action="client/frame",
            verdict_allow=False,
            severity="BLOCK",
            rule_id="airlock.client_frame_too_large",
            reason="Client JSON-RPC frame exceeded max_payload_bytes and was discarded.",
            artifact_sha256=sha,
            metadata={"max_payload_bytes": self._policy.max_payload_bytes},
        )
        await self._emit_client_error(
            rpc_id=None,
            code=JSONRPC_POLICY_VIOLATION,
            message="Policy violation: client JSON-RPC frame exceeds max_payload_bytes.",
        )

    async def _handle_client_frame(self, frame: bytes) -> None:
        if not frame.strip():
            return
        frame_sha = hashlib.sha256(frame).hexdigest()
        try:
            msg = parse_jsonrpc_bytes(frame)
            # Re-encode up front: JSON allows escapes (e.g. a lone surrogate "\ud800") that decode to a str but
            # cannot be encoded back to UTF-8. Such a frame is malformed, not a reason to crash the client pump.
            wire_bytes = exact_json_bytes(cast(JsonObject, msg.model_dump(mode="json"))) + b"\n"
        except (UnicodeDecodeError, ValueError, ValidationError):
            self._record_event(
                action="client/frame",
                verdict_allow=False,
                severity="BLOCK",
                rule_id="airlock.malformed_client_frame",
                reason="Malformed JSON-RPC 2.0 frame received from client.",
                artifact_sha256=frame_sha,
            )
            await self._emit_client_error(
                rpc_id=None,
                code=JSONRPC_PARSE_ERROR,
                message="Parse error: malformed JSON-RPC 2.0 frame.",
            )
            return

        if isinstance(msg, JsonRpcSuccessResponse | JsonRpcErrorResponse):
            self._record_event(
                action="client/response",
                verdict_allow=False,
                severity="BLOCK",
                rule_id="airlock.client_response_denied",
                reason="Unexpected response frame received from client.",
                artifact_sha256=frame_sha,
                request_id=msg.id,
            )
            return

        wire_sha = hashlib.sha256(wire_bytes[:-1]).hexdigest()

        if isinstance(msg, JsonRpcNotification):
            await self._handle_client_notification(msg, wire_bytes=wire_bytes, wire_sha=wire_sha)
            return

        await self._handle_client_request(msg, wire_bytes=wire_bytes, wire_sha=wire_sha)

    async def _handle_verdicted_client_call(
        self,
        msg: JsonRpcRequest,
        *,
        action: str,
        verdict: Verdict,
        tool_name: str | None = None,
        require_verified_tool: bool = False,
    ) -> bool:
        """
        Apply an engine `Verdict` for `tools/call` or `resources/read`.
        Returns True if the request should be forwarded to downstream, False if blocked/contained.
        """
        if verdict.rule_id in _HARD_ENFORCED_CALL_RULES:
            self._record_event(
                action=action,
                verdict_allow=False,
                severity="BLOCK",
                rule_id=verdict.rule_id,
                reason=verdict.reason,
                artifact_sha256=verdict.artifact_sha256,
                tool_name=tool_name,
                request_id=msg.id,
                redactions=verdict.redactions,
            )
            await self._emit_client_error(
                rpc_id=msg.id,
                code=JSONRPC_POLICY_VIOLATION,
                message=f"Policy violation ({verdict.rule_id}): {verdict.reason}",
                data={"rule_id": verdict.rule_id},
            )
            return False

        if verdict.severity == "AAD_FIRE":
            if self._mode == "observe":
                self._record_event(
                    action=action,
                    verdict_allow=False,
                    severity="AAD_FIRE",
                    rule_id=verdict.rule_id,
                    reason=verdict.reason,
                    artifact_sha256=verdict.artifact_sha256,
                    tool_name=tool_name,
                    request_id=msg.id,
                    redactions=verdict.redactions,
                    metadata=self._with_redacted_payload(
                        self._observe_metadata(would_terminate=True), verdict.redacted_payload
                    ),
                )
                return True
            await self._trigger_aad(
                action=action,
                rule_id=verdict.rule_id,
                reason=verdict.reason,
                artifact_sha256=verdict.artifact_sha256,
                rpc_id=msg.id,
                tool_name=tool_name,
                redactions=verdict.redactions,
                metadata=self._with_redacted_payload(None, verdict.redacted_payload),
            )
            return False

        if not verdict.verdict_allow:
            if self._mode == "observe":
                self._record_event(
                    action=action,
                    verdict_allow=False,
                    severity="BLOCK",
                    rule_id=verdict.rule_id,
                    reason=verdict.reason,
                    artifact_sha256=verdict.artifact_sha256,
                    tool_name=tool_name,
                    request_id=msg.id,
                    redactions=verdict.redactions,
                    metadata=self._with_redacted_payload(self._observe_metadata(), verdict.redacted_payload),
                )
                return True
            self._record_event(
                action=action,
                verdict_allow=False,
                severity="BLOCK",
                rule_id=verdict.rule_id,
                reason=verdict.reason,
                artifact_sha256=verdict.artifact_sha256,
                tool_name=tool_name,
                request_id=msg.id,
                redactions=verdict.redactions,
                metadata=self._with_redacted_payload(None, verdict.redacted_payload),
            )
            await self._emit_client_error(
                rpc_id=msg.id,
                code=JSONRPC_POLICY_VIOLATION,
                message=f"Policy violation ({verdict.rule_id}): {verdict.reason}",
                data={"rule_id": verdict.rule_id},
            )
            return False

        if require_verified_tool and (self._verified_tool_names is None or tool_name not in self._verified_tool_names):
            not_verified_reason = (
                "No tools/list response has passed AgBOM pin verification in this session yet."
                if self._verified_tool_names is None
                else f"Tool '{tool_name}' was not in the verified tools/list manifest."
            )
            if self._mode == "observe":
                self._record_event(
                    action=action,
                    verdict_allow=False,
                    severity="BLOCK",
                    rule_id="airlock.tool_not_verified",
                    reason=not_verified_reason,
                    artifact_sha256=verdict.artifact_sha256,
                    tool_name=tool_name,
                    request_id=msg.id,
                    metadata=self._with_redacted_payload(self._observe_metadata(), verdict.redacted_payload),
                )
                return True
            self._record_event(
                action=action,
                verdict_allow=False,
                severity="BLOCK",
                rule_id="airlock.tool_not_verified",
                reason=not_verified_reason,
                artifact_sha256=verdict.artifact_sha256,
                tool_name=tool_name,
                request_id=msg.id,
            )
            await self._emit_client_error(
                rpc_id=msg.id,
                code=JSONRPC_POLICY_VIOLATION,
                message=f"Policy violation (airlock.tool_not_verified): {not_verified_reason}",
                data={"rule_id": "airlock.tool_not_verified"},
            )
            return False

        self._record_event(
            action=action,
            verdict_allow=True,
            severity="INFO",
            rule_id=verdict.rule_id,
            reason=verdict.reason,
            artifact_sha256=verdict.artifact_sha256,
            tool_name=tool_name,
            request_id=msg.id,
            metadata=self._with_redacted_payload(None, verdict.redacted_payload),
        )
        return True

    async def _handle_server_violation(
        self,
        *,
        action: str,
        severity: Literal["BLOCK", "AAD_FIRE"],
        rule_id: str,
        reason: str,
        artifact_sha256: str,
        rpc_id: RpcId,
        tool_name: str | None = None,
        redactions: Sequence[RedactionRecord] = (),
        redacted_payload: JsonValue = None,
        already_observed: bool = False,
    ) -> bool:
        """
        Apply a downstream response policy/scanner/AgBOM verdict.
        Returns True when the response was blocked or triggered AAD containment (`enforce` mode),
        or False in `observe` mode after recording the violation once so execution may continue.
        """
        if self._mode == "observe":
            if not already_observed:
                self._record_event(
                    action=action,
                    verdict_allow=False,
                    severity=severity,
                    rule_id=rule_id,
                    reason=reason,
                    artifact_sha256=artifact_sha256,
                    tool_name=tool_name,
                    request_id=rpc_id,
                    redactions=redactions,
                    metadata=self._with_redacted_payload(
                        self._observe_metadata(would_terminate=(severity == "AAD_FIRE")),
                        redacted_payload,
                    ),
                )
            return False

        meta = self._with_redacted_payload(None, redacted_payload)
        if severity == "AAD_FIRE":
            await self._trigger_aad(
                action=action,
                rule_id=rule_id,
                reason=reason,
                artifact_sha256=artifact_sha256,
                rpc_id=rpc_id,
                tool_name=tool_name,
                redactions=redactions,
                metadata=meta,
            )
            return True

        self._record_event(
            action=action,
            verdict_allow=False,
            severity="BLOCK",
            rule_id=rule_id,
            reason=reason,
            artifact_sha256=artifact_sha256,
            tool_name=tool_name,
            request_id=rpc_id,
            redactions=redactions,
            metadata=meta,
        )
        await self._emit_client_error(
            rpc_id=rpc_id,
            code=JSONRPC_POLICY_VIOLATION,
            message=f"Policy violation ({rule_id}): {reason}",
            data={"rule_id": rule_id},
        )
        return True

    async def _handle_client_notification(
        self,
        msg: JsonRpcNotification,
        *,
        wire_bytes: bytes,
        wire_sha: str,
    ) -> None:
        if len(wire_bytes) - 1 > self._policy.max_payload_bytes:
            self._record_event(
                action=msg.method,
                verdict_allow=False,
                severity="BLOCK",
                rule_id="airlock.payload_too_large",
                reason="Client notification exceeded max_payload_bytes.",
                artifact_sha256=wire_sha,
            )
            return
        if msg.method not in _ALLOWED_CLIENT_NOTIFICATIONS:
            if self._mode == "observe":
                self._record_event(
                    action=msg.method,
                    verdict_allow=False,
                    severity="BLOCK",
                    rule_id="airlock.notification_not_allowed",
                    reason=f"Client notification method '{msg.method}' is not allowlisted.",
                    artifact_sha256=wire_sha,
                    metadata=self._observe_metadata(),
                )
                await self._write_downstream_bytes(wire_bytes)
                return
            self._record_event(
                action=msg.method,
                verdict_allow=False,
                severity="BLOCK",
                rule_id="airlock.notification_not_allowed",
                reason=f"Client notification method '{msg.method}' is not allowlisted.",
                artifact_sha256=wire_sha,
            )
            return
        ok, is_aad, reason, findings = await self._scan_outbound_envelope(params=msg.params, request_id=None)
        if is_aad:
            if self._mode == "observe":
                self._record_event(
                    action=msg.method,
                    verdict_allow=False,
                    severity="AAD_FIRE",
                    rule_id="egress.canary_exfiltration",
                    reason=reason,
                    artifact_sha256=wire_sha,
                    redactions=findings,
                    metadata=self._observe_metadata(would_terminate=True),
                )
                await self._write_downstream_bytes(wire_bytes)
                return
            await self._trigger_aad(
                action=msg.method,
                rule_id="egress.canary_exfiltration",
                reason=reason,
                artifact_sha256=wire_sha,
                redactions=findings,
            )
            return
        if not ok:
            if self._mode == "observe":
                self._record_event(
                    action=msg.method,
                    verdict_allow=False,
                    severity="BLOCK",
                    rule_id="airlock.outbound_notification_blocked",
                    reason=reason,
                    artifact_sha256=wire_sha,
                    redactions=findings,
                    metadata=self._observe_metadata(),
                )
                await self._write_downstream_bytes(wire_bytes)
                return
            self._record_event(
                action=msg.method,
                verdict_allow=False,
                severity="BLOCK",
                rule_id="airlock.outbound_notification_blocked",
                reason=reason,
                artifact_sha256=wire_sha,
                redactions=findings,
            )
            return
        self._record_event(
            action=msg.method,
            verdict_allow=True,
            severity="INFO",
            rule_id="airlock.notification_allowed",
            reason=f"Forwarded allowlisted client notification '{msg.method}'.",
            artifact_sha256=wire_sha,
        )
        await self._write_downstream_bytes(wire_bytes)

    async def _handle_client_request(
        self,
        msg: JsonRpcRequest,
        *,
        wire_bytes: bytes,
        wire_sha: str,
    ) -> None:
        # Bound every request id the same way the engine does for tools/call, so no method lets bulk data leave
        # through the id (the downstream would echo it back, but the request itself is already egress).
        id_problem = rpc_id_problem(msg.id)
        if id_problem is not None:
            self._record_event(
                action=msg.method,
                verdict_allow=False,
                severity="BLOCK",
                rule_id="airlock.invalid_request_id",
                reason=id_problem,
                artifact_sha256=wire_sha,
            )
            await self._emit_client_error(
                rpc_id=None,
                code=JSONRPC_INVALID_REQUEST,
                message=f"Invalid request: {id_problem}",
            )
            return

        if msg.id in self._expired_ids:
            self._record_event(
                action=msg.method,
                verdict_allow=False,
                severity="BLOCK",
                rule_id="airlock.expired_rpc_id_reused",
                reason="Request id belongs to a timed-out request that the server may still answer.",
                artifact_sha256=wire_sha,
                request_id=msg.id,
            )
            await self._emit_client_error(
                rpc_id=msg.id,
                code=JSONRPC_POLICY_VIOLATION,
                message="Policy violation: this id was used by a request that timed out; use a new id.",
            )
            return

        if msg.id in self._in_flight:
            self._record_event(
                action=msg.method,
                verdict_allow=False,
                severity="BLOCK",
                rule_id="airlock.duplicate_rpc_id",
                reason="Duplicate active JSON-RPC request id rejected.",
                artifact_sha256=wire_sha,
                request_id=msg.id,
            )
            await self._emit_client_error(
                rpc_id=msg.id,
                code=JSONRPC_POLICY_VIOLATION,
                message="Policy violation: duplicate in-flight JSON-RPC id.",
            )
            return

        if msg.method == "tools/call":
            raw_name = msg.params.get("name")
            tool_name = raw_name if isinstance(raw_name, str) else None
            verdict = evaluate_tool_call(msg, self._policy)
            should_forward = await self._handle_verdicted_client_call(
                msg,
                action="tools/call",
                verdict=verdict,
                tool_name=tool_name,
                require_verified_tool=True,
            )
            if not should_forward:
                return
            self._add_in_flight(
                InFlightRequest(
                    rpc_id=msg.id,
                    method="tools/call",
                    started_monotonic=time.monotonic(),
                    tool_name=tool_name,
                )
            )
            if not await self._write_downstream_bytes(wire_bytes):
                self._pop_in_flight(msg.id)
                await self._emit_client_error(
                    rpc_id=msg.id,
                    code=JSONRPC_POLICY_VIOLATION,
                    message="Downstream server stdin is closed.",
                )
            return

        if msg.method == "resources/read" and self._policy.allow_resources_read:
            verdict = evaluate_resource_read(msg, self._policy)
            should_forward = await self._handle_verdicted_client_call(
                msg,
                action="resources/read",
                verdict=verdict,
                tool_name=None,
                require_verified_tool=False,
            )
            if not should_forward:
                return
            self._add_in_flight(
                InFlightRequest(
                    rpc_id=msg.id,
                    method="resources/read",
                    started_monotonic=time.monotonic(),
                )
            )
            if not await self._write_downstream_bytes(wire_bytes):
                self._pop_in_flight(msg.id)
                await self._emit_client_error(
                    rpc_id=msg.id,
                    code=JSONRPC_POLICY_VIOLATION,
                    message="Downstream server stdin is closed.",
                )
            return

        if len(wire_bytes) - 1 > self._policy.max_payload_bytes:
            self._record_event(
                action=msg.method,
                verdict_allow=False,
                severity="BLOCK",
                rule_id="airlock.payload_too_large",
                reason=f"Request size {len(wire_bytes) - 1} exceeds limit of {self._policy.max_payload_bytes} bytes.",
                artifact_sha256=wire_sha,
                request_id=msg.id,
            )
            await self._emit_client_error(
                rpc_id=msg.id,
                code=JSONRPC_POLICY_VIOLATION,
                message="Policy violation: request exceeds max_payload_bytes.",
            )
            return

        allowed_methods = (
            _ALLOWED_CLIENT_REQUEST_METHODS | {"resources/list", "resources/read"}
            if self._policy.allow_resources_read
            else _ALLOWED_CLIENT_REQUEST_METHODS
        )
        observed_violation = False
        if msg.method not in allowed_methods:
            if self._mode != "observe":
                self._record_event(
                    action=msg.method,
                    verdict_allow=False,
                    severity="BLOCK",
                    rule_id="airlock.method_not_allowed",
                    reason=f"JSON-RPC method '{msg.method}' is not allowlisted.",
                    artifact_sha256=wire_sha,
                    request_id=msg.id,
                )
                await self._emit_client_error(
                    rpc_id=msg.id,
                    code=JSONRPC_POLICY_VIOLATION,
                    message=f"Policy violation: method '{msg.method}' is not permitted.",
                )
                return
            self._record_event(
                action=msg.method,
                verdict_allow=False,
                severity="BLOCK",
                rule_id="airlock.method_not_allowed",
                reason=f"JSON-RPC method '{msg.method}' is not allowlisted.",
                artifact_sha256=wire_sha,
                request_id=msg.id,
                metadata=self._observe_metadata(),
            )
            observed_violation = True

        scan_params = msg.params
        paginated = False
        if msg.method == "tools/list" and "cursor" in msg.params:
            # A cursor is opaque server data; the client may only echo back one the server issued on a verified
            # page. Anything else would be a free-form channel out of the airlock.
            cursor = msg.params["cursor"]
            if not isinstance(cursor, str) or cursor not in self._issued_cursors:
                if self._mode != "observe":
                    self._record_event(
                        action=msg.method,
                        verdict_allow=False,
                        severity="BLOCK",
                        rule_id="airlock.unknown_cursor",
                        reason="tools/list cursor was not issued by the server on a verified page.",
                        artifact_sha256=wire_sha,
                        request_id=msg.id,
                    )
                    await self._emit_client_error(
                        rpc_id=msg.id,
                        code=JSONRPC_POLICY_VIOLATION,
                        message="Policy violation: unknown tools/list cursor.",
                    )
                    return
                if not observed_violation:
                    self._record_event(
                        action=msg.method,
                        verdict_allow=False,
                        severity="BLOCK",
                        rule_id="airlock.unknown_cursor",
                        reason="tools/list cursor was not issued by the server on a verified page.",
                        artifact_sha256=wire_sha,
                        request_id=msg.id,
                        metadata=self._observe_metadata(),
                    )
                    observed_violation = True
            scan_params = {key: value for key, value in msg.params.items() if key != "cursor"}
            paginated = True

        ok, is_aad, reason, findings = await self._scan_outbound_envelope(params=scan_params, request_id=msg.id)
        if is_aad:
            if self._mode != "observe":
                await self._trigger_aad(
                    action=msg.method,
                    rule_id="egress.canary_exfiltration",
                    reason=reason,
                    artifact_sha256=wire_sha,
                    rpc_id=msg.id,
                    redactions=findings,
                )
                return
            if not observed_violation:
                self._record_event(
                    action=msg.method,
                    verdict_allow=False,
                    severity="AAD_FIRE",
                    rule_id="egress.canary_exfiltration",
                    reason=reason,
                    artifact_sha256=wire_sha,
                    request_id=msg.id,
                    redactions=findings,
                    metadata=self._observe_metadata(would_terminate=True),
                )
                observed_violation = True
        elif not ok:
            if self._mode != "observe":
                self._record_event(
                    action=msg.method,
                    verdict_allow=False,
                    severity="BLOCK",
                    rule_id="airlock.outbound_request_blocked",
                    reason=reason,
                    artifact_sha256=wire_sha,
                    request_id=msg.id,
                    redactions=findings,
                )
                await self._emit_client_error(
                    rpc_id=msg.id,
                    code=JSONRPC_POLICY_VIOLATION,
                    message=f"Policy violation: {reason}",
                )
                return
            if not observed_violation:
                self._record_event(
                    action=msg.method,
                    verdict_allow=False,
                    severity="BLOCK",
                    rule_id="airlock.outbound_request_blocked",
                    reason=reason,
                    artifact_sha256=wire_sha,
                    request_id=msg.id,
                    redactions=findings,
                    metadata=self._observe_metadata(),
                )
                observed_violation = True

        if not observed_violation:
            self._record_event(
                action=msg.method,
                verdict_allow=True,
                severity="INFO",
                rule_id="airlock.request_allowed",
                reason=f"Forwarded allowlisted MCP request '{msg.method}'.",
                artifact_sha256=wire_sha,
                request_id=msg.id,
            )
        self._add_in_flight(
            InFlightRequest(rpc_id=msg.id, method=msg.method, started_monotonic=time.monotonic(), paginated=paginated)
        )
        if not await self._write_downstream_bytes(wire_bytes):
            self._pop_in_flight(msg.id)
            await self._emit_client_error(
                rpc_id=msg.id,
                code=JSONRPC_POLICY_VIOLATION,
                message="Downstream server stdin is closed.",
            )

    async def _handle_malformed_server_frame(
        self,
        *,
        frame_bytes: bytes,
        rule_id: str,
        reason: str,
    ) -> None:
        sha = hashlib.sha256(frame_bytes).hexdigest()
        meta: JsonObject = {"byte_length": len(frame_bytes)}
        self._log_err(f"[airlock server protocol warning] {reason}")
        if self._aad_on_malformed_server_frame:
            await self._trigger_aad(
                action="downstream/stdout",
                rule_id=rule_id,
                reason=reason,
                artifact_sha256=sha,
                metadata=meta,
            )
            return
        self._record_event(
            action="downstream/stdout",
            verdict_allow=False,
            severity="BLOCK",
            rule_id=rule_id,
            reason=reason,
            artifact_sha256=sha,
            metadata=meta,
        )

    async def _handle_server_frame(self, frame: bytes) -> None:
        if not frame.strip():
            return
        frame_sha = hashlib.sha256(frame).hexdigest()
        try:
            msg = parse_jsonrpc_bytes(frame)
        except (UnicodeDecodeError, ValueError, ValidationError):
            await self._handle_malformed_server_frame(
                frame_bytes=frame,
                rule_id="airlock.server_malformed_frame",
                reason="Downstream server emitted non-JSON or invalid JSON-RPC 2.0 line on stdout.",
            )
            return

        if isinstance(msg, JsonRpcRequest):
            self._record_event(
                action=f"downstream/{msg.method}",
                verdict_allow=False,
                severity="BLOCK",
                rule_id="airlock.server_request_denied",
                reason="Unsolicited downstream server-to-client JSON-RPC request dropped.",
                artifact_sha256=frame_sha,
                request_id=msg.id,
            )
            return

        if isinstance(msg, JsonRpcNotification):
            self._record_event(
                action=f"downstream/{msg.method}",
                verdict_allow=False,
                severity="WARN",
                rule_id="airlock.server_notification_dropped",
                reason="Downstream server notification suppressed.",
                artifact_sha256=frame_sha,
            )
            return

        if isinstance(msg, JsonRpcErrorResponse) and msg.id is None:
            # A standard way for a server to report an error it cannot tie to a request; not an attack signal.
            self._record_event(
                action="downstream/response",
                verdict_allow=False,
                severity="WARN",
                rule_id="airlock.server_null_id_error_dropped",
                reason="Downstream error response with id null dropped (cannot be correlated to a request).",
                artifact_sha256=frame_sha,
                metadata={"error_code": msg.error.code},
            )
            return

        if msg.id is not None and msg.id in self._expired_ids:
            # The answer to a request that already timed out. Never forwarded (the client got a timeout error),
            # but still scanned so a planted canary in it fires AAD.
            del self._expired_ids[msg.id]
            late_verdict = evaluate_tool_response(msg, self._policy)
            if late_verdict.severity == "AAD_FIRE":
                await self._trigger_aad(
                    action="downstream/late_response",
                    rule_id=late_verdict.rule_id,
                    reason=late_verdict.reason,
                    artifact_sha256=late_verdict.artifact_sha256,
                    redactions=late_verdict.redactions,
                )
                return
            self._record_event(
                action="downstream/late_response",
                verdict_allow=False,
                severity="WARN",
                rule_id="airlock.late_response_dropped",
                reason="Downstream answered a request after it timed out; the late response was dropped.",
                artifact_sha256=frame_sha,
                request_id=msg.id,
            )
            return

        if msg.id is None or msg.id not in self._in_flight:
            await self._trigger_aad(
                action="downstream/response",
                rule_id="airlock.unsolicited_response_id",
                reason="Downstream server emitted response for inactive or spoofed JSON-RPC id.",
                artifact_sha256=frame_sha,
                rpc_id=None,
                metadata={"spoofed_id_sha256": hashlib.sha256(str(msg.id).encode("utf-8")).hexdigest()},
            )
            return

        in_flight = self._pop_in_flight(msg.id)
        if in_flight is None:
            return

        resp_verdict = evaluate_tool_response(msg, self._policy, resource_read=in_flight.method == "resources/read")
        # Enforce size/ID/canonicalization safety invariants unconditionally, even in observe mode.
        if resp_verdict.rule_id in _HARD_ENFORCED_RESPONSE_RULES:
            self._record_event(
                action=in_flight.method,
                verdict_allow=False,
                severity="BLOCK",
                rule_id=resp_verdict.rule_id,
                reason=resp_verdict.reason,
                artifact_sha256=resp_verdict.artifact_sha256,
                tool_name=in_flight.tool_name,
                request_id=msg.id,
                redactions=resp_verdict.redactions,
            )
            await self._emit_client_error(
                rpc_id=msg.id,
                code=JSONRPC_POLICY_VIOLATION,
                message=f"Policy violation ({resp_verdict.rule_id}): {resp_verdict.reason}",
                data={"rule_id": resp_verdict.rule_id},
            )
            return

        observed_violation = False
        if resp_verdict.severity == "AAD_FIRE":
            if await self._handle_server_violation(
                action=in_flight.method,
                severity="AAD_FIRE",
                rule_id=resp_verdict.rule_id,
                reason=resp_verdict.reason,
                artifact_sha256=resp_verdict.artifact_sha256,
                rpc_id=msg.id,
                tool_name=in_flight.tool_name,
                redactions=resp_verdict.redactions,
                redacted_payload=resp_verdict.redacted_payload,
                already_observed=observed_violation,
            ):
                return
            observed_violation = True

        forward_msg: JsonRpcSuccessResponse | JsonRpcErrorResponse = msg
        verified_names: set[str] | None = None
        issued_cursor: str | None = None

        if (
            in_flight.method == "initialize"
            and isinstance(msg, JsonRpcSuccessResponse)
            and isinstance(msg.result, dict)
            and "instructions" in msg.result
        ):
            # `instructions` is free text the model reads, outside the AgBOM tool pins: forward it only when pinned.
            instructions = msg.result["instructions"]
            pin = self._policy.instructions_sha256
            pin_matches = isinstance(instructions, str) and compute_instructions_pin(instructions) == pin
            if pin is not None and not pin_matches:
                if await self._handle_server_violation(
                    action="initialize",
                    severity="AAD_FIRE",
                    rule_id="airlock.instructions_pin_mismatch",
                    reason="Server initialize instructions do not match the pinned instructions_sha256 (rug pull).",
                    artifact_sha256=resp_verdict.artifact_sha256,
                    rpc_id=msg.id,
                    redacted_payload=resp_verdict.redacted_payload,
                    already_observed=observed_violation,
                ):
                    return
                observed_violation = True
            elif pin is None and self._mode == "enforce":
                stripped: JsonObject = {k: v for k, v in msg.result.items() if k != "instructions"}
                forward_msg = JsonRpcSuccessResponse(jsonrpc="2.0", id=msg.id, result=stripped)
                resp_verdict = evaluate_tool_response(forward_msg, self._policy)
                self._record_event(
                    action="initialize",
                    verdict_allow=True,
                    severity="WARN",
                    rule_id="airlock.instructions_stripped",
                    reason="Server initialize instructions are not pinned (instructions_sha256) and were removed.",
                    artifact_sha256=resp_verdict.artifact_sha256,
                    request_id=msg.id,
                )

        if in_flight.method == "tools/list" and isinstance(msg, JsonRpcSuccessResponse):
            parsed_tools: list[ToolDefinition] | None = None
            try:
                parsed_tools = _parse_tools_list_result(msg.result)
            except (ValueError, ValidationError) as exc:
                if await self._handle_server_violation(
                    action="tools/list",
                    severity="AAD_FIRE",
                    rule_id="airlock.invalid_tools_list_manifest",
                    reason=f"Invalid tools/list manifest from downstream server: {exc}",
                    artifact_sha256=resp_verdict.artifact_sha256,
                    rpc_id=msg.id,
                    redacted_payload=resp_verdict.redacted_payload,
                    already_observed=observed_violation,
                ):
                    return
                observed_violation = True

            if parsed_tools is not None:
                pin_verdict = verify_tools_list(parsed_tools, self._policy)
                if pin_verdict.severity == "AAD_FIRE" or not pin_verdict.verdict_allow:
                    sev: Literal["BLOCK", "AAD_FIRE"] = "AAD_FIRE" if pin_verdict.severity == "AAD_FIRE" else "BLOCK"
                    if await self._handle_server_violation(
                        action="tools/list",
                        severity=sev,
                        rule_id=pin_verdict.rule_id,
                        reason=pin_verdict.reason,
                        artifact_sha256=pin_verdict.artifact_sha256,
                        rpc_id=msg.id,
                        redacted_payload=pin_verdict.redacted_payload,
                        already_observed=observed_violation,
                    ):
                        return
                    observed_violation = True

                # Forward verified (or observed) tools plus nextCursor; extra unpinned keys are dropped in enforce.
                raw_result = cast(JsonObject, msg.result)  # `_parse_tools_list_result` accepted it as an object
                tools_wire: list[JsonValue] = [tool.wire_dict() for tool in parsed_tools]
                rebuilt: JsonObject = {"tools": tools_wire}
                next_cursor = raw_result.get("nextCursor")
                if next_cursor is not None:
                    cursor_ok, cursor_aad, cursor_reason, cursor_findings = self._check_next_cursor(next_cursor)
                    if cursor_aad or not cursor_ok:
                        cursor_sev: Literal["BLOCK", "AAD_FIRE"] = "AAD_FIRE" if cursor_aad else "BLOCK"
                        cursor_rule = "egress.response_canary_detected" if cursor_aad else "airlock.invalid_next_cursor"
                        if await self._handle_server_violation(
                            action="tools/list",
                            severity=cursor_sev,
                            rule_id=cursor_rule,
                            reason=cursor_reason,
                            artifact_sha256=resp_verdict.artifact_sha256,
                            rpc_id=msg.id,
                            redactions=cursor_findings,
                            redacted_payload=resp_verdict.redacted_payload,
                            already_observed=observed_violation,
                        ):
                            return
                        observed_violation = True
                    if isinstance(next_cursor, str):
                        rebuilt["nextCursor"] = next_cursor
                        issued_cursor = next_cursor
                dropped_keys = [key for key in raw_result if key not in ("tools", "nextCursor")]
                if dropped_keys:
                    self._record_event(
                        action="tools/list",
                        verdict_allow=True,
                        severity="WARN",
                        rule_id="airlock.tools_list_extra_keys_stripped",
                        reason="Unpinned keys in the tools/list result were removed before forwarding.",
                        artifact_sha256=resp_verdict.artifact_sha256,
                        request_id=msg.id,
                        metadata={"dropped_key_count": len(dropped_keys)},
                    )
                forward_msg = JsonRpcSuccessResponse(jsonrpc="2.0", id=msg.id, result=rebuilt)
                # Re-scan what will actually be forwarded. The cursor was checked above without the entropy detector
                # (it is a legitimately random token), so it is left out of this scan.
                resp_verdict = evaluate_tool_response(
                    JsonRpcSuccessResponse(jsonrpc="2.0", id=msg.id, result={"tools": tools_wire}), self._policy
                )
                verified_names = {tool.name for tool in parsed_tools}

        if resp_verdict.rule_id in _HARD_ENFORCED_RESPONSE_RULES:
            self._record_event(
                action=in_flight.method,
                verdict_allow=False,
                severity="BLOCK",
                rule_id=resp_verdict.rule_id,
                reason=resp_verdict.reason,
                artifact_sha256=resp_verdict.artifact_sha256,
                tool_name=in_flight.tool_name,
                request_id=msg.id,
                redactions=resp_verdict.redactions,
            )
            await self._emit_client_error(
                rpc_id=msg.id,
                code=JSONRPC_POLICY_VIOLATION,
                message=f"Policy violation ({resp_verdict.rule_id}): {resp_verdict.reason}",
                data={"rule_id": resp_verdict.rule_id},
            )
            return

        if resp_verdict.severity == "AAD_FIRE" or not resp_verdict.verdict_allow:
            final_sev: Literal["BLOCK", "AAD_FIRE"] = "AAD_FIRE" if resp_verdict.severity == "AAD_FIRE" else "BLOCK"
            if await self._handle_server_violation(
                action=in_flight.method,
                severity=final_sev,
                rule_id=resp_verdict.rule_id,
                reason=resp_verdict.reason,
                artifact_sha256=resp_verdict.artifact_sha256,
                rpc_id=msg.id,
                tool_name=in_flight.tool_name,
                redactions=resp_verdict.redactions,
                redacted_payload=resp_verdict.redacted_payload,
                already_observed=observed_violation,
            ):
                return
            observed_violation = True

        wire_resp_body = exact_json_bytes(cast(JsonObject, forward_msg.model_dump(mode="json")))
        if len(wire_resp_body) > self._policy.max_payload_bytes:
            oversized_sha = hashlib.sha256(wire_resp_body).hexdigest()
            self._record_event(
                action=in_flight.method,
                verdict_allow=False,
                severity="BLOCK",
                rule_id="airlock.response_too_large",
                reason=(
                    f"Response size {len(wire_resp_body)} exceeds limit of {self._policy.max_payload_bytes} bytes."
                ),
                artifact_sha256=oversized_sha,
                tool_name=in_flight.tool_name,
                request_id=msg.id,
            )
            await self._emit_client_error(
                rpc_id=msg.id,
                code=JSONRPC_POLICY_VIOLATION,
                message=(
                    f"Policy violation (airlock.response_too_large): "
                    f"Response size {len(wire_resp_body)} exceeds limit of "
                    f"{self._policy.max_payload_bytes} bytes."
                ),
                data={"rule_id": "airlock.response_too_large"},
            )
            return

        if not observed_violation:
            receipt_sha256 = hashlib.sha256(wire_resp_body).hexdigest()
            self._record_event(
                action=in_flight.method,
                verdict_allow=True,
                severity="INFO",
                rule_id="airlock.response_allowed",
                reason=f"Verified and forwarded downstream response for '{in_flight.method}'.",
                artifact_sha256=receipt_sha256,
                tool_name=in_flight.tool_name,
                request_id=msg.id,
                metadata=self._with_redacted_payload(None, resp_verdict.redacted_payload),
            )
        if verified_names is not None:
            # A fresh listing replaces the verified set (a tool the server stopped listing can no longer be
            # called) and resets prior-cycle cursors; a later page of a paginated listing adds to it.
            base = self._verified_tool_names if (in_flight.paginated and self._verified_tool_names) else set()
            self._verified_tool_names = base | verified_names
            if not in_flight.paginated:
                self._issued_cursors.clear()
        if issued_cursor is not None:
            _remember(self._issued_cursors, issued_cursor, MAX_ISSUED_CURSORS)
        await self._write_client_bytes(wire_resp_body + b"\n")

    async def _fail_remaining_in_flight_on_eof(self) -> None:
        if not self._in_flight:
            return
        sha = hashlib.sha256(b"").hexdigest()
        for rpc_id, req in list(self._in_flight.items()):
            self._pop_in_flight(rpc_id)
            self._record_event(
                action=req.method,
                verdict_allow=False,
                severity="BLOCK",
                rule_id="airlock.downstream_eof",
                reason="Downstream server stdout closed before response arrived.",
                artifact_sha256=sha,
                tool_name=req.tool_name,
                request_id=rpc_id,
            )
            await self._emit_client_error(
                rpc_id=rpc_id,
                code=JSONRPC_POLICY_VIOLATION,
                message="Downstream server terminated before completing request.",
            )

    async def _wait_idle_or_stopped(self) -> None:
        while not self._stop_event.is_set() and not self._idle_event.is_set():
            idle_task = asyncio.create_task(self._idle_event.wait())
            stop_task = asyncio.create_task(self._stop_event.wait())
            done, pending = await asyncio.wait({idle_task, stop_task}, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, *done, return_exceptions=True)

    async def _pump_client(self) -> None:
        while not self._stop_event.is_set():
            frame, oversized = await self._client_frames.read_frame()
            if self._stop_event.is_set():
                return
            if oversized:
                await self._handle_oversized_client_frame()
                continue
            if frame is None:
                break
            await self._handle_client_frame(frame)
        if not self._stop_event.is_set():
            await self._wait_idle_or_stopped()
            if not self._stop_event.is_set():
                self._close_downstream_stdin()
                self._request_stop()

    async def _pump_server(self) -> None:
        proc = self._proc
        if proc is None or proc.stdout is None:
            self._stop_event.set()
            return
        server_frames = BoundedLineReader(proc.stdout, max_bytes=self._policy.max_payload_bytes)
        while not self._stop_event.is_set():
            frame, oversized = await server_frames.read_frame()
            if self._stop_event.is_set():
                return
            if oversized:
                await self._handle_malformed_server_frame(
                    frame_bytes=b"",
                    rule_id="airlock.server_frame_too_large",
                    reason="Downstream server frame exceeded max_payload_bytes and was discarded.",
                )
                continue
            if frame is None:
                break
            await self._handle_server_frame(frame)
        if not self._stop_event.is_set() and not (self._aad_fired or self._faulted):
            await self._fail_remaining_in_flight_on_eof()
            self._request_stop()

    async def _pump_stderr(self) -> None:
        proc = self._proc
        if proc is None or proc.stderr is None:
            return
        err_frames = BoundedLineReader(proc.stderr, max_bytes=MAX_STDERR_LINE_BYTES)
        while True:
            frame, oversized = await err_frames.read_frame()
            if oversized:
                self._log_err("[downstream stderr] [truncated oversized stderr line]")
                continue
            if frame is None:
                return
            text = frame.decode("utf-8", errors="replace")
            self._log_err(f"[downstream stderr] {text}")

    async def _timeout_watchdog(self) -> None:
        interval = min(0.05, self._request_timeout_seconds / 4.0)
        sha = hashlib.sha256(b"").hexdigest()
        while not self._stop_event.is_set():
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=interval)
                return
            except TimeoutError:
                pass
            now = time.monotonic()
            expired = [
                req
                for req in list(self._in_flight.values())
                if (now - req.started_monotonic) >= self._request_timeout_seconds
            ]
            for req in expired:
                if self._pop_in_flight(req.rpc_id) is None:
                    continue
                _remember(self._expired_ids, req.rpc_id, MAX_EXPIRED_ID_TOMBSTONES)
                self._record_event(
                    action=req.method,
                    verdict_allow=False,
                    severity="BLOCK",
                    rule_id="airlock.request_timeout",
                    reason=f"Downstream request '{req.method}' exceeded timeout of {self._request_timeout_seconds}s.",
                    artifact_sha256=sha,
                    tool_name=req.tool_name,
                    request_id=req.rpc_id,
                )
                await self._emit_client_error(
                    rpc_id=req.rpc_id,
                    code=JSONRPC_REQUEST_TIMEOUT,
                    message=f"Downstream request '{req.method}' timed out.",
                )

    async def run(self) -> int:
        """Spawn the isolated downstream MCP server, proxy frames until EOF or AAD kill, and return exit code."""
        # Every session's first record states how it was run, so a quiet observe-mode session cannot pass for an
        # enforced one. Written before the downstream exists: if the ledger cannot record this, nothing is started.
        self._record_event(
            action="airlock/session_start",
            verdict_allow=True,
            severity="WARN" if self._mode == "observe" else "INFO",
            rule_id=SESSION_STARTED_RULE_ID,
            reason=(
                "Session started in OBSERVE mode: policy violations are recorded but forwarded, and AAD does not "
                "terminate the downstream."
                if self._mode == "observe"
                else "Session started in enforce mode."
            ),
            artifact_sha256=_EMPTY_SHA256,
            metadata={
                "enforcement_mode": self._mode,
                "policy_id": self._policy.policy_id,
                "record_redacted_payloads": self._record_redacted_payloads,
                "opaque_policy_errors": self._opaque_policy_errors,
            },
        )
        if self._mode == "observe":
            self._log_err(
                "[airlock WARNING] OBSERVE MODE: policy violations are forwarded to the downstream and AAD does not "
                "kill it. Use only in an isolated red-team sandbox with throwaway canaries."
            )
        child_env = build_minimal_subprocess_env(allowed_keys=self._allowed_env_keys, extra_env=self._extra_env)
        cwd_str = str(self._cwd) if self._cwd is not None else None
        self._proc, self._job = await spawn_contained_subprocess(self._command, env=child_env, cwd=cwd_str)

        tasks = (
            asyncio.create_task(self._supervised("client-pump", self._pump_client()), name="airlock-client-pump"),
            asyncio.create_task(self._supervised("server-pump", self._pump_server()), name="airlock-server-pump"),
            asyncio.create_task(self._supervised("stderr-pump", self._pump_stderr()), name="airlock-stderr-pump"),
            asyncio.create_task(
                self._supervised("timeout-watchdog", self._timeout_watchdog()), name="airlock-timeout-watchdog"
            ),
        )
        try:
            await self._stop_event.wait()
            if not self._aad_fired:
                self._close_downstream_stdin()
                try:
                    await asyncio.wait_for(self._proc.wait(), timeout=2.0)
                except TimeoutError:
                    await _hard_kill_subprocess(self._proc, job=self._job)
            if self._proc.returncode is not None and not tasks[2].done():
                try:
                    await asyncio.wait_for(asyncio.shield(tasks[2]), timeout=0.2)
                except (TimeoutError, asyncio.CancelledError):
                    pass
        finally:
            self._stop_event.set()
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if self._proc.returncode is None:
                await _hard_kill_subprocess(self._proc, job=self._job)
            if self._job is not None:
                self._job.close()  # kill-on-close: also ends anything the server left running in its job

        return self._exit_code

    def request_shutdown(self, reason: str = "shutdown requested") -> None:
        """Begin a normal shutdown (used by the CLI's SIGTERM/SIGHUP/SIGINT handlers); the downstream is stopped."""
        if not self._stop_event.is_set():
            self._log_err(f"[airlock] {reason}; shutting down")
            self._request_stop()

    def _request_stop(self) -> None:
        """
        Ask `run()` to shut down, unless the AAD kill switch or a fault shutdown is in progress. Those sequences set
        the stop event themselves once they finish: `run()` cancels the remaining tasks on stop, so stopping early
        (e.g. because killing the downstream made the server pump hit EOF) could cancel the task that is still
        sending the client its terminal `-32099` / `-32603` errors.
        """
        if self._aad_fired or self._faulted:
            return
        self._stop_event.set()


def _settle_write(fut: asyncio.Future[None], error: BaseException | None) -> None:
    if fut.done():  # already cancelled by the proxy's client write timeout
        return
    if error is None:
        fut.set_result(None)
    else:
        fut.set_exception(error)


class _BinaryStdoutWriter:
    """
    Write framed JSON-RPC bytes to stdout from a dedicated daemon thread.

    A client that stops reading blocks only this thread, never the event loop, so timeouts and the AAD kill switch keep
    running; `drain()` completes once the bytes are written and the proxy bounds it with its client write timeout.
    Writes go straight to the file descriptor (`os.write`), so a thread stuck on a full pipe never holds the lock of
    `sys.stdout`'s buffer at interpreter exit.
    """

    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream
        try:
            self._fd: int | None = stream.fileno()
        except (AttributeError, OSError, ValueError):
            self._fd = None
        self._pending = bytearray()
        self._queue: queue.SimpleQueue[tuple[bytes, asyncio.AbstractEventLoop, asyncio.Future[None]]] = (
            queue.SimpleQueue()
        )
        self._thread = threading.Thread(target=self._run, name="airlock-stdout-writer", daemon=True)
        self._thread.start()

    def _write_all(self, data: bytes) -> None:
        if self._fd is None:
            self._stream.write(data)
            self._stream.flush()
            return
        view = memoryview(data)
        while view:
            written = os.write(self._fd, view)
            view = view[written:]

    def _run(self) -> None:
        while True:
            data, loop, fut = self._queue.get()
            error: BaseException | None = None
            try:
                self._write_all(data)
            except (OSError, ValueError) as exc:
                error = exc
            try:
                loop.call_soon_threadsafe(_settle_write, fut, error)
            except RuntimeError:  # event loop already closed
                return

    def write(self, data: bytes) -> None:
        self._pending.extend(data)

    async def drain(self) -> None:
        if not self._pending:
            return
        data = bytes(self._pending)
        self._pending.clear()
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[None] = loop.create_future()
        self._queue.put((data, loop, fut))
        await fut


class BoundedStdinReader:
    """
    Async reader bridging blocking binary stdin into an event loop under a fixed read-ahead budget.

    Accounts for all unread bytes across queued chunks (including chunks whose loop wakeup is still pending),
    blocks the producer thread when the budget is full, returns capacity as the consumer takes bytes, and
    wakes any waiting producer immediately on `close()`.
    """

    def __init__(
        self,
        raw_stdin: BinaryIO,
        *,
        loop: asyncio.AbstractEventLoop,
        max_buffered_bytes: int = DEFAULT_CLI_STDIN_READAHEAD_BYTES,
        read_chunk_bytes: int = DEFAULT_CLI_STDIN_READ_CHUNK_BYTES,
    ) -> None:
        if max_buffered_bytes <= 0:
            raise ValueError("max_buffered_bytes must be positive.")
        if read_chunk_bytes <= 0:
            raise ValueError("read_chunk_bytes must be positive.")
        self._raw_stdin = raw_stdin
        self._loop = loop
        self._max_buffered_bytes = max_buffered_bytes
        self._read_chunk_bytes = read_chunk_bytes
        self._cond = threading.Condition()
        self._chunks: deque[bytes] = deque()
        self._buffered_bytes = 0
        self._eof = False
        self._closed = False
        self._data_event = asyncio.Event()
        self._waiting_for_capacity = threading.Event()
        self._thread = threading.Thread(target=self._pump, name="airlock-stdin-pump", daemon=True)
        self._thread.start()

    @property
    def max_buffered_bytes(self) -> int:
        return self._max_buffered_bytes

    @property
    def buffered_bytes(self) -> int:
        with self._cond:
            return self._buffered_bytes

    @property
    def waiting_for_capacity(self) -> threading.Event:
        return self._waiting_for_capacity

    @property
    def thread(self) -> threading.Thread:
        return self._thread

    def _notify_loop(self) -> None:
        try:
            self._loop.call_soon_threadsafe(self._data_event.set)
        except RuntimeError:
            pass

    def _pump(self) -> None:
        # Use raw `os.read(fd, ...)` on real OS descriptors so exiting on AAD while a daemon thread is blocked
        # waiting on an open stdin pipe never races CPython's `BufferedReader` finalizer on Windows.
        fd: int | None = None
        try:
            candidate = self._raw_stdin.fileno()
            if isinstance(candidate, int) and candidate >= 0:
                fd = candidate
        except (AttributeError, OSError, ValueError):
            fd = None

        read1_fn = getattr(self._raw_stdin, "read1", None)

        def _read_chunk(size: int) -> bytes:
            if fd is not None:
                return os.read(fd, size)
            if callable(read1_fn):
                chunk_obj = read1_fn(size)
                return chunk_obj if isinstance(chunk_obj, bytes) else b""
            return self._raw_stdin.read(size)

        try:
            while True:
                with self._cond:
                    while not self._closed and self._buffered_bytes >= self._max_buffered_bytes:
                        self._waiting_for_capacity.set()
                        self._cond.wait()
                    self._waiting_for_capacity.clear()
                    if self._closed:
                        return
                    allowance = min(self._read_chunk_bytes, self._max_buffered_bytes - self._buffered_bytes)

                chunk = _read_chunk(allowance)
                if not chunk:
                    with self._cond:
                        self._eof = True
                    self._notify_loop()
                    return

                with self._cond:
                    if self._closed:
                        return
                    self._chunks.append(chunk)
                    self._buffered_bytes += len(chunk)
                self._notify_loop()
        except (OSError, RuntimeError, ValueError):
            with self._cond:
                self._waiting_for_capacity.clear()
                self._eof = True
            self._notify_loop()

    async def read(self, n: int = -1) -> bytes:
        """Consume up to `n` unread bytes (or the next chunk if `n < 0`), returning read-ahead capacity."""
        if n == 0:
            return b""
        while True:
            with self._cond:
                if self._chunks:
                    if n > 0:
                        head = self._chunks[0]
                        if len(head) <= n:
                            data = self._chunks.popleft()
                        else:
                            data = head[:n]
                            self._chunks[0] = head[n:]
                    else:
                        data = self._chunks.popleft()
                    self._buffered_bytes -= len(data)
                    self._cond.notify_all()
                    return data
                if self._eof or self._closed:
                    return b""
                self._data_event.clear()
            await self._data_event.wait()

    def close(self) -> None:
        """Mark closed, wake any capacity waiter on the producer thread, and unblock waiting consumers."""
        with self._cond:
            self._closed = True
            self._eof = True
            self._waiting_for_capacity.clear()
            self._cond.notify_all()
        self._notify_loop()


def parse_allow_env_keys(raw_value: str | None) -> tuple[str, ...] | None:
    """Merge comma-separated user `--allow-env` keys onto OS execution defaults cleanly."""
    if raw_value is None:
        return None
    defaults = _WIN32_DEFAULT_ENV_KEYS if sys.platform == "win32" else _POSIX_DEFAULT_ENV_KEYS
    extras = [item.strip() for item in raw_value.split(",") if item.strip()]
    return tuple(dict.fromkeys([*defaults, *extras]))


async def _run_cli_async(
    *,
    command: Sequence[str],
    policy: AirlockPolicy,
    ledger: AuditLedger,
    request_timeout_seconds: float,
    allowed_env_keys: Sequence[str] | None,
    aad_on_malformed_server_frame: bool,
    session_id: str | None,
    mode: EnforcementMode,
    record_redacted_payloads: bool,
    opaque_policy_errors: bool,
) -> int:
    loop = asyncio.get_running_loop()
    client_reader = BoundedStdinReader(sys.stdin.buffer, loop=loop)
    client_writer = _BinaryStdoutWriter(sys.stdout.buffer)
    proxy = AirlockProxy(
        command=command,
        policy=policy,
        ledger=ledger,
        client_reader=client_reader,
        client_writer=client_writer,
        request_timeout_seconds=request_timeout_seconds,
        allowed_env_keys=allowed_env_keys,
        err_stream=sys.stderr,
        aad_on_malformed_server_frame=aad_on_malformed_server_frame,
        session_id=session_id,
        mode=mode,
        record_redacted_payloads=record_redacted_payloads,
        opaque_policy_errors=opaque_policy_errors,
    )
    if sys.platform != "win32":
        # A client usually stops a server with SIGTERM (or SIGHUP/SIGINT). Run the normal shutdown so the downstream
        # is stopped too; the Linux parent-death signal covers SIGKILL, and on Windows the Job Object does.
        for sig_name in ("SIGTERM", "SIGHUP", "SIGINT"):
            sig = getattr(signal, sig_name, None)
            if isinstance(sig, signal.Signals):
                try:
                    loop.add_signal_handler(sig, proxy.request_shutdown, f"received {sig_name}")
                except (NotImplementedError, RuntimeError, ValueError):
                    pass
    try:
        return await proxy.run()
    finally:
        client_reader.close()


def _build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mellyn-airlock",
        description="Fail-closed async MCP stdio security proxy with AgBOM verification and AAD kill switch.",
    )
    parser.add_argument(
        "--policy",
        required=True,
        type=Path,
        help="Path to TOML AirlockPolicy file.",
    )
    parser.add_argument(
        "--audit-log",
        required=True,
        type=Path,
        help="Path to append-only hash-chained audit.jsonl ledger.",
    )
    parser.add_argument(
        "--allow-env",
        default=None,
        help="Comma-separated environment variable names additionally permitted inside the downstream subprocess.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_REQUEST_TIMEOUT_SECONDS,
        help=f"Per-request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT_SECONDS}).",
    )
    parser.add_argument(
        "--aad-on-malformed-server-frame",
        action="store_true",
        help="Trigger AAD containment kill immediately if the downstream server emits non-JSON stdout.",
    )
    parser.add_argument(
        "--session-id",
        default=None,
        help="Optional session identifier attached to every AuditLedger ZoneEvent.",
    )
    parser.add_argument(
        "--mode",
        choices=("enforce", "observe"),
        default="enforce",
        help="Airlock mode: 'enforce' (default fail-closed) or 'observe' (red-team telemetry pass-through).",
    )
    parser.add_argument(
        "--record-redacted-payloads",
        action="store_true",
        help=(
            "Record request/response payloads (up to 16 KiB each, secrets and canaries redacted) in AuditLedger "
            "metadata, for ALLOWED traffic too and in both modes. File contents and personal data in tool results "
            "will be stored in the audit log."
        ),
    )
    parser.add_argument(
        "--opaque-policy-errors",
        action="store_true",
        help="Suppress rule_id and detailed policy reasons on -32000 client error frames in enforce mode.",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Downstream MCP server command to spawn (prefix with '--').",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `mellyn-airlock`."""
    parser = _build_cli_parser()
    args = parser.parse_args(argv)

    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        sys.stderr.write("mellyn-airlock: missing downstream MCP server command after '--'.\n")
        return 2
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        sys.stderr.write("mellyn-airlock: --timeout must be a finite positive number of seconds.\n")
        return 2

    try:
        policy_text = args.policy.read_text(encoding="utf-8")
        policy = parse_airlock_policy_toml(policy_text)
    except (OSError, UnicodeDecodeError, ValueError, ValidationError) as exc:
        sys.stderr.write(f"mellyn-airlock: failed to load TOML policy '{args.policy}': {exc}\n")
        return 2
    if args.mode == "observe" and not policy.allow_observe_mode:
        sys.stderr.write(
            "mellyn-airlock: --mode observe requires `allow_observe_mode = true` in the policy "
            f"'{args.policy}'; refusing to run with enforcement off.\n"
        )
        return 2

    try:
        ledger = AuditLedger(args.audit_log, canary_tokens=tuple(policy.canary_tokens))
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"mellyn-airlock: failed to open audit ledger '{args.audit_log}': {exc}\n")
        return 2

    try:
        allowed_env = parse_allow_env_keys(args.allow_env)
        return asyncio.run(
            _run_cli_async(
                command=command,
                policy=policy,
                ledger=ledger,
                request_timeout_seconds=args.timeout,
                allowed_env_keys=allowed_env,
                aad_on_malformed_server_frame=bool(args.aad_on_malformed_server_frame),
                session_id=args.session_id,
                mode=cast(EnforcementMode, args.mode),
                record_redacted_payloads=bool(args.record_redacted_payloads),
                opaque_policy_errors=bool(args.opaque_policy_errors),
            )
        )
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # fail closed; never write tracebacks to stdout
        sys.stderr.write(f"mellyn-airlock: fatal error ({type(exc).__name__}): {exc}\n")
        return INTERNAL_FAULT_EXIT_CODE


__all__ = [
    "AAD_EXIT_CODE",
    "DEFAULT_CLI_STDIN_READ_CHUNK_BYTES",
    "DEFAULT_CLI_STDIN_READAHEAD_BYTES",
    "DEFAULT_REQUEST_TIMEOUT_SECONDS",
    "INTERNAL_FAULT_EXIT_CODE",
    "JSONRPC_AAD_CONTAINMENT_SEVERED",
    "JSONRPC_INTERNAL_ERROR",
    "JSONRPC_INVALID_REQUEST",
    "JSONRPC_PARSE_ERROR",
    "JSONRPC_POLICY_VIOLATION",
    "JSONRPC_REQUEST_TIMEOUT",
    "MAX_EXPIRED_ID_TOMBSTONES",
    "MAX_ISSUED_CURSORS",
    "MAX_RECORDED_REDACTED_PAYLOAD_BYTES",
    "MAX_STDERR_LINE_BYTES",
    "AirlockProxy",
    "AsyncByteReader",
    "BoundedLineReader",
    "BoundedStdinReader",
    "ClientWriter",
    "EnforcementMode",
    "InFlightRequest",
    "RpcId",
    "build_minimal_subprocess_env",
    "main",
    "parse_allow_env_keys",
]


if __name__ == "__main__":
    raise SystemExit(main())
