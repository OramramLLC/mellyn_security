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

import asyncio
import hashlib
import os
import re
import secrets
import signal
import sys
import time
from collections import OrderedDict
from collections.abc import Awaitable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, TextIO, cast

from pydantic import ValidationError

from mcp_airlock.airlock.engine import (
    MAX_OPAQUE_TOKEN_CHARS,
    compute_instructions_pin,
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
    parse_jsonrpc_bytes,
)
from mcp_airlock.core.audit import AuditLedger, redact_core_secrets
from mcp_airlock.core.normalize import JsonObject, JsonValue, exact_json_bytes, has_invisible_unicode, strip_invisible
from mcp_airlock.core.schemas import RedactionRecord, Severity, ZoneEvent
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
MAX_STDERR_LINE_BYTES = 4096
# Ids of requests that timed out are remembered (bounded) so a late answer is dropped instead of firing AAD as a
# "spoofed" id, and so the client cannot reuse such an id and receive the old request's late answer.
MAX_EXPIRED_ID_TOMBSTONES = 4096
# `nextCursor` values the server returned on verified `tools/list` pages; only these may be sent back as `cursor`.
MAX_ISSUED_CURSORS = 256
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

_ALLOWED_CLIENT_REQUEST_METHODS: frozenset[str] = frozenset({"initialize", "ping", "tools/list"})
_ALLOWED_CLIENT_NOTIFICATIONS: frozenset[str] = frozenset({"notifications/initialized", "notifications/cancelled"})
_STDERR_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

_POSIX_DEFAULT_ENV_KEYS: tuple[str, ...] = ("PATH", "LANG", "LC_ALL", "TMPDIR", "TZ")
_WIN32_DEFAULT_ENV_KEYS: tuple[str, ...] = ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")

type RpcId = int | str


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

    def __init__(self, reader: asyncio.StreamReader, *, max_bytes: int) -> None:
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


async def _hard_kill_subprocess(proc: asyncio.subprocess.Process) -> None:
    """Forcefully terminate `proc` (preferring its process group via `SIGKILL` on POSIX) and reap it."""
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
        client_reader: asyncio.StreamReader,
        client_writer: ClientWriter,
        request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
        allowed_env_keys: Sequence[str] | None = None,
        extra_env: Mapping[str, str] | None = None,
        cwd: Path | None = None,
        err_stream: TextIO | None = None,
        aad_on_malformed_server_frame: bool = False,
    ) -> None:
        if not command:
            raise ValueError("AirlockProxy requires a non-empty command.")
        if request_timeout_seconds <= 0:
            raise ValueError("request_timeout_seconds must be positive.")

        self._command = tuple(command)
        self._policy = policy
        self._ledger = ledger
        self._client_reader = client_reader
        self._client_writer = client_writer
        self._request_timeout_seconds = float(request_timeout_seconds)
        self._allowed_env_keys = None if allowed_env_keys is None else tuple(allowed_env_keys)
        self._extra_env = dict(extra_env) if extra_env is not None else None
        self._cwd = cwd
        self._err_stream: TextIO = sys.stderr if err_stream is None else err_stream
        self._aad_on_malformed_server_frame = aad_on_malformed_server_frame

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
        self._faulted = False
        self._exit_code = 0
        self._downstream_stdin_closed = False
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
    ) -> None:
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
            metadata=metadata or {},
        )
        self._ledger.record(event)

    async def _write_client_bytes(self, payload: bytes, *, allow_during_aad: bool = False) -> None:
        async with self._client_write_lock:
            if (self._aad_fired or self._faulted) and not allow_during_aad:
                return
            try:
                self._client_writer.write(payload)
                await self._client_writer.drain()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

    async def _emit_client_error(
        self,
        *,
        rpc_id: RpcId | None,
        code: int,
        message: str,
        data: JsonObject | None = None,
        allow_during_aad: bool = False,
    ) -> None:
        frame = _jsonrpc_error_bytes(rpc_id, code, message, data=data)
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
            self._stop_event.set()
            return
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
            for rpc_id in pending:
                await self._emit_client_error(
                    rpc_id=rpc_id,
                    code=JSONRPC_INTERNAL_ERROR,
                    message="Airlock internal fault; request aborted and session closed.",
                    allow_during_aad=True,
                )
        finally:
            self._close_downstream_stdin()
            if self._proc is not None:
                await _hard_kill_subprocess(self._proc)
            self._stop_event.set()

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
          1. Synchronously flush & fsync `AAD_FIRE` event to `AuditLedger`.
          2. Emit terminal `-32099` (`AAD_CONTAINMENT_SEVERED`) error frames to client for active `rpc_id`s and close
             downstream stdin.
          3. Immediately `SIGKILL` downstream process/group and await exit.
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
                self._record_event(
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
            except Exception as rec_exc:
                self._log_err(f"[airlock AAD_FIRE] audit write failed ({type(rec_exc).__name__}); containing anyway")
            self._log_err(f"[airlock AAD_FIRE] rule={rule_id} reason={reason}")

            # 2. Emit terminal -32099 error frame(s).
            active_ids: list[RpcId] = []
            if rpc_id is not None:
                active_ids.append(rpc_id)
            for pending_id in list(self._in_flight):
                if pending_id not in active_ids:
                    active_ids.append(pending_id)
            self._in_flight.clear()
            self._idle_event.set()

            for target_id in active_ids:
                await self._emit_client_error(
                    rpc_id=target_id,
                    code=JSONRPC_AAD_CONTAINMENT_SEVERED,
                    message="AAD_CONTAINMENT_SEVERED",
                    data={"rule_id": rule_id},
                    allow_during_aad=True,
                )
        finally:
            # 3. Sever the downstream input pipe, hard SIGKILL its process group/process and reap it.
            self._close_downstream_stdin()
            if self._proc is not None:
                await _hard_kill_subprocess(self._proc)
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
            await self._trigger_aad(
                action=msg.method,
                rule_id="egress.canary_exfiltration",
                reason=reason,
                artifact_sha256=wire_sha,
                redactions=findings,
            )
            return
        if not ok:
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
            if verdict.severity == "AAD_FIRE":
                await self._trigger_aad(
                    action="tools/call",
                    rule_id=verdict.rule_id,
                    reason=verdict.reason,
                    artifact_sha256=verdict.artifact_sha256,
                    rpc_id=msg.id,
                    tool_name=tool_name,
                    redactions=verdict.redactions,
                )
                return
            if not verdict.verdict_allow:
                self._record_event(
                    action="tools/call",
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
                return

            # The AgBOM pins only protect the session if the tool was actually listed and verified: refuse calls
            # before any verified tools/list, and calls to tools the verified listing did not include.
            if self._verified_tool_names is None or tool_name not in self._verified_tool_names:
                not_verified_reason = (
                    "No tools/list response has passed AgBOM pin verification in this session yet."
                    if self._verified_tool_names is None
                    else f"Tool '{tool_name}' was not in the verified tools/list manifest."
                )
                self._record_event(
                    action="tools/call",
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
                return

            self._record_event(
                action="tools/call",
                verdict_allow=True,
                severity="INFO",
                rule_id=verdict.rule_id,
                reason=verdict.reason,
                artifact_sha256=verdict.artifact_sha256,
                tool_name=tool_name,
                request_id=msg.id,
            )
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

        if msg.method not in _ALLOWED_CLIENT_REQUEST_METHODS:
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

        scan_params = msg.params
        paginated = False
        if msg.method == "tools/list" and "cursor" in msg.params:
            # A cursor is opaque server data; the client may only echo back one the server issued on a verified
            # page. Anything else would be a free-form channel out of the airlock.
            cursor = msg.params["cursor"]
            if not isinstance(cursor, str) or cursor not in self._issued_cursors:
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
            scan_params = {key: value for key, value in msg.params.items() if key != "cursor"}
            paginated = True

        ok, is_aad, reason, findings = await self._scan_outbound_envelope(params=scan_params, request_id=msg.id)
        if is_aad:
            await self._trigger_aad(
                action=msg.method,
                rule_id="egress.canary_exfiltration",
                reason=reason,
                artifact_sha256=wire_sha,
                rpc_id=msg.id,
                redactions=findings,
            )
            return
        if not ok:
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

        resp_verdict = evaluate_tool_response(msg, self._policy)
        if resp_verdict.severity == "AAD_FIRE":
            await self._trigger_aad(
                action=in_flight.method,
                rule_id=resp_verdict.rule_id,
                reason=resp_verdict.reason,
                artifact_sha256=resp_verdict.artifact_sha256,
                rpc_id=msg.id,
                tool_name=in_flight.tool_name,
                redactions=resp_verdict.redactions,
            )
            return

        # Enforce size cap before AgBOM manifest parsing on tools/list; check AgBOM BEFORE general invisible block
        # so invisible Unicode tag injection inside tool definitions fires AAD_FIRE as required.
        if resp_verdict.rule_id == "airlock.response_too_large":
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
                await self._trigger_aad(
                    action="initialize",
                    rule_id="airlock.instructions_pin_mismatch",
                    reason="Server initialize instructions do not match the pinned instructions_sha256 (rug pull).",
                    artifact_sha256=resp_verdict.artifact_sha256,
                    rpc_id=msg.id,
                )
                return
            if pin is None:
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
            try:
                tool_defs = _parse_tools_list_result(msg.result)
            except (ValueError, ValidationError) as exc:
                await self._trigger_aad(
                    action="tools/list",
                    rule_id="airlock.invalid_tools_list_manifest",
                    reason=f"Invalid tools/list manifest from downstream server: {exc}",
                    artifact_sha256=resp_verdict.artifact_sha256,
                    rpc_id=msg.id,
                )
                return

            pin_verdict = verify_tools_list(tool_defs, self._policy)
            if pin_verdict.severity == "AAD_FIRE":
                await self._trigger_aad(
                    action="tools/list",
                    rule_id=pin_verdict.rule_id,
                    reason=pin_verdict.reason,
                    artifact_sha256=pin_verdict.artifact_sha256,
                    rpc_id=msg.id,
                )
                return
            if not pin_verdict.verdict_allow:
                self._record_event(
                    action="tools/list",
                    verdict_allow=False,
                    severity="BLOCK",
                    rule_id=pin_verdict.rule_id,
                    reason=pin_verdict.reason,
                    artifact_sha256=pin_verdict.artifact_sha256,
                    request_id=msg.id,
                )
                await self._emit_client_error(
                    rpc_id=msg.id,
                    code=JSONRPC_POLICY_VIOLATION,
                    message=f"Policy violation ({pin_verdict.rule_id}): {pin_verdict.reason}",
                    data={"rule_id": pin_verdict.rule_id},
                )
                return

            # Forward only what was verified: the pinned tool definitions plus a checked `nextCursor`. Any other key
            # in the result is free text the model could read, so it is dropped.
            raw_result = cast(JsonObject, msg.result)  # `_parse_tools_list_result` accepted it as an object
            tools_wire: list[JsonValue] = [tool.wire_dict() for tool in tool_defs]
            rebuilt: JsonObject = {"tools": tools_wire}
            next_cursor = raw_result.get("nextCursor")
            if next_cursor is not None:
                cursor_ok, cursor_aad, cursor_reason, cursor_findings = self._check_next_cursor(next_cursor)
                if cursor_aad:
                    await self._trigger_aad(
                        action="tools/list",
                        rule_id="egress.response_canary_detected",
                        reason=cursor_reason,
                        artifact_sha256=resp_verdict.artifact_sha256,
                        rpc_id=msg.id,
                        redactions=cursor_findings,
                    )
                    return
                if not cursor_ok:
                    self._record_event(
                        action="tools/list",
                        verdict_allow=False,
                        severity="BLOCK",
                        rule_id="airlock.invalid_next_cursor",
                        reason=cursor_reason,
                        artifact_sha256=resp_verdict.artifact_sha256,
                        request_id=msg.id,
                        redactions=cursor_findings,
                    )
                    await self._emit_client_error(
                        rpc_id=msg.id,
                        code=JSONRPC_POLICY_VIOLATION,
                        message=f"Policy violation (airlock.invalid_next_cursor): {cursor_reason}",
                        data={"rule_id": "airlock.invalid_next_cursor"},
                    )
                    return
                rebuilt["nextCursor"] = next_cursor
                issued_cursor = cast(str, next_cursor)
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
            verified_names = {tool.name for tool in tool_defs}

        if resp_verdict.severity == "AAD_FIRE":
            await self._trigger_aad(
                action=in_flight.method,
                rule_id=resp_verdict.rule_id,
                reason=resp_verdict.reason,
                artifact_sha256=resp_verdict.artifact_sha256,
                rpc_id=msg.id,
                tool_name=in_flight.tool_name,
                redactions=resp_verdict.redactions,
            )
            return

        if not resp_verdict.verdict_allow:
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

        self._record_event(
            action=in_flight.method,
            verdict_allow=True,
            severity="INFO",
            rule_id="airlock.response_allowed",
            reason=f"Verified and forwarded downstream response for '{in_flight.method}'.",
            artifact_sha256=resp_verdict.artifact_sha256,
            tool_name=in_flight.tool_name,
            request_id=msg.id,
        )
        if verified_names is not None:
            # A fresh listing replaces the verified set (a tool the server stopped listing can no longer be
            # called); a later page of a paginated listing adds to it.
            base = self._verified_tool_names if (in_flight.paginated and self._verified_tool_names) else set()
            self._verified_tool_names = base | verified_names
        if issued_cursor is not None:
            _remember(self._issued_cursors, issued_cursor, MAX_ISSUED_CURSORS)
        wire_resp = exact_json_bytes(cast(JsonObject, forward_msg.model_dump(mode="json"))) + b"\n"
        await self._write_client_bytes(wire_resp)

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
                self._stop_event.set()

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
        if not self._stop_event.is_set():
            await self._fail_remaining_in_flight_on_eof()
            self._stop_event.set()

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
        child_env = build_minimal_subprocess_env(allowed_keys=self._allowed_env_keys, extra_env=self._extra_env)
        cwd_str = str(self._cwd) if self._cwd is not None else None
        self._proc = await asyncio.create_subprocess_exec(  # noqa: S603 - explicit argv list, never a shell
            *self._command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
            env=child_env,
            cwd=cwd_str,
        )

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
                    await _hard_kill_subprocess(self._proc)
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
                await _hard_kill_subprocess(self._proc)

        return self._exit_code


__all__ = [
    "AAD_EXIT_CODE",
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
    "MAX_STDERR_LINE_BYTES",
    "AirlockProxy",
    "BoundedLineReader",
    "ClientWriter",
    "InFlightRequest",
    "RpcId",
    "build_minimal_subprocess_env",
]
