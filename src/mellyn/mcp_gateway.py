"""
MCP JSON-RPC 2.0 Security Gateway for Mellyn Security.

One gateway process fronts every downstream MCP server for one client connection (one agent session):

    MCP client (Claude Code, Cursor, Antigravity, ...)  <- stdio ->  gateway  <- stdio ->  server A, server B, ...

- One session, one Authorizer: taint picked up from server A (a GitHub issue) still applies when the agent
  next calls server B (a shell). Separate gateway processes per server would each start clean.
- Tools are exposed to the client as "<server>__<tool>", so the authorizer always knows which server a tool
  belongs to; risk tiers and allow rules are keyed by server too (see policy.py).
- The gateway answers the client's initialize itself. Downstream `instructions` never reach the client, and
  tool/resource listings from untrusted servers taint the session, because descriptions are model-visible
  text supplied by the server.
- Downstream replies are matched by request ID. Notifications and server-to-client requests (sampling,
  elicitation, roots) that arrive in between are never mistaken for the reply; server requests are refused.
- REQUIRE_APPROVAL calls are held as pending approvals that a human approves through the local approval
  server (approvals.py) with the approver key. The agent then retries the exact call.

Usage:
    python -m mellyn.mcp_gateway --config config/mellyn-gateway.example.toml \
        --workspace . --audit-log mellyn-audit.jsonl [--approval-port 8765]
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import io
import itertools
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import IO, Any, BinaryIO, Literal, Protocol, TextIO

from mellyn.approvals import ApprovalHTTPServer, PendingApprovals
from mellyn.audit import AuditChainError, AuditLogger
from mellyn.authorizer import RESOURCE_READ_TOOL, Authorizer
from mellyn.credentials import CredentialConfig, CredentialConfigError, Role
from mellyn.egress import WorkspaceConfigError, check_workspace_root
from mellyn.http_downstream import StreamableHttpDownstream
from mellyn.legacy_env import LEGACY_ENV_PREFIX, LegacyConfigError, check_no_legacy_env
from mellyn.models import (
    DOWNSTREAM_ERROR,
    DOWNSTREAM_TIMEOUT_SECONDS,
    MAX_LINE_BYTES,
    SUPPORTED_PROTOCOL_VERSIONS,
    Decision,
    GatewayLocalError,
    TaintSource,
    ToolCallRequest,
    canonical_json,
    jsonrpc_error,
    local_downstream_error,
)
from mellyn.oauth_client import OAuthError
from mellyn.policy_loader import PolicyLoadError
from mellyn.scanner import ScannerConfig, ScanResult, invisible_unicode_tools, scan_value
from mellyn.state_store import SqliteStateStore, StateStoreError
from mellyn.unified_config import load_mellyn_config

MAX_ARGUMENTS_BYTES = 64 * 1024
DEFAULT_MAX_INBOX_MESSAGES = 256
DEFAULT_MAX_INBOX_BYTES = 8 * 1024 * 1024
MAX_LIST_PAGES = 20
INIT_TIMEOUT_SECONDS = 30.0
TOOL_SEPARATOR = "__"
GATEWAY_INFO = {"name": "mellyn-gateway", "version": "1.0.0"}

# JSON-RPC 2.0 standard and Mellyn Security gateway error codes
JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_INTERNAL_ERROR = -32603
MELLYN_APPROVAL_REQUIRED = -32001
MELLYN_POLICY_DENIED = -32003
MELLYN_AAD_CONTAINED = -32099
# Methods that reach a downstream server; all are refused once AAD containment has severed the session.
_DOWNSTREAM_METHODS = frozenset({"tools/list", "tools/call", "resources/list", "resources/read"})

# Content-free notifications that are safe to pass from a downstream server to the client.
FORWARDED_SERVER_NOTIFICATIONS = frozenset({"notifications/tools/list_changed", "notifications/resources/list_changed"})

_local_downstream_error = local_downstream_error
_jsonrpc_error = jsonrpc_error


def _came_from_server(response: Mapping[str, Any]) -> bool:
    """True when a downstream server wrote this reply (a result OR an error), so its text reaches the agent."""
    return not isinstance(response, GatewayLocalError)


def _jsonrpc_result(req_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def compute_tools_hash(tools: Sequence[Mapping[str, Any]]) -> str:
    """
    Compute the deterministic SHA-256 hex digest of a server's `tools/list` definitions.

    Pinning this digest under `[pinned_tool_hashes]` in the policy lets an operator attest that they
    have reviewed a server's tool names, schemas, and descriptions: matching listings do not taint
    the session at turn 0, while any unreviewed change ("rug pull") is rejected fail-closed.
    """
    normalized = sorted((dict(t) for t in tools), key=lambda item: str(item.get("name", "")))
    return hashlib.sha256(canonical_json({"tools": normalized}).encode("utf-8")).hexdigest()


class Downstream(Protocol):
    """One downstream MCP server, as the gateway sees it."""

    name: str

    def request(
        self, method: str, params: dict[str, Any], timeout: float = DOWNSTREAM_TIMEOUT_SECONDS
    ) -> dict[str, Any]:
        """Return the server's JSON-RPC response with the matching ID, or a GatewayLocalError if it never answered."""
        ...

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None: ...

    def close(self) -> None: ...


_EOF = object()


# Both the current prefix and the retired one: main() refuses to start when old-prefixed variables are set,
# but library callers of downstream_environment() get the same protection.
SECRET_ENV_PREFIXES = ("MELLYN_", LEGACY_ENV_PREFIX)


def downstream_environment(
    environ: Mapping[str, str] | None = None, *, secret_names: Iterable[str] = ()
) -> dict[str, str]:
    """
    The environment for downstream MCP servers: the gateway's own, minus every MELLYN_* variable, every variable
    with the pre-rename prefix, and every variable the config names as a secret (`secret_names`: OAuth client
    secrets and bearer tokens). The servers the gateway launches are untrusted and must not see the gateway's
    credentials, whichever name a deployment set them under.
    """
    source = os.environ if environ is None else environ
    withheld = {name.upper() for name in secret_names}
    return {
        key: value
        for key, value in source.items()
        if not key.upper().startswith(SECRET_ENV_PREFIXES) and key.upper() not in withheld
    }


def _valid_request_id(req_id: Any) -> bool:
    """MCP base protocol: request IDs must be strings or integers, excluding booleans and null."""
    return isinstance(req_id, str | int) and not isinstance(req_id, bool)


def _valid_jsonrpc_response(response: Mapping[str, Any]) -> bool:
    """A JSON-RPC 2.0 response must declare '2.0' and carry exclusively 'result' or a dict 'error'."""
    if response.get("jsonrpc") != "2.0":
        return False
    has_result = "result" in response
    has_error = "error" in response
    if has_result == has_error:
        return False
    if has_error and not isinstance(response["error"], dict):
        return False
    return True


def _resolve_executable(argv0: str, env: Mapping[str, str], launcher_cwd: Path) -> str:
    """
    Resolve `argv[0]` against `launcher_cwd` or trusted `PATH` before changing a child's `cwd` to
    `workspace_root`. Uses `os.path.abspath` (not `Path.resolve()`) so Python venv symlinks keep
    their identity, and prevents bare command names from matching binaries inside `workspace_root`.
    """
    if os.path.isabs(argv0):
        return argv0
    if "/" in argv0 or (os.sep != "/" and os.sep in argv0):
        return os.path.abspath(launcher_cwd / argv0)
    found = shutil.which(argv0, path=env.get("PATH"))
    if found is None:
        raise FileNotFoundError(f"Executable '{argv0}' was not found on PATH.")
    return os.path.abspath(found)


def _resolve_posix_account(spec: str) -> tuple[int, int, str, str]:
    """Return `(uid, gid, username, home_dir)` for a POSIX account name or numeric UID."""
    import pwd

    pw = pwd.getpwuid(int(spec)) if spec.isdigit() else pwd.getpwnam(spec)
    return pw.pw_uid, pw.pw_gid, pw.pw_name, pw.pw_dir


def check_privilege_separation(
    *, running_as_root: bool, is_pid1: bool, gateway_user: str | None, downstream_user: str | None
) -> None:
    """
    Refuse configurations that would leave the gateway, or its MCP servers, running with root's privileges.

    Started as root, the gateway must be told both users: MCP servers run as `downstream_user` and the gateway
    drops to `gateway_user` for good. Without them it would run its whole life as root (with CAP_SETUID in the
    container), or hand root to every MCP server it launches. Switching users needs a root start, so naming
    users while not root is refused too, with a clear message rather than a failed spawn later.

    With separate users the gateway must also be PID 1 of its PID namespace (the container's main process, no
    `init`). After the drop it may not signal its MCP servers, and Linux applies the same permission check to the
    parent-death signal, so neither the gateway nor PR_SET_PDEATHSIG can stop a server that ignores stdin EOF.
    What does stop it is the kernel killing every process in the namespace when PID 1 exits.
    """
    if running_as_root and (gateway_user is None or downstream_user is None):
        raise RuntimeError(
            "The gateway is running as root: pass both --gateway-user and --downstream-user so it drops privileges "
            "and MCP servers run as a separate user (or start it as an unprivileged user without either flag)."
        )
    if not running_as_root and (gateway_user is not None or downstream_user is not None):
        raise RuntimeError("--gateway-user and --downstream-user need the gateway to start as root to switch users.")
    if (gateway_user is None) != (downstream_user is None):
        raise RuntimeError("--gateway-user and --downstream-user must be given together.")
    if downstream_user is not None and not is_pid1:
        raise RuntimeError(
            "--downstream-user needs the gateway to be PID 1 (the container's main process, without `init`): once "
            "it drops privileges it cannot signal its MCP servers, so only the end of the PID namespace stops them."
        )


def _drop_gateway_privileges(gateway_user: str) -> None:
    """
    Permanently set real, effective, and saved UID/GID (and clear supplementary groups) to `gateway_user`.
    Transitioning from UID 0 on Linux clears permitted and effective capabilities (`CAP_SETUID`, `CAP_SETGID`).
    """
    if os.name != "posix":
        raise RuntimeError("--gateway-user privilege separation requires a POSIX platform.")
    uid, gid, uname, home = _resolve_posix_account(gateway_user)
    if os.geteuid() == uid and os.getuid() == uid and os.getegid() == gid and os.getgid() == gid:
        return
    os.setgroups([])
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    if os.geteuid() != uid or os.getuid() != uid or os.getegid() != gid:
        raise RuntimeError(f"Failed to drop gateway privileges to '{gateway_user}'.")
    os.environ["HOME"] = home
    os.environ["USER"] = uname
    os.environ["LOGNAME"] = uname


def iter_bounded_frames(
    stream: BinaryIO | TextIO, *, max_line_bytes: int = MAX_LINE_BYTES
) -> Iterator[tuple[bytes | None, bool]]:
    """
    Yield `(frame_bytes, oversized)` from a newline-delimited stream without unbounded buffering.

    Reads bounded chunks (`min(65536, max_line_bytes + 2)`), measures limits strictly in UTF-8 bytes
    (never Unicode codepoints), and drains any oversized frame through its `\\n` delimiter while
    discarding excess bytes immediately. Empty/whitespace-only frames within the limit are skipped.
    """
    if max_line_bytes <= 0:
        raise ValueError("max_line_bytes must be positive.")
    chunk_limit = min(65536, max_line_bytes + 2)
    bstream = getattr(stream, "buffer", None)
    if bstream is not None:
        raw_source: Any = bstream
        is_bytes = True
    else:
        raw_source = stream
        is_bytes = isinstance(stream, io.RawIOBase | io.BufferedIOBase)

    while True:
        buf = bytearray()
        oversized = False
        got_any = False
        while True:
            piece = raw_source.readline(chunk_limit)
            if not piece:
                break
            got_any = True
            chunk_bytes = piece if is_bytes else str(piece).encode("utf-8", errors="surrogatepass")
            ended = chunk_bytes.endswith(b"\n")
            if not oversized:
                if len(buf) + len(chunk_bytes) > max_line_bytes + 2:
                    oversized = True
                    buf.clear()
                else:
                    buf.extend(chunk_bytes)
            if ended:
                break
        if not got_any:
            return
        if oversized:
            yield None, True
            continue
        payload = bytes(buf).rstrip(b"\r\n")
        if len(payload) > max_line_bytes:
            yield None, True
            continue
        stripped = payload.strip()
        if not stripped:
            continue
        yield stripped, False


class _BoundedInbox:
    """Thread-safe inbox bounding both queued message count and total queued UTF-8 bytes."""

    def __init__(
        self,
        *,
        max_messages: int = DEFAULT_MAX_INBOX_MESSAGES,
        max_bytes: int = DEFAULT_MAX_INBOX_BYTES,
    ) -> None:
        if max_messages <= 0 or max_bytes <= 0:
            raise ValueError("Inbox capacity limits must be positive.")
        self.max_messages = max_messages
        self.max_bytes = max_bytes
        self._cond = threading.Condition()
        self._items: deque[tuple[Any, int]] = deque()
        self._queued_bytes = 0
        self._eof = False
        self._closed = False

    @property
    def qsize(self) -> int:
        with self._cond:
            return len(self._items)

    @property
    def queued_bytes(self) -> int:
        with self._cond:
            return self._queued_bytes

    def put(self, item: Any, byte_size: int) -> bool:
        size = max(1, byte_size)
        if size > self.max_bytes:
            return False
        with self._cond:
            while not self._closed and (
                len(self._items) >= self.max_messages or self._queued_bytes + size > self.max_bytes
            ):
                self._cond.wait()
            if self._closed:
                return False
            self._items.append((item, size))
            self._queued_bytes += size
            self._cond.notify_all()
            return True

    def mark_eof(self) -> None:
        with self._cond:
            self._eof = True
            self._cond.notify_all()

    def close(self) -> None:
        with self._cond:
            self._closed = True
            self._eof = True
            self._items.clear()
            self._queued_bytes = 0
            self._cond.notify_all()

    def get(self, *, deadline: float) -> Any:
        with self._cond:
            while not self._items and not self._eof and not self._closed:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise queue.Empty
                self._cond.wait(timeout=remaining)
            if self._items:
                item, size = self._items.popleft()
                self._queued_bytes -= size
                self._cond.notify_all()
                return item
            return _EOF


class StdioDownstream:
    """
    A downstream MCP server launched as a subprocess (argv list, no shell) and spoken to over stdio.

    A reader thread parses bounded byte frames into a bounded `_BoundedInbox`. `request` enforces a single
    overall deadline covering both pipe write/flush and reply wait, closing an unresponsive child if either
    stalls so healthy peer servers continue operating.
    """

    def __init__(
        self,
        name: str,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        launcher_cwd: Path | None = None,
        user: str | int | None = None,
        group: str | int | None = None,
        child_home: str | None = None,
        child_username: str | None = None,
        on_notification: Callable[[str, dict[str, Any]], None] | None = None,
        stderr: int | TextIO | None = None,
        max_line_bytes: int = MAX_LINE_BYTES,
        max_inbox_messages: int = DEFAULT_MAX_INBOX_MESSAGES,
        max_inbox_bytes: int = DEFAULT_MAX_INBOX_BYTES,
        writer: Callable[[bytes], None] | None = None,
        env: Mapping[str, str] | None = None,
        secret_env_names: Iterable[str] = (),
    ) -> None:
        if not argv:
            raise ValueError(f"Server '{name}' requires a non-empty command argv.")
        self.name = name
        self.on_notification = on_notification or (lambda _server, _msg: None)
        self._max_line_bytes = max_line_bytes
        self._ids = itertools.count(1)
        self._inbox = _BoundedInbox(max_messages=max_inbox_messages, max_bytes=max_inbox_bytes)
        self._write_lock = threading.Lock()
        self._custom_writer = writer
        self._writer_thread: threading.Thread | None = None
        self._closed = False

        child_env = downstream_environment(env, secret_names=secret_env_names)
        if child_home is not None:
            child_env["HOME"] = child_home
        if child_username is not None:
            child_env["USER"] = child_username
            child_env["LOGNAME"] = child_username

        resolved_argv = [_resolve_executable(argv[0], child_env, launcher_cwd or Path.cwd()), *argv[1:]]
        popen_kwargs: dict[str, Any] = {}
        if cwd is not None:
            popen_kwargs["cwd"] = str(cwd)
        if user is not None:
            popen_kwargs["user"] = user
        if group is not None:
            popen_kwargs["group"] = group
        if user is not None or group is not None:
            popen_kwargs["extra_groups"] = []

        self.proc = subprocess.Popen(  # noqa: S603 - argv list validated by gateway_config; never a shell
            resolved_argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr if stderr is not None else sys.stderr,
            env=child_env,
            **popen_kwargs,
        )
        self._reader = threading.Thread(target=self._read_loop, name=f"mcp-{name}-reader", daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        stdout = self.proc.stdout
        if stdout is None:
            self._inbox.mark_eof()
            return
        try:
            for frame, oversized in iter_bounded_frames(stdout, max_line_bytes=self._max_line_bytes):
                if oversized or frame is None:
                    continue
                try:
                    parsed = json.loads(frame.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                self._inbox.put(parsed, len(frame))
        except (OSError, ValueError):
            pass
        finally:
            self._inbox.mark_eof()

    def _raw_write(self, payload: bytes) -> None:
        if self._custom_writer is not None:
            self._custom_writer(payload)
            return
        stdin = self.proc.stdin
        if stdin is None:
            raise BrokenPipeError("stdin closed")
        stdin.write(payload)
        stdin.flush()

    def _abort_unresponsive(self) -> None:
        """Mark this server dead and terminate it without hanging when a request deadline expires."""
        self._closed = True
        self._inbox.close()
        for stop in (self.proc.terminate, self.proc.kill):
            try:
                stop()
                break
            except OSError:
                continue
        writer_stuck = self._writer_thread is not None and self._writer_thread.is_alive()
        if self.proc.stdin is not None and not writer_stuck:
            try:
                self.proc.stdin.close()
            except OSError:
                pass

    def _write_with_deadline(self, message: dict[str, Any], deadline: float) -> tuple[bool, bool]:
        """Return `(wrote_ok, timed_out)`. Counts writing and flushing against `deadline`."""
        if self._closed:
            return False, False
        payload = (json.dumps(message) + "\n").encode("utf-8")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            self._abort_unresponsive()
            return False, True
        if not self._write_lock.acquire(timeout=remaining):
            self._abort_unresponsive()
            return False, True
        try:
            if self._closed:
                return False, False
            done = threading.Event()
            errors: list[BaseException] = []

            def _do_write() -> None:
                try:
                    self._raw_write(payload)
                except BaseException as exc:  # noqa: BLE001
                    errors.append(exc)
                finally:
                    done.set()

            worker = threading.Thread(target=_do_write, name=f"mcp-{self.name}-writer", daemon=True)
            self._writer_thread = worker
            worker.start()
            if not done.wait(timeout=max(0.0, deadline - time.monotonic())):
                self._abort_unresponsive()
                return False, True
            if errors:
                return False, False
            return True, False
        finally:
            self._write_lock.release()

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self._write_with_deadline(message, time.monotonic() + min(5.0, DOWNSTREAM_TIMEOUT_SECONDS))

    def request(
        self, method: str, params: dict[str, Any], timeout: float = DOWNSTREAM_TIMEOUT_SECONDS
    ) -> dict[str, Any]:
        req_id = f"mellyn-{next(self._ids)}"
        deadline = time.monotonic() + timeout
        wrote, write_timed_out = self._write_with_deadline(
            {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params},
            deadline,
        )
        if not wrote:
            if write_timed_out:
                return _local_downstream_error(req_id, f"Downstream server '{self.name}' timed out.")
            return _local_downstream_error(req_id, f"Downstream server '{self.name}' is not accepting input.")
        while True:
            # Checked on every message, not only when the inbox is empty: a server that keeps the inbox full
            # (a notification flood faster than the gateway forwards it) must not hold the request open forever.
            if time.monotonic() >= deadline:
                self._abort_unresponsive()
                return _local_downstream_error(req_id, f"Downstream server '{self.name}' timed out.")
            try:
                message = self._inbox.get(deadline=deadline)
            except queue.Empty:
                self._abort_unresponsive()
                return _local_downstream_error(req_id, f"Downstream server '{self.name}' timed out.")
            if message is _EOF:
                return _local_downstream_error(req_id, f"Downstream server '{self.name}' closed.")
            if not isinstance(message, dict):
                continue
            if isinstance(message.get("method"), str):
                if "id" in message:  # server-to-client request (sampling, elicitation, roots): refuse
                    srv_id = message["id"] if _valid_request_id(message["id"]) else None
                    self._write_with_deadline(
                        _jsonrpc_error(srv_id, JSONRPC_METHOD_NOT_FOUND, "Not permitted by gateway."),
                        deadline,
                    )
                else:
                    self.on_notification(self.name, message)
                continue
            if message.get("id") == req_id:
                if not _valid_jsonrpc_response(message):
                    return _local_downstream_error(
                        req_id, f"Downstream server '{self.name}' returned a malformed JSON-RPC response."
                    )
                return message
            # A response to some earlier, timed-out request: drop it.

    def close(self) -> None:
        """
        Stop the server: close its stdin (an MCP server exits on EOF), wait, then signal it if it is still running.

        When the server runs as a separate user and the gateway has dropped privileges, signalling is not allowed
        (EPERM). That is expected, not an error: such a gateway runs as PID 1 (see check_privilege_separation), so
        the kernel kills the server when the gateway exits. close() must therefore return, not hang.
        """
        self._closed = True
        inbox = getattr(self, "_inbox", None)
        if inbox is not None:
            inbox.close()
        writer_thread = getattr(self, "_writer_thread", None)
        writer_stuck = writer_thread is not None and writer_thread.is_alive()
        try:
            if self.proc.stdin is not None and not writer_stuck:
                self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            for stop in (self.proc.terminate, self.proc.kill):
                try:
                    stop()
                except PermissionError:
                    break  # separate user: the kernel kills it when the gateway (PID 1) exits
                except OSError:
                    break
                try:
                    self.proc.wait(timeout=5)
                    break
                except subprocess.TimeoutExpired:
                    continue
        self._reader.join(timeout=5)
        # If the server could not be stopped, the reader thread is still blocked in readline() holding the stream's
        # lock, and close() would wait for it forever. Leave the pipe to the (daemon) reader: the server is killed,
        # and the pipe reaches EOF, when the gateway exits.
        if self.proc.stdout is not None and not self._reader.is_alive():
            self.proc.stdout.close()

    def kill_now(self) -> None:
        """Immediately sever stdin/inbox and terminate the downstream process for AAD containment."""
        self._closed = True
        inbox = getattr(self, "_inbox", None)
        if inbox is not None:
            inbox.close()
        writer_thread = getattr(self, "_writer_thread", None)
        writer_stuck = writer_thread is not None and writer_thread.is_alive()
        try:
            if self.proc.stdin is not None and not writer_stuck:
                self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.kill()
            self.proc.wait(timeout=2)
        except (PermissionError, OSError, subprocess.TimeoutExpired):
            pass
        reader = getattr(self, "_reader", None)
        if reader is not None:
            reader.join(timeout=2)
            if self.proc.stdout is not None and not reader.is_alive():
                try:
                    self.proc.stdout.close()
                except OSError:
                    pass


def initialize_downstream(server: Downstream, timeout: float = INIT_TIMEOUT_SECONDS) -> None:
    """Run the MCP handshake with a downstream server. Raises RuntimeError if it fails."""
    response = server.request(
        "initialize",
        {"protocolVersion": SUPPORTED_PROTOCOL_VERSIONS[0], "capabilities": {}, "clientInfo": GATEWAY_INFO},
        timeout=timeout,
    )
    if not _valid_jsonrpc_response(response) or not isinstance(response.get("result"), dict):
        raise RuntimeError(f"Downstream server '{server.name}' failed to initialize: {response.get('error')}")
    negotiated = response["result"].get("protocolVersion")
    if not isinstance(negotiated, str) or negotiated not in SUPPORTED_PROTOCOL_VERSIONS:
        raise RuntimeError(f"Downstream server '{server.name}' negotiated unsupported protocolVersion: {negotiated!r}")
    server.notify("notifications/initialized")


class MCPGateway:
    """Deterministic MCP JSON-RPC 2.0 policy enforcement gateway over one or more downstream servers."""

    def __init__(
        self,
        *,
        authorizer: Authorizer,
        servers: Mapping[str, Downstream],
        approvals: PendingApprovals | None = None,
        notify_client: Callable[[dict[str, Any]], None] | None = None,
        session_id: str | None = None,
        scanner_config: ScannerConfig | None = None,
        mode: Literal["enforce", "observe"] = "enforce",
        allow_observe_mode: bool = False,
    ) -> None:
        if not servers:
            raise ValueError("The gateway needs at least one downstream server.")
        for name in servers:
            if TOOL_SEPARATOR in name or not name:
                raise ValueError(f"Server name '{name}' must not be empty or contain '{TOOL_SEPARATOR}'.")
        if mode not in ("enforce", "observe"):
            raise ValueError(f"Unsupported gateway mode {mode!r}; expected 'enforce' or 'observe'.")
        if mode == "observe" and not allow_observe_mode:
            raise ValueError("Observe mode requires explicit allow_observe_mode = true (fail closed).")
        self.authorizer = authorizer
        self.servers = dict(servers)
        self.approvals = approvals
        self.notify_client = notify_client or (lambda _msg: None)
        self.session_id = session_id or authorizer.create_session()
        self.scanner_config = scanner_config
        self.mode: Literal["enforce", "observe"] = mode
        self.allow_observe_mode = allow_observe_mode
        self._quarantined_servers: set[str] = set()
        self._aad_tripped = False
        self._resource_owner: dict[str, str | None] = {}  # uri -> server (None when two servers claim it)

    # ---- AAD & Scanner helpers -------------------------------------------------------------------

    def _trigger_aad(self, server_name: str) -> None:
        """
        Sever the whole session, not just `server_name`, as the Airlock does.

        A canary in a request means the agent already holds it (response scanning missed it once), so every other
        server is the obvious next way out. All servers are stopped and every later call is refused.
        """
        del server_name  # the trigger is recorded in the audit log; containment covers every server
        self._aad_tripped = True
        self._quarantined_servers.update(self.servers)
        for server in self.servers.values():
            kill_fn = getattr(server, "kill_now", None)
            try:
                if callable(kill_fn):
                    kill_fn()
                else:
                    server.close()
            except Exception as exc:  # noqa: BLE001 - one server failing to stop must not leave the others running
                print(f"AAD: could not stop downstream server '{server.name}': {exc}", file=sys.stderr)

    def _apply_scanner(
        self,
        req_id: Any,
        *,
        server_name: str,
        tool_name: str,
        payload: Any,
        direction: Literal["request", "response"],
    ) -> dict[str, Any] | None:
        if self.scanner_config is None:
            return None
        scan: ScanResult = scan_value(payload, self.scanner_config)
        if scan.clean:
            return None

        is_aad = scan.canary_matched and self.scanner_config.aad_kill_on_leak
        if self.mode == "observe":
            decision_label = "observed_aad" if is_aad else "observed_block"
        elif is_aad:
            decision_label = "aad_fire"
        else:
            decision_label = "blocked_egress"

        # Rule IDs only. A hash of the matched value would let anyone holding the log confirm a guessed canary or
        # secret, and field paths include dict keys, which are attacker-controlled text.
        rule_summary = ", ".join(sorted({f"{f.kind}:{f.rule_id}" for f in scan.findings}))
        snap = self.authorizer._state.get_session_snapshot(self.session_id)
        self.authorizer.audit.record_containment(
            session_id=self.session_id,
            tool_name=tool_name,
            mcp_server=server_name,
            decision=decision_label,
            reasons=(f"Egress scanner {direction} match ({rule_summary}).",),
            payload=payload,
            tainted=bool(snap and snap.tainted),
            taint_count=snap.taint_count if snap else 0,
            taint_sources=snap.taint_entries if snap else (),
            enforcement_mode=self.mode,
        )

        if self.mode == "observe":
            return None

        if is_aad:
            self._trigger_aad(server_name)
            return _jsonrpc_error(
                req_id,
                MELLYN_AAD_CONTAINED,
                "AAD containment severed this session: a canary was detected and every downstream server was stopped.",
                {"decision": "aad_fire", "mcp_server": server_name},
            )
        return _jsonrpc_error(
            req_id,
            MELLYN_POLICY_DENIED,
            f"Tool {direction} blocked by Mellyn Security egress scanner.",
            {"decision": Decision.DENY.value, "mcp_server": server_name},
        )

    def _reject_hidden_text(
        self, req_id: Any, *, server_name: str, listed: list[dict[str, Any]], kind: str
    ) -> dict[str, Any] | None:
        """
        Block a listing whose definitions hide text in invisible format/tag characters, pinned or not.

        Pinning records a hash; it does not make hidden instructions safe, and pinned descriptions are not tainted.
        Independent of the scanner config, so it applies even with no canaries configured.
        """
        flagged = invisible_unicode_tools(listed)
        if not flagged:
            return None
        observed = self.mode == "observe"
        snap = self.authorizer._state.get_session_snapshot(self.session_id)
        self.authorizer.audit.record_containment(
            session_id=self.session_id,
            tool_name=kind,
            mcp_server=server_name,
            decision="observed_hidden_unicode" if observed else "blocked_listing",
            reasons=(f"{kind} from '{server_name}' has {len(flagged)} definition(s) with invisible Unicode.",),
            payload=listed,
            tainted=bool(snap and snap.tainted),
            taint_count=snap.taint_count if snap else 0,
            taint_sources=snap.taint_entries if snap else (),
            enforcement_mode=self.mode,
            policy_id="gateway.hidden_unicode",
        )
        if observed:
            return None
        return _jsonrpc_error(
            req_id,
            MELLYN_POLICY_DENIED,
            f"Listing from '{server_name}' blocked: definitions contain invisible Unicode characters.",
            {"decision": Decision.DENY.value, "mcp_server": server_name},
        )

    # ---- Taint helpers --------------------------------------------------------------------------

    def _is_trusted(self, server: str) -> bool:
        return server in self.authorizer.policy.config.trusted_mcp_servers

    def _taint_from(self, server: str, what: str) -> None:
        if not self._is_trusted(server):
            self.authorizer.mark_tainted(self.session_id, TaintSource(source_type=what, origin=server))

    def on_downstream_notification(self, server: str, message: dict[str, Any]) -> None:
        """Pass only content-free list-changed notifications through; drop the rest."""
        if message.get("method") in FORWARDED_SERVER_NOTIFICATIONS:
            self.notify_client({"jsonrpc": "2.0", "method": message["method"]})

    # ---- Dispatch -------------------------------------------------------------------------------

    def handle_message(self, message: Any) -> dict[str, Any] | None:
        """Process one JSON-RPC 2.0 message from the MCP client. Returns the reply, or None for notifications."""
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return _jsonrpc_error(None, JSONRPC_INVALID_REQUEST, "Invalid JSON-RPC 2.0 message.")
        has_id = "id" in message
        raw_id = message.get("id")
        if has_id and not _valid_request_id(raw_id):
            return _jsonrpc_error(
                None, JSONRPC_INVALID_REQUEST, "Request 'id' must be a string or integer (not null or boolean)."
            )
        method = message.get("method")
        if not isinstance(method, str) or not method:
            return _jsonrpc_error(raw_id if has_id else None, JSONRPC_INVALID_REQUEST, "Missing or invalid 'method'.")
        if not has_id:
            return None  # client notifications (initialized, cancelled, ...) need no reply; nothing is executed
        req_id = raw_id
        params = message.get("params", {})
        if not isinstance(params, dict):
            return _jsonrpc_error(req_id, JSONRPC_INVALID_PARAMS, "'params' must be a JSON object.")

        handlers: dict[str, Callable[[Any, dict[str, Any]], dict[str, Any]]] = {
            "initialize": self._initialize,
            "ping": lambda rid, _p: _jsonrpc_result(rid, {}),
            "tools/list": self._tools_list,
            "tools/call": self._tools_call,
            "resources/list": self._resources_list,
            "resources/read": self._resources_read,
            "resources/templates/list": lambda rid, _p: _jsonrpc_result(rid, {"resourceTemplates": []}),
            "prompts/list": lambda rid, _p: _jsonrpc_result(rid, {"prompts": []}),
        }
        handler = handlers.get(method)
        if handler is None:
            return _jsonrpc_error(
                req_id, JSONRPC_METHOD_NOT_FOUND, f"Method '{method}' is not permitted by the gateway."
            )
        if self._aad_tripped and method in _DOWNSTREAM_METHODS:
            return _jsonrpc_error(
                req_id, MELLYN_AAD_CONTAINED, "This session was severed by AAD containment; start a new session."
            )
        return handler(req_id, params)

    def _initialize(self, req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        requested = params.get("protocolVersion")
        version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else SUPPORTED_PROTOCOL_VERSIONS[0]
        return _jsonrpc_result(
            req_id,
            {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": True}, "resources": {"listChanged": True}},
                "serverInfo": GATEWAY_INFO,
            },
        )

    def _list_all(self, server: Downstream, method: str, key: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        seen_cursors: set[str] = set()
        cursor: str | None = None
        for _ in range(MAX_LIST_PAGES):
            response = server.request(method, {"cursor": cursor} if cursor else {})
            if not _valid_jsonrpc_response(response):
                break
            result = response.get("result")
            if not isinstance(result, dict):
                break
            items.extend(item for item in result.get(key, []) if isinstance(item, dict))
            next_cursor = result.get("nextCursor") if isinstance(result.get("nextCursor"), str) else None
            if not next_cursor or next_cursor in seen_cursors:
                break
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        return items

    def _fetch_tools_strict(self, server: Downstream) -> tuple[bool, list[dict[str, Any]], str]:
        """
        Fetch a complete, error-free `tools/list` from `server`.
        Requires every page to return a valid JSON-RPC result, every tool entry to carry a valid
        non-reserved unique name, and pagination to finish cleanly within `MAX_LIST_PAGES`.
        """
        items: list[dict[str, Any]] = []
        seen_names: set[str] = set()
        seen_cursors: set[str] = set()
        cursor: str | None = None
        for _ in range(MAX_LIST_PAGES):
            response = server.request("tools/list", {"cursor": cursor} if cursor else {})
            if not _valid_jsonrpc_response(response) or not isinstance(response.get("result"), dict):
                return False, [], f"Downstream MCP server '{server.name}' did not return a valid tools/list result."
            raw_tools = response["result"].get("tools")
            if not isinstance(raw_tools, list):
                return False, [], f"Downstream MCP server '{server.name}' returned a malformed tools array."
            for entry in raw_tools:
                if not isinstance(entry, dict) or not _valid_name(entry.get("name")):
                    return False, [], f"Downstream MCP server '{server.name}' returned an invalid tool definition."
                tname = entry["name"]
                if tname in seen_names:
                    return False, [], f"Downstream MCP server '{server.name}' returned duplicate tool '{tname}'."
                seen_names.add(tname)
                items.append(entry)
            next_cursor = response["result"].get("nextCursor")
            if next_cursor is None or next_cursor == "":
                return True, items, ""
            if not isinstance(next_cursor, str) or next_cursor in seen_cursors:
                return False, [], f"Downstream MCP server '{server.name}' returned an invalid pagination cursor."
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        return False, [], f"Downstream MCP server '{server.name}' exceeded MAX_LIST_PAGES ({MAX_LIST_PAGES})."

    def _verify_pinned_server(self, server_name: str, expected_hash: str) -> tuple[bool, list[dict[str, Any]], str]:
        ok, listed, err = self._fetch_tools_strict(self.servers[server_name])
        if not ok:
            return False, [], err
        try:
            actual_hash = compute_tools_hash(listed)
        except (TypeError, ValueError):
            return False, [], f"Downstream MCP server '{server_name}' tool definitions failed canonical hashing."
        if actual_hash != expected_hash:
            return (
                False,
                [],
                f"Downstream MCP server '{server_name}' tool definitions do not match pinned SHA-256 hash.",
            )
        return True, listed, ""

    def _tools_list(self, req_id: Any, _params: dict[str, Any]) -> dict[str, Any]:
        tools: list[dict[str, Any]] = []
        pinned = self.authorizer.policy.config.pinned_tool_hashes
        for name, server in self.servers.items():
            if name in pinned:
                ok, listed, err = self._verify_pinned_server(name, pinned[name])
                if not ok:
                    return _jsonrpc_error(
                        req_id,
                        MELLYN_POLICY_DENIED,
                        err,
                        {"decision": Decision.DENY.value, "mcp_server": name},
                    )
            else:
                listed = [t for t in self._list_all(server, "tools/list", "tools") if _valid_name(t.get("name"))]
            # Tool names and descriptions are server-written text the agent reads, so they are scanned like results.
            listing_err = self._reject_hidden_text(req_id, server_name=name, listed=listed, kind="tools/list")
            if listing_err is None:
                listing_err = self._apply_scanner(
                    req_id, server_name=name, tool_name="tools/list", payload=listed, direction="response"
                )
            if listing_err is not None:
                return listing_err
            for tool in listed:
                tools.append({**tool, "name": f"{name}{TOOL_SEPARATOR}{tool['name']}"})
            if listed and name not in pinned:
                self._taint_from(name, "mcp_tool_descriptions")
        return _jsonrpc_result(req_id, {"tools": tools})

    def _resources_list(self, req_id: Any, _params: dict[str, Any]) -> dict[str, Any]:
        resources: list[dict[str, Any]] = []
        owners: dict[str, str | None] = {}
        for name, server in self.servers.items():
            listed = [r for r in self._list_all(server, "resources/list", "resources") if isinstance(r.get("uri"), str)]
            listing_err = self._reject_hidden_text(req_id, server_name=name, listed=listed, kind="resources/list")
            if listing_err is None:
                listing_err = self._apply_scanner(
                    req_id, server_name=name, tool_name="resources/list", payload=listed, direction="response"
                )
            if listing_err is not None:
                return listing_err
            for resource in listed:
                uri = resource["uri"]
                owners[uri] = None if uri in owners and owners[uri] != name else name
                resources.append(resource)
            if listed:
                self._taint_from(name, "mcp_resource_descriptions")
        self._resource_owner = owners
        return _jsonrpc_result(req_id, {"resources": [r for r in resources if owners.get(r["uri"])]})

    def _tools_call(self, req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        exposed = params.get("name")
        if not isinstance(exposed, str) or TOOL_SEPARATOR not in exposed:
            return _jsonrpc_error(req_id, JSONRPC_INVALID_PARAMS, "tools/call 'name' must be '<server>__<tool>'.")
        server_name, _, tool_name = exposed.partition(TOOL_SEPARATOR)
        if server_name not in self.servers or not _valid_name(tool_name):
            return _jsonrpc_error(req_id, JSONRPC_INVALID_PARAMS, f"Unknown tool '{exposed}'.")
        if server_name in self._quarantined_servers:
            return _jsonrpc_error(
                req_id,
                MELLYN_AAD_CONTAINED,
                f"Downstream server '{server_name}' is quarantined after AAD containment.",
            )
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            return _jsonrpc_error(req_id, JSONRPC_INVALID_PARAMS, "tools/call 'arguments' must be a JSON object.")
        try:
            encoded_args = canonical_json(arguments).encode("utf-8")
        except (TypeError, ValueError) as exc:
            return _jsonrpc_error(req_id, JSONRPC_INVALID_PARAMS, f"Invalid tool arguments: {exc}")
        if len(encoded_args) > MAX_ARGUMENTS_BYTES:
            return _jsonrpc_error(req_id, JSONRPC_INVALID_PARAMS, "tools/call 'arguments' exceed 64 KiB.")

        scan_err = self._apply_scanner(
            req_id,
            server_name=server_name,
            tool_name=tool_name,
            payload=arguments,
            direction="request",
        )
        if scan_err is not None:
            return scan_err

        request = ToolCallRequest(
            self.session_id,
            tool_name,
            arguments,
            mcp_server=server_name,
            mcp_method="tools/call",
        )
        pinned = self.authorizer.policy.config.pinned_tool_hashes
        pin_denial: str | None = None
        if server_name in pinned:
            ok, listed, err = self._verify_pinned_server(server_name, pinned[server_name])
            if not ok:
                pin_denial = err
            elif all(t["name"] != tool_name for t in listed):
                pin_denial = f"Tool '{tool_name}' is not present in pinned tool definitions for '{server_name}'."

        blocked = self._authorize(req_id, request, denial_reason=pin_denial)
        if blocked is not None:
            return blocked
        # Forward exactly what was authorized, rebuilt from validated fields.
        response = self.servers[server_name].request("tools/call", {"name": tool_name, "arguments": arguments})
        if not _valid_jsonrpc_response(response):
            return _jsonrpc_error(req_id, DOWNSTREAM_ERROR, "Malformed downstream JSON-RPC response.")
        # Taint on anything the server wrote, errors included: a relayed error message reaches the agent too,
        # so an injection delivered as an error must taint just like one delivered as a result.
        if _came_from_server(response):
            self.authorizer.record_tool_result_taint(request)
        resp_scan_err = self._apply_scanner(
            req_id,
            server_name=server_name,
            tool_name=tool_name,
            payload=response,
            direction="response",
        )
        if resp_scan_err is not None:
            return resp_scan_err
        return _relay(req_id, response)

    def _resources_read(self, req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        uri = params.get("uri")
        if not isinstance(uri, str) or not uri.strip():
            return _jsonrpc_error(req_id, JSONRPC_INVALID_PARAMS, "resources/read requires a non-empty string 'uri'.")
        server_name = self._resource_owner.get(uri)
        if server_name is None:
            return _jsonrpc_error(
                req_id, JSONRPC_INVALID_PARAMS, "Unknown or ambiguous resource URI; call resources/list first."
            )
        if server_name in self._quarantined_servers:
            return _jsonrpc_error(
                req_id,
                MELLYN_AAD_CONTAINED,
                f"Downstream server '{server_name}' is quarantined after AAD containment.",
            )
        scan_err = self._apply_scanner(
            req_id,
            server_name=server_name,
            tool_name=RESOURCE_READ_TOOL,
            payload={"uri": uri},
            direction="request",
        )
        if scan_err is not None:
            return scan_err
        request = ToolCallRequest(
            self.session_id,
            RESOURCE_READ_TOOL,
            {"uri": uri},
            mcp_server=server_name,
            mcp_method="resources/read",
        )
        blocked = self._authorize(req_id, request)
        if blocked is not None:
            return blocked
        response = self.servers[server_name].request("resources/read", {"uri": uri})
        if not _valid_jsonrpc_response(response):
            return _jsonrpc_error(req_id, DOWNSTREAM_ERROR, "Malformed downstream JSON-RPC response.")
        # Taint on anything the server wrote, errors included: a relayed error message reaches the agent too,
        # so an injection delivered as an error must taint just like one delivered as a result.
        if _came_from_server(response):
            self.authorizer.record_tool_result_taint(request)
        resp_scan_err = self._apply_scanner(
            req_id,
            server_name=server_name,
            tool_name=RESOURCE_READ_TOOL,
            payload=response,
            direction="response",
        )
        if resp_scan_err is not None:
            return resp_scan_err
        return _relay(req_id, response)

    def _authorize(
        self, req_id: Any, request: ToolCallRequest, *, denial_reason: str | None = None
    ) -> dict[str, Any] | None:
        """Return None when the call may proceed, otherwise the JSON-RPC error to send back."""
        result = self.authorizer.authorize(request, record_taint_on_allow=False, denial_reason=denial_reason)
        if result.decision == Decision.ALLOW:
            return None
        if self.mode == "observe" and result.decision == Decision.REQUIRE_APPROVAL:
            # Observe mode lets a call that would wait for approval run, and records that it ran. It never relaxes
            # DENY: denials cover the gateway's own config, audit log and state, secret files, and destructive
            # commands, and one let through could change what is enforced long after the observe session ends.
            snap = self.authorizer._state.get_session_snapshot(self.session_id)
            self.authorizer.audit.record_containment(
                session_id=self.session_id,
                tool_name=request.tool_name,
                mcp_server=request.mcp_server,
                decision="observed_require_approval",
                reasons=("Observe mode ran a call that needs human approval without waiting for it.",),
                payload=request.arguments,
                tainted=bool(snap and snap.tainted),
                taint_count=snap.taint_count if snap else 0,
                taint_sources=snap.taint_entries if snap else (),
                enforcement_mode=self.mode,
                policy_id="gateway.observe",
            )
            return None
        # Full reasons go to the audit log and the approver, not to the agent: they would tell an injected
        # model exactly which rule to work around.
        data: dict[str, Any] = {"decision": result.decision.value, "audit_id": result.audit_id}
        if result.decision == Decision.DENY:
            return _jsonrpc_error(req_id, MELLYN_POLICY_DENIED, "Tool call denied by Mellyn Security policy.", data)
        if self.approvals is None:
            return _jsonrpc_error(
                req_id, MELLYN_POLICY_DENIED, "Tool call needs human approval, and approvals are not configured.", data
            )
        pending = self.approvals.add(request, result)
        data["approval_id"] = pending.approval_id
        return _jsonrpc_error(
            req_id,
            MELLYN_APPROVAL_REQUIRED,
            f"Tool call is waiting for human approval ({pending.approval_id}). Retry the same call once approved.",
            data,
        )


def resolve_gateway_mode(
    cli_mode: str | None, *, config_mode: str, allow_observe_mode: bool
) -> Literal["enforce", "observe"]:
    """
    Decide the gateway mode. Observe takes two separate opt-ins, as in the Airlock: the config must permit it
    (`allow_observe_mode = true`) and the operator must pass `--mode observe`. The config alone never switches
    enforcement off, so `config_mode` only matters for the warning the caller prints.
    """
    del config_mode
    if cli_mode not in (None, "enforce", "observe"):
        raise ValueError(f"Unsupported mode {cli_mode!r}; expected 'enforce' or 'observe'.")
    if cli_mode == "observe":
        if not allow_observe_mode:
            raise ValueError("--mode observe requires [runtime].allow_observe_mode = true in the config.")
        return "observe"
    return "enforce"


def _valid_name(name: Any) -> bool:
    if not isinstance(name, str) or not 0 < len(name) <= 128:
        return False
    if not name.isprintable() or name.isspace():
        return False
    return name != RESOURCE_READ_TOOL and "/" not in name


def _relay(req_id: Any, response: dict[str, Any]) -> dict[str, Any]:
    """Re-address a downstream response to the client's request ID, keeping only result or a sanitized error."""
    if not _valid_jsonrpc_response(response):
        return _jsonrpc_error(req_id, DOWNSTREAM_ERROR, "Malformed downstream JSON-RPC response.")
    if "result" in response:
        return _jsonrpc_result(req_id, response["result"])
    error = response["error"]
    code = (
        error.get("code")
        if isinstance(error.get("code"), int) and not isinstance(error.get("code"), bool)
        else (DOWNSTREAM_ERROR)
    )
    message = error.get("message") if isinstance(error.get("message"), str) else "Downstream server error."
    return _jsonrpc_error(req_id, code, message[:1000])


def run_stdio_proxy(
    *,
    gateway: MCPGateway,
    client_in: BinaryIO | TextIO,
    client_out: TextIO,
    max_line_bytes: int = MAX_LINE_BYTES,
) -> int:
    """Read bounded UTF-8 newline-delimited JSON-RPC frames from client_in and write replies to client_out."""
    for frame, oversized in iter_bounded_frames(client_in, max_line_bytes=max_line_bytes):
        if oversized or frame is None:
            reply: dict[str, Any] | None = _jsonrpc_error(None, JSONRPC_INVALID_REQUEST, "Message too large.")
        else:
            try:
                message = json.loads(frame.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                reply = _jsonrpc_error(None, JSONRPC_PARSE_ERROR, "Malformed JSON-RPC message.")
            else:
                try:
                    reply = gateway.handle_message(message)
                except Exception:  # noqa: BLE001 - contain unexpected errors so the stdio loop fails closed
                    raw_id = message.get("id") if isinstance(message, dict) else None
                    err_id = raw_id if _valid_request_id(raw_id) else None
                    reply = _jsonrpc_error(err_id, JSONRPC_INTERNAL_ERROR, "Internal gateway error (fail-closed).")
        if reply is not None:
            client_out.write(json.dumps(reply) + "\n")
            client_out.flush()
    return 0


def _inside(path: Path, root: Path) -> str | None:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return None


def check_token_caches_outside_workspace(servers: Sequence[Any], workspace_root: Path) -> None:
    """
    Refuse an OAuth token cache inside the agent's workspace.

    Protected paths only stop the agent writing a file, not reading it, and a cache holds live access and refresh
    tokens: an agent that can read one can call the downstream server directly, around the gateway.
    """
    for spec in servers:
        oauth = getattr(spec, "oauth", None)
        cache = getattr(oauth, "token_cache_path", None) if oauth is not None else None
        if cache is not None and _inside(Path(cache), workspace_root) is not None:
            raise ValueError(
                f"Server '{spec.name}' keeps its OAuth token cache inside the workspace ('{cache}'), where the "
                "agent's tools could read it. Move oauth.token_cache_path outside the workspace."
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mellyn Security — MCP stdio JSON-RPC gateway")
    parser.add_argument("--config", type=Path, required=True, help="Gateway or unified config (.toml)")
    parser.add_argument("--workspace", type=Path, default=Path.cwd(), help="Workspace root directory")
    parser.add_argument(
        "--audit-log",
        type=Path,
        default=None,
        help="Append-only hash-chained JSONL audit file (optional if runtime.audit_log is set in mellyn.toml)",
    )
    parser.add_argument(
        "--mode",
        choices=("enforce", "observe"),
        default=None,
        help=(
            "Execution mode (default: enforce). Observe needs this flag AND [runtime].allow_observe_mode = true; "
            "it lets approval-required calls and scanner hits through and logs them, but never relaxes a DENY"
        ),
    )
    parser.add_argument("--approval-port", type=int, default=0, help="Local approval server port (0 = any free)")
    parser.add_argument(
        "--approval-host",
        default="127.0.0.1",
        choices=("127.0.0.1", "0.0.0.0"),  # noqa: S104 - 0.0.0.0 only inside the internal-only container
        help="Bind address for approval server (127.0.0.1 default; 0.0.0.0 inside isolated internal container)",
    )
    parser.add_argument(
        "--gateway-user",
        default=os.environ.get("MELLYN_GATEWAY_USER", "").strip() or None,
        help="POSIX user/UID the gateway drops to after spawning isolated downstream servers",
    )
    parser.add_argument(
        "--downstream-user",
        default=os.environ.get("MELLYN_DOWNSTREAM_USER", "").strip() or None,
        help="Unprivileged POSIX user/UID used for downstream MCP child processes",
    )
    args = parser.parse_args(argv)

    launcher_cwd = Path.cwd()
    try:
        check_no_legacy_env()
        unified = load_mellyn_config(args.config)
        config = unified.gateway
        policy = unified.policy
        check_workspace_root(args.workspace, require_mount=os.environ.get("MELLYN_REQUIRE_WORKSPACE_MOUNT") == "1")
    except (PolicyLoadError, WorkspaceConfigError, LegacyConfigError) as exc:
        print(f"Gateway config, policy or workspace rejected (fail-closed): {exc}", file=sys.stderr)
        return 2

    try:
        effective_mode = resolve_gateway_mode(
            args.mode, config_mode=unified.runtime.mode, allow_observe_mode=unified.runtime.allow_observe_mode
        )
    except ValueError as exc:
        print(f"Observe mode rejected (fail-closed): {exc}", file=sys.stderr)
        return 2
    if unified.runtime.mode == "observe" and effective_mode == "enforce":
        print(
            "Config sets [runtime].mode = 'observe', but observe mode also needs --mode observe; running in enforce.",
            file=sys.stderr,
        )

    raw_audit_path = args.audit_log or unified.runtime.audit_log
    if raw_audit_path is None:
        print("Gateway requires --audit-log (or [runtime].audit_log in mellyn.toml).", file=sys.stderr)
        return 2

    if policy.allowed_mcp_servers is None:
        print("Gateway mode requires 'allowed_mcp_servers' in the policy (fail-closed).", file=sys.stderr)
        return 2
    not_allowed = [s.name for s in config.servers if s.name not in policy.allowed_mcp_servers]
    if not_allowed:
        print(f"Servers not in the policy's allowed_mcp_servers: {not_allowed}", file=sys.stderr)
        return 2

    workspace_root = args.workspace.resolve()
    audit_log_path = raw_audit_path.resolve()

    ds_uid: int | None = None
    ds_gid: int | None = None
    ds_name: str | None = None
    ds_home: str | None = None
    try:
        check_privilege_separation(
            running_as_root=os.name == "posix" and os.geteuid() == 0,
            is_pid1=os.getpid() == 1,
            gateway_user=args.gateway_user,
            downstream_user=args.downstream_user,
        )
        if args.downstream_user is not None:
            if os.name != "posix":
                raise RuntimeError("--downstream-user requires a POSIX platform.")
            ds_uid, ds_gid, ds_name, ds_home = _resolve_posix_account(args.downstream_user)
        if args.gateway_user is not None:
            if os.name != "posix":
                raise RuntimeError("--gateway-user requires a POSIX platform.")
            gw_uid, _, _, _ = _resolve_posix_account(args.gateway_user)
            if ds_uid is not None and ds_uid == gw_uid:
                raise RuntimeError("--downstream-user and --gateway-user must resolve to distinct UIDs.")
    except (KeyError, ValueError, RuntimeError) as exc:
        print(f"Privilege separation configuration rejected (fail-closed): {exc}", file=sys.stderr)
        return 2

    # The agent must never be able to edit the files that control or record its own enforcement.
    protected_inputs: list[Path] = [config.path, config.policy_path, audit_log_path]
    if unified.runtime.state_db is not None:
        state_db_path = unified.runtime.state_db
        protected_inputs.extend(
            [
                state_db_path,
                state_db_path.with_name(f"{state_db_path.name}-wal"),
                state_db_path.with_name(f"{state_db_path.name}-shm"),
            ]
        )
    try:
        check_token_caches_outside_workspace(config.servers, workspace_root)
    except ValueError as exc:
        print(f"Gateway config rejected (fail-closed): {exc}", file=sys.stderr)
        return 2
    own_files = [_inside(p, workspace_root) for p in protected_inputs]
    # The ledger's siblings record or guard it too: `<ledger>.lock` (a directory planted there stops every
    # restart) and the `<ledger>.v1-*` / `.pre-chain-*` files older ledgers are moved aside to.
    ledger_rel = _inside(audit_log_path, workspace_root)
    if ledger_rel:
        own_files.append(f"{ledger_rel}.*")
    policy = dataclasses.replace(policy, protected_paths=(*policy.protected_paths, *[p for p in own_files if p]))

    credentials: CredentialConfig | None = None
    try:
        credentials = CredentialConfig.from_env(roles=frozenset({Role.APPROVER}))
    except CredentialConfigError as exc:
        print(f"Approvals disabled ({exc}); calls needing approval will be denied.", file=sys.stderr)

    approval_server: ApprovalHTTPServer | None = None
    servers: dict[str, Downstream] = {}
    audit_file: IO[str] | None = None
    state_store: SqliteStateStore | None = None
    gateway: MCPGateway | None = None

    def notify_client(message: dict[str, Any]) -> None:
        sys.stdout.write(json.dumps(message) + "\n")
        sys.stdout.flush()

    def on_notification(server: str, message: dict[str, Any]) -> None:
        if gateway is not None:
            gateway.on_downstream_notification(server, message)

    try:
        for spec in config.servers:
            if spec.transport == "stdio":
                servers[spec.name] = StdioDownstream(
                    spec.name,
                    spec.command,
                    cwd=workspace_root,
                    launcher_cwd=launcher_cwd,
                    user=ds_uid,
                    group=ds_gid,
                    child_home=ds_home,
                    child_username=ds_name,
                    on_notification=on_notification,
                    secret_env_names=unified.secret_env_names,
                )
        if args.gateway_user is not None:
            _drop_gateway_privileges(args.gateway_user)
        for spec in config.servers:
            if spec.transport == "streamable-http":
                if spec.url is None:
                    raise RuntimeError(f"Server '{spec.name}' missing URL for streamable-http transport.")
                servers[spec.name] = StreamableHttpDownstream(
                    spec.name,
                    spec.url,
                    oauth_config=spec.oauth,
                    allowed_domains=policy.allowed_egress_domains | unified.gateway_egress_domains,
                    on_notification=on_notification,
                )

        audit_logger, audit_file = AuditLogger.open_chained(
            audit_log_path,
            canary_tokens=unified.scanner.canary_tokens,
            enforcement_mode=effective_mode,
            source="gateway",
        )
        if audit_logger.rotated_legacy_path is not None:
            kind_label = "unchained pre-1.1" if audit_logger.rotated_legacy_format == "pre_chain" else "v1"
            print(
                f"Moved the {kind_label} audit log to {audit_logger.rotated_legacy_path} "
                "and started a new hash-chained log.",
                file=sys.stderr,
            )
        if unified.runtime.state_db is not None:
            state_store = SqliteStateStore(unified.runtime.state_db)

        # One session for the life of the process: no idle expiry, or a client left open overnight would be
        # locked out (the expired session fails closed and the gateway cannot mint a clean one without
        # laundering taint).
        authorizer = Authorizer(
            workspace_root=workspace_root,
            policy_config=policy,
            audit_logger=audit_logger,
            session_ttl_seconds=None,
            state_store=state_store,
        )
        approvals: PendingApprovals | None = None
        if credentials is not None:
            approvals = PendingApprovals(authorizer)
            approval_server = ApprovalHTTPServer(
                approvals, credentials, port=args.approval_port, host=args.approval_host
            )
            approval_server.start_in_background()
            print(f"Approvals: python -m mellyn.approve --url {approval_server.url} list", file=sys.stderr)

        if effective_mode == "observe":
            print(
                "WARNING: mellyn-gateway running in --mode observe "
                "(policy/scanner violations are forwarded and logged, not blocked).",
                file=sys.stderr,
            )

        for srv in servers.values():
            initialize_downstream(srv)
        gateway = MCPGateway(
            authorizer=authorizer,
            servers=servers,
            approvals=approvals,
            notify_client=notify_client,
            scanner_config=unified.scanner,
            mode=effective_mode,
            allow_observe_mode=unified.runtime.allow_observe_mode,
        )
        return run_stdio_proxy(gateway=gateway, client_in=sys.stdin, client_out=sys.stdout)
    except (OSError, RuntimeError, ValueError, AuditChainError, StateStoreError, OAuthError) as exc:
        print(f"Gateway stopped (fail-closed): {exc}", file=sys.stderr)
        return 2
    finally:
        for server in servers.values():
            server.close()
        if approval_server is not None:
            approval_server.shutdown()
            approval_server.server_close()
        if state_store is not None:
            state_store.close()
        if audit_file is not None and not audit_file.closed:
            audit_file.close()


if __name__ == "__main__":
    raise SystemExit(main())
