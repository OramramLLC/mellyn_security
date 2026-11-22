"""
MCP JSON-RPC 2.0 Security Gateway for Mellyn Security (AegisAI).

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
    python -m aegis_ai.mcp_gateway --config config/mellyn-gateway.example.toml \
        --workspace . --audit-log mellyn-audit.jsonl [--approval-port 8765]
"""

from __future__ import annotations

import argparse
import dataclasses
import itertools
import json
import os
import queue
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol, TextIO

from aegis_ai.approvals import ApprovalHTTPServer, PendingApprovals
from aegis_ai.audit import AuditLogger
from aegis_ai.authorizer import RESOURCE_READ_TOOL, Authorizer
from aegis_ai.credentials import CredentialConfig, CredentialConfigError, Role
from aegis_ai.egress import WorkspaceConfigError, check_workspace_root
from aegis_ai.gateway_config import load_gateway_config
from aegis_ai.models import Decision, TaintSource, ToolCallRequest, canonical_json
from aegis_ai.policy_loader import PolicyLoadError, load_policy_file

MAX_ARGUMENTS_BYTES = 64 * 1024
MAX_LINE_BYTES = 4 * 1024 * 1024
MAX_LIST_PAGES = 20
DOWNSTREAM_TIMEOUT_SECONDS = 60.0
INIT_TIMEOUT_SECONDS = 30.0
TOOL_SEPARATOR = "__"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
GATEWAY_INFO = {"name": "mellyn-gateway", "version": "0.1.0"}

# JSON-RPC 2.0 standard and Mellyn Security gateway error codes
JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
DOWNSTREAM_ERROR = -32000
MELLYN_APPROVAL_REQUIRED = -32001
MELLYN_POLICY_DENIED = -32003

# Content-free notifications that are safe to pass from a downstream server to the client.
FORWARDED_SERVER_NOTIFICATIONS = frozenset({"notifications/tools/list_changed", "notifications/resources/list_changed"})


def _jsonrpc_error(req_id: Any, code: int, message: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    error_body: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error_body["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": error_body}


def _jsonrpc_result(req_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


class Downstream(Protocol):
    """One downstream MCP server, as the gateway sees it."""

    name: str

    def request(
        self, method: str, params: dict[str, Any], timeout: float = DOWNSTREAM_TIMEOUT_SECONDS
    ) -> dict[str, Any]:
        """Send a request and return the JSON-RPC response with the matching ID (or a gateway error)."""
        ...

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None: ...

    def close(self) -> None: ...


_EOF = object()


SECRET_ENV_PREFIXES = ("AEGIS_", "MELLYN_")


def downstream_environment(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """
    The environment for downstream MCP servers: the gateway's own, minus every AEGIS_* and MELLYN_* variable.
    The pepper and key digests are the gateway's secrets; the servers it launches are untrusted and must not see
    them. MELLYN_* is stripped too because the product was renamed: a deployment may set its secrets under the
    new prefix even though the code reads AEGIS_*.
    """
    source = os.environ if environ is None else environ
    return {key: value for key, value in source.items() if not key.upper().startswith(SECRET_ENV_PREFIXES)}


class StdioDownstream:
    """
    A downstream MCP server launched as a subprocess (argv list, no shell) and spoken to over stdio.

    A reader thread parses each stdout line into a queue. `request` uses its own IDs and returns only the
    response carrying that ID; anything else that arrives meanwhile is handled, not returned:
    notifications go to `on_notification`, server-to-client requests are refused, malformed or oversized
    lines are dropped. The server's stderr goes to `stderr`, never to the audit log.
    """

    def __init__(
        self,
        name: str,
        argv: Sequence[str],
        *,
        on_notification: Callable[[str, dict[str, Any]], None] | None = None,
        stderr: TextIO | None = None,
    ) -> None:
        self.name = name
        self.on_notification = on_notification or (lambda _server, _msg: None)
        self._ids = itertools.count(1)
        self._inbox: queue.Queue[Any] = queue.Queue()
        self._write_lock = threading.Lock()
        self.proc = subprocess.Popen(  # noqa: S603 - argv list validated by gateway_config; never a shell
            list(argv),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr if stderr is not None else sys.stderr,
            env=downstream_environment(),
        )
        self._reader = threading.Thread(target=self._read_loop, name=f"mcp-{name}-reader", daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        stdout = self.proc.stdout
        if stdout is None:
            self._inbox.put(_EOF)
            return
        while True:
            line = stdout.readline(MAX_LINE_BYTES + 1)
            if not line:
                break
            if len(line) > MAX_LINE_BYTES and not line.endswith(b"\n"):
                while line and not line.endswith(b"\n"):  # discard the rest of an oversized line
                    line = stdout.readline(MAX_LINE_BYTES + 1)
                continue
            try:
                self._inbox.put(json.loads(line.decode("utf-8")))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
        self._inbox.put(_EOF)

    def _write(self, message: dict[str, Any]) -> bool:
        stdin = self.proc.stdin
        if stdin is None:
            return False
        try:
            with self._write_lock:
                stdin.write((json.dumps(message) + "\n").encode("utf-8"))
                stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            return False
        return True

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self._write(message)

    def request(
        self, method: str, params: dict[str, Any], timeout: float = DOWNSTREAM_TIMEOUT_SECONDS
    ) -> dict[str, Any]:
        req_id = f"mellyn-{next(self._ids)}"
        if not self._write({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}):
            return _jsonrpc_error(req_id, DOWNSTREAM_ERROR, f"Downstream server '{self.name}' is not accepting input.")
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return _jsonrpc_error(req_id, DOWNSTREAM_ERROR, f"Downstream server '{self.name}' timed out.")
            try:
                message = self._inbox.get(timeout=remaining)
            except queue.Empty:
                continue
            if message is _EOF:
                self._inbox.put(_EOF)  # keep reporting closed to later requests
                return _jsonrpc_error(req_id, DOWNSTREAM_ERROR, f"Downstream server '{self.name}' closed.")
            if not isinstance(message, dict):
                continue
            if isinstance(message.get("method"), str):
                if "id" in message:  # server-to-client request (sampling, elicitation, roots): refuse
                    self._write(_jsonrpc_error(message["id"], JSONRPC_METHOD_NOT_FOUND, "Not permitted by gateway."))
                else:
                    self.on_notification(self.name, message)
                continue
            if message.get("id") == req_id:
                return message
            # A response to some earlier, timed-out request: drop it.

    def close(self) -> None:
        try:
            if self.proc.stdin is not None:
                self.proc.stdin.close()
        except OSError:
            pass
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        self._reader.join(timeout=5)
        if self.proc.stdout is not None:
            self.proc.stdout.close()


def initialize_downstream(server: Downstream, timeout: float = INIT_TIMEOUT_SECONDS) -> None:
    """Run the MCP handshake with a downstream server. Raises RuntimeError if it fails."""
    response = server.request(
        "initialize",
        {"protocolVersion": SUPPORTED_PROTOCOL_VERSIONS[0], "capabilities": {}, "clientInfo": GATEWAY_INFO},
        timeout=timeout,
    )
    if not isinstance(response.get("result"), dict):
        raise RuntimeError(f"Downstream server '{server.name}' failed to initialize: {response.get('error')}")
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
    ) -> None:
        if not servers:
            raise ValueError("The gateway needs at least one downstream server.")
        for name in servers:
            if TOOL_SEPARATOR in name or not name:
                raise ValueError(f"Server name '{name}' must not be empty or contain '{TOOL_SEPARATOR}'.")
        self.authorizer = authorizer
        self.servers = dict(servers)
        self.approvals = approvals
        self.notify_client = notify_client or (lambda _msg: None)
        self.session_id = session_id or authorizer.create_session()
        self._resource_owner: dict[str, str | None] = {}  # uri -> server (None when two servers claim it)

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
        method = message.get("method")
        if not isinstance(method, str) or not method:
            return _jsonrpc_error(message.get("id"), JSONRPC_INVALID_REQUEST, "Missing or invalid 'method'.")
        if "id" not in message:
            return None  # client notifications (initialized, cancelled, ...) need no reply; nothing is executed
        req_id = message["id"]
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
        cursor: str | None = None
        for _ in range(MAX_LIST_PAGES):
            response = server.request(method, {"cursor": cursor} if cursor else {})
            result = response.get("result")
            if not isinstance(result, dict):
                break
            items.extend(item for item in result.get(key, []) if isinstance(item, dict))
            cursor = result.get("nextCursor") if isinstance(result.get("nextCursor"), str) else None
            if not cursor:
                break
        return items

    def _tools_list(self, req_id: Any, _params: dict[str, Any]) -> dict[str, Any]:
        tools: list[dict[str, Any]] = []
        for name, server in self.servers.items():
            listed = [t for t in self._list_all(server, "tools/list", "tools") if _valid_name(t.get("name"))]
            for tool in listed:
                tools.append({**tool, "name": f"{name}{TOOL_SEPARATOR}{tool['name']}"})
            if listed:
                self._taint_from(name, "mcp_tool_descriptions")
        return _jsonrpc_result(req_id, {"tools": tools})

    def _resources_list(self, req_id: Any, _params: dict[str, Any]) -> dict[str, Any]:
        resources: list[dict[str, Any]] = []
        owners: dict[str, str | None] = {}
        for name, server in self.servers.items():
            listed = [r for r in self._list_all(server, "resources/list", "resources") if isinstance(r.get("uri"), str)]
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
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            return _jsonrpc_error(req_id, JSONRPC_INVALID_PARAMS, "tools/call 'arguments' must be a JSON object.")
        if len(canonical_json(arguments).encode("utf-8")) > MAX_ARGUMENTS_BYTES:
            return _jsonrpc_error(req_id, JSONRPC_INVALID_PARAMS, "tools/call 'arguments' exceed 64 KiB.")

        request = ToolCallRequest(self.session_id, tool_name, arguments, mcp_server=server_name)
        blocked = self._authorize(req_id, request)
        if blocked is not None:
            return blocked
        # Forward exactly what was authorized, rebuilt from validated fields.
        response = self.servers[server_name].request("tools/call", {"name": tool_name, "arguments": arguments})
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
        request = ToolCallRequest(self.session_id, RESOURCE_READ_TOOL, {"uri": uri}, mcp_server=server_name)
        blocked = self._authorize(req_id, request)
        if blocked is not None:
            return blocked
        return _relay(req_id, self.servers[server_name].request("resources/read", {"uri": uri}))

    def _authorize(self, req_id: Any, request: ToolCallRequest) -> dict[str, Any] | None:
        """Return None when the call may proceed, otherwise the JSON-RPC error to send back."""
        result = self.authorizer.authorize(request)
        if result.decision == Decision.ALLOW:
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


def _valid_name(name: Any) -> bool:
    return isinstance(name, str) and 0 < len(name) <= 128 and name.isprintable() and not name.isspace()


def _relay(req_id: Any, response: dict[str, Any]) -> dict[str, Any]:
    """Re-address a downstream response to the client's request ID, keeping only result or a sanitized error."""
    if "result" in response:
        return _jsonrpc_result(req_id, response["result"])
    error = response.get("error") if isinstance(response.get("error"), dict) else {}
    code = error.get("code") if isinstance(error.get("code"), int) else DOWNSTREAM_ERROR
    message = error.get("message") if isinstance(error.get("message"), str) else "Downstream server error."
    return _jsonrpc_error(req_id, code, message[:1000])


def run_stdio_proxy(*, gateway: MCPGateway, client_in: TextIO, client_out: TextIO) -> int:
    """Read newline-delimited JSON-RPC messages from client_in and write replies to client_out."""
    for raw_line in client_in:
        line = raw_line.strip()
        if not line:
            continue
        if len(line) > MAX_LINE_BYTES:
            reply: dict[str, Any] | None = _jsonrpc_error(None, JSONRPC_INVALID_REQUEST, "Message too large.")
        else:
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                reply = _jsonrpc_error(None, JSONRPC_PARSE_ERROR, "Malformed JSON-RPC message.")
            else:
                reply = gateway.handle_message(message)
        if reply is not None:
            client_out.write(json.dumps(reply) + "\n")
            client_out.flush()
    return 0


def _inside(path: Path, root: Path) -> str | None:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mellyn Security — MCP stdio JSON-RPC gateway")
    parser.add_argument("--config", type=Path, required=True, help="Gateway config (.toml) listing the servers")
    parser.add_argument("--workspace", type=Path, default=Path.cwd(), help="Workspace root directory")
    parser.add_argument("--audit-log", type=Path, required=True, help="Append-only JSONL audit file")
    parser.add_argument("--approval-port", type=int, default=0, help="Local approval server port (0 = any free)")
    args = parser.parse_args(argv)

    try:
        config = load_gateway_config(args.config)
        policy = load_policy_file(config.policy_path)
        check_workspace_root(args.workspace, require_mount=os.environ.get("AEGIS_REQUIRE_WORKSPACE_MOUNT") == "1")
    except (PolicyLoadError, WorkspaceConfigError) as exc:
        print(f"Gateway config, policy or workspace rejected (fail-closed): {exc}", file=sys.stderr)
        return 2
    if policy.allowed_mcp_servers is None:
        print("Gateway mode requires 'allowed_mcp_servers' in the policy (fail-closed).", file=sys.stderr)
        return 2
    not_allowed = [s.name for s in config.servers if s.name not in policy.allowed_mcp_servers]
    if not_allowed:
        print(f"Servers not in the policy's allowed_mcp_servers: {not_allowed}", file=sys.stderr)
        return 2

    # The agent must never be able to edit the files that control or record its own enforcement.
    own_files = [_inside(p, args.workspace) for p in (config.path, config.policy_path, args.audit_log)]
    policy = dataclasses.replace(policy, protected_paths=(*policy.protected_paths, *[p for p in own_files if p]))

    approval_server: ApprovalHTTPServer | None = None
    servers: dict[str, StdioDownstream] = {}
    with args.audit_log.open("a", encoding="utf-8") as audit_file:
        # One session for the life of the process: no idle expiry, or a client left open overnight would be
        # locked out (the expired session fails closed and the gateway cannot mint a clean one without
        # laundering taint).
        authorizer = Authorizer(
            workspace_root=args.workspace,
            policy_config=policy,
            audit_logger=AuditLogger(audit_file),
            session_ttl_seconds=None,
        )
        approvals = PendingApprovals(authorizer)
        try:
            credentials = CredentialConfig.from_env(roles=frozenset({Role.APPROVER}))
        except CredentialConfigError as exc:
            print(f"Approvals disabled ({exc}); calls needing approval will be denied.", file=sys.stderr)
            approvals = None
        else:
            approval_server = ApprovalHTTPServer(approvals, credentials, port=args.approval_port)
            approval_server.start_in_background()
            print(f"Approvals: python -m aegis_ai.approve --url {approval_server.url} list", file=sys.stderr)

        def notify_client(message: dict[str, Any]) -> None:
            sys.stdout.write(json.dumps(message) + "\n")
            sys.stdout.flush()

        gateway: MCPGateway | None = None

        def on_notification(server: str, message: dict[str, Any]) -> None:
            if gateway is not None:
                gateway.on_downstream_notification(server, message)

        try:
            for spec in config.servers:
                servers[spec.name] = StdioDownstream(spec.name, spec.command, on_notification=on_notification)
                initialize_downstream(servers[spec.name])
            gateway = MCPGateway(
                authorizer=authorizer, servers=servers, approvals=approvals, notify_client=notify_client
            )
            return run_stdio_proxy(gateway=gateway, client_in=sys.stdin, client_out=sys.stdout)
        except (OSError, RuntimeError) as exc:
            print(f"Gateway stopped (fail-closed): {exc}", file=sys.stderr)
            return 2
        finally:
            for server in servers.values():
                server.close()
            if approval_server is not None:
                approval_server.shutdown()
                approval_server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
