"""
Upstream MCP Streamable HTTP Server (`mellyn serve`) with dual-mode authentication (HMAC & OIDC).

Exposes:
  - `POST /mcp` and `DELETE /mcp` enforcing Mellyn Security policy, session ownership binding,
    cross-tool taint tracking, obfuscated canary/secret scanning, AAD containment, and chained JSONL.
  - `GET /.well-known/oauth-protected-resource` and `GET /.well-known/oauth-protected-resource/mcp`
    publishing RFC 9728 Protected Resource Metadata when `[auth].mode = "oidc"`.
  - `GET /healthz` returning service health after strict `Host` validation.
"""

from __future__ import annotations

import argparse
import dataclasses
import hmac
import json
import os
import re
import sys
import threading
import urllib.parse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import IO, Any

from mellyn.approvals import API_KEY_HEADER, ApprovalHTTPServer, PendingApprovals
from mellyn.audit import AuditChainError, AuditLogger
from mellyn.authorizer import DEFAULT_SESSION_TTL_SECONDS, Authorizer, SessionLimitError
from mellyn.credentials import CredentialConfig, CredentialConfigError, Role
from mellyn.egress import WorkspaceConfigError, check_workspace_root
from mellyn.http_downstream import StreamableHttpDownstream
from mellyn.legacy_env import LegacyConfigError, check_no_legacy_env
from mellyn.mcp_gateway import (
    JSONRPC_INVALID_REQUEST,
    JSONRPC_PARSE_ERROR,
    Downstream,
    MCPGateway,
    StdioDownstream,
    _drop_gateway_privileges,
    _inside,
    _resolve_posix_account,
    check_privilege_separation,
    check_token_caches_outside_workspace,
    initialize_downstream,
    resolve_gateway_mode,
)
from mellyn.models import (
    MAX_LINE_BYTES,
    SUPPORTED_PROTOCOL_VERSIONS,
    jsonrpc_error,
)
from mellyn.notifications import ApprovalWebhookNotifier
from mellyn.oauth_client import OAuthError
from mellyn.oauth_resource import (
    AuthConfig,
    AuthenticatedPrincipal,
    OAuthResourceError,
    OAuthResourceValidator,
    build_protected_resource_metadata,
    build_www_authenticate_challenge,
    normalize_origin,
)
from mellyn.policy import PolicyConfig
from mellyn.policy_loader import PolicyLoadError
from mellyn.scanner import ScannerConfig
from mellyn.state_store import SqliteStateStore, StateStoreError
from mellyn.unified_config import load_mellyn_config

DEFAULT_HTTP_GATEWAY_HOST = "127.0.0.1"
NON_LOOPBACK_HTTP_GATEWAY_HOST = "0.0.0.0"  # noqa: S104 - explicit opt-in via allow_non_loopback=True
ALLOWED_HTTP_GATEWAY_HOSTS: frozenset[str] = frozenset({DEFAULT_HTTP_GATEWAY_HOST, NON_LOOPBACK_HTTP_GATEWAY_HOST})
DEFAULT_HTTP_GATEWAY_PORT = 8000
MAX_HTTP_MCP_BODY_BYTES = MAX_LINE_BYTES

LOOPBACK_HOST_NAMES: frozenset[str] = frozenset({"127.0.0.1", "localhost", "[::1]"})
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_MAX_SESSION_ID_HEADER_CHARS = 256


def _strict_json_object_loads(raw_text: str) -> dict[str, Any]:
    def _reject_dup_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"Duplicate JSON key '{key}' in JSON-RPC request.")
            out[key] = value
        return out

    parsed = json.loads(raw_text, object_pairs_hook=_reject_dup_keys)
    if not isinstance(parsed, dict):
        raise ValueError("MCP HTTP POST body must be a single JSON-RPC object (batch arrays are rejected).")
    return parsed


def _parse_host_header(raw_host: str) -> str | None:
    if not isinstance(raw_host, str):
        return None
    trimmed = raw_host.strip().lower()
    if not trimmed or _CONTROL_CHARS_RE.search(trimmed) or any(ch in trimmed for ch in ("/", "\\", "@", " ")):
        return None
    if trimmed.startswith("["):
        end_bracket = trimmed.find("]")
        if end_bracket <= 1:
            return None
        tail = trimmed[end_bracket + 1 :]
        if tail:
            if not tail.startswith(":") or not tail[1:].isdigit():
                return None
        return trimmed[: end_bracket + 1]
    if ":" in trimmed:
        host_part, _, port_part = trimmed.partition(":")
        if not port_part.isdigit() or ":" in host_part:
            return None
        return host_part.rstrip(".")
    return trimmed.rstrip(".")


def _format_host_for_url(raw_host: str) -> str:
    """Validate and return host[:port] from a checked Host header."""
    trimmed = raw_host.strip().lower()
    if trimmed.startswith("["):
        return trimmed
    return trimmed


_CONTAINED_MESSAGE = "This identity was contained after a canary leak; an operator must restart the gateway."


class PrincipalContainedError(RuntimeError):
    """The authenticated identity was cut off by AAD containment."""


@dataclass
class _SessionEntry:
    gateway: MCPGateway
    owner_subject: str
    lock: threading.Lock = field(default_factory=threading.Lock)


class _HttpGatewayHandler(BaseHTTPRequestHandler):
    server: StreamableHttpGatewayServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        """Silence default per-request stderr logging so bearer tokens never enter console logs."""

    def _apply_security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")

    def _drain_small_unread_body(self) -> None:
        if getattr(self, "_body_consumed", False) or "Transfer-Encoding" in self.headers:
            return
        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            return
        try:
            length = int(raw_len)
        except ValueError:
            return
        if not 0 < length <= 65_536:
            return
        prev_timeout = self.connection.gettimeout()
        try:
            self.connection.settimeout(0.05)
            self.rfile.read(length)
        except OSError:
            pass
        finally:
            with_sock = self.connection
            try:
                with_sock.settimeout(prev_timeout)
            except OSError:
                pass

    def _send_bytes(
        self,
        status: HTTPStatus | int,
        content_type: str,
        payload: bytes,
        *,
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        self.close_connection = True
        self.send_response(int(status))
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self._apply_security_headers()
        if extra_headers:
            for key, val in extra_headers.items():
                self.send_header(key, val)
        self.end_headers()
        if payload:
            self.wfile.write(payload)
        self.wfile.flush()
        if int(status) >= 400:
            self._drain_small_unread_body()

    def _send_empty(
        self,
        status: HTTPStatus | int,
        *,
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        self.close_connection = True
        self.send_response(int(status))
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self._apply_security_headers()
        if extra_headers:
            for key, val in extra_headers.items():
                self.send_header(key, val)
        self.end_headers()
        self.wfile.flush()
        if int(status) >= 400:
            self._drain_small_unread_body()

    def _send_json(
        self,
        status: HTTPStatus | int,
        body: Any,
        *,
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self._send_bytes(status, "application/json; charset=utf-8", payload, extra_headers=extra_headers)

    def _check_host(self) -> str | None:
        raw_host = self.headers.get("Host") or ""
        hostname = _parse_host_header(raw_host)
        if hostname is None or hostname not in self.server.allowed_host_names:
            self._send_json(HTTPStatus.MISDIRECTED_REQUEST, {"error": "Unexpected or missing Host header."})
            return None
        return _format_host_for_url(raw_host)

    def _check_origin(self) -> bool:
        if "Origin" not in self.headers:
            return True
        raw_origin = self.headers.get("Origin") or ""
        try:
            norm = normalize_origin(raw_origin)
        except ValueError:
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "Origin header rejected by policy."})
            return False
        if norm not in self.server.auth_config.allowed_origins:
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "Origin is not in auth.allowed_origins."})
            return False
        return True

    def _base_resource_scheme(self) -> str:
        if self.server.auth_config.allow_insecure_loopback_for_tests:
            return "http"
        return "https"

    def _resource_metadata_url(self, host_port: str) -> str:
        res = self.server.auth_config.resource
        if res is not None:
            parsed = urllib.parse.urlparse(res)
            origin = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
            return f"{origin}/.well-known/oauth-protected-resource/mcp"
        return f"{self._base_resource_scheme()}://{host_port}/.well-known/oauth-protected-resource/mcp"

    def _authenticate(self, host_port: str) -> AuthenticatedPrincipal | None:
        mode = self.server.auth_config.mode
        if mode == "hmac":
            if self.server.credentials is None:
                self._send_json(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {"error": "Agent credentials are not configured on this gateway (fail-closed)."},
                )
                return None
            provided = self.headers.get(API_KEY_HEADER)
            if not provided:
                auth_hdr = self.headers.get("Authorization") or ""
                if auth_hdr.lower().startswith("bearer "):
                    provided = auth_hdr[7:].strip()
            if not provided or not self.server.credentials.verify(provided, Role.AGENT):
                self._send_json(
                    HTTPStatus.UNAUTHORIZED,
                    {"error": "Valid agent API credential is required."},
                    extra_headers={"WWW-Authenticate": "Bearer"},
                )
                return None
            return AuthenticatedPrincipal(
                subject="hmac:agent",
                auth_mode="hmac",
                display_identity="hmac:agent",
                scopes=frozenset(),
                roles=frozenset({Role.AGENT}),
            )

        if self.server.oidc_validator is None:
            self._send_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "OIDC validator is not configured on this gateway (fail-closed)."},
            )
            return None
        prm_url = self._resource_metadata_url(host_port)
        auth_hdr = self.headers.get("Authorization") or ""
        if not auth_hdr.lower().startswith("bearer "):
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "OIDC Bearer token required."},
                extra_headers={"WWW-Authenticate": build_www_authenticate_challenge(prm_url)},
            )
            return None
        raw_token = auth_hdr[7:].strip()
        if not raw_token:
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "Bearer token must not be empty."},
                extra_headers={"WWW-Authenticate": build_www_authenticate_challenge(prm_url)},
            )
            return None
        try:
            principal = self.server.oidc_validator.validate_token(raw_token, require_agent_scopes=True)
        except OAuthResourceError as exc:
            chal = build_www_authenticate_challenge(
                prm_url,
                error=exc.oauth_error,
                scope=exc.required_scope,
            )
            self._send_json(exc.http_status, {"error": str(exc)}, extra_headers={"WWW-Authenticate": chal})
            return None
        if Role.AGENT not in principal.roles:
            # An approver token (or an approver-scoped token from a non-approver) is never an agent token, so the
            # credential that approves held calls cannot also be the one that makes them.
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "This token carries an approver scope; use a separate agent token for /mcp."},
            )
            return None
        return principal

    def _authenticate_agent(self, host_port: str) -> AuthenticatedPrincipal | None:
        """Authenticate the caller, then refuse an identity that AAD containment has cut off."""
        principal = self._authenticate(host_port)
        if principal is None:
            return None
        if self.server.is_principal_contained(principal.subject):
            self._send_json(HTTPStatus.FORBIDDEN, {"error": _CONTAINED_MESSAGE})
            return None
        return principal

    def _read_session_id_header(self) -> tuple[bool, str | None]:
        raw = self.headers.get("Mcp-Session-Id")
        if raw is None:
            return (True, None)
        clean = raw.strip()
        if not clean or len(clean) > _MAX_SESSION_ID_HEADER_CHARS or _CONTROL_CHARS_RE.search(clean):
            return (False, None)
        return (True, clean)

    def _read_json_rpc_body(self) -> dict[str, Any] | None:
        if "Transfer-Encoding" in self.headers:
            self.close_connection = True
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                jsonrpc_error(None, JSONRPC_INVALID_REQUEST, "Transfer-Encoding is not supported."),
            )
            return None
        ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ctype != "application/json":
            self._send_json(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                {"error": "Content-Type must be application/json."},
            )
            return None
        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Content-Length header is required."})
            return None
        try:
            length = int(raw_len)
        except ValueError:
            length = -1
        if length < 0:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid Content-Length header."})
            return None
        if length > MAX_HTTP_MCP_BODY_BYTES:
            self.close_connection = True
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                jsonrpc_error(None, JSONRPC_INVALID_REQUEST, "Request payload exceeds maximum byte limit."),
            )
            return None
        self._body_consumed = True
        raw_bytes = self.rfile.read(length) if length > 0 else b""
        if len(raw_bytes) != length:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                jsonrpc_error(None, JSONRPC_PARSE_ERROR, "Incomplete JSON-RPC request body."),
            )
            return None
        try:
            text = raw_bytes.decode("utf-8")
            return _strict_json_object_loads(text)
        except (UnicodeDecodeError, ValueError) as exc:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                jsonrpc_error(None, JSONRPC_PARSE_ERROR, f"Invalid JSON-RPC payload: {exc}"),
            )
            return None

    def do_GET(self) -> None:  # noqa: N802 - stdlib HTTP dispatch
        host_port = self._check_host()
        if host_port is None:
            return
        if not self._check_origin():
            return
        path = urllib.parse.urlparse(self.path).path

        if path == "/healthz":
            self._send_json(
                HTTPStatus.OK,
                {"status": "ok", "auth_mode": self.server.auth_config.mode},
            )
            return

        if path in ("/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"):
            if self.server.auth_config.mode != "oidc":
                self._send_json(
                    HTTPStatus.NOT_FOUND,
                    {"error": "Protected resource metadata is disabled in hmac mode."},
                )
                return
            meta = build_protected_resource_metadata(
                self.server.auth_config,
                resource_url=f"{self._base_resource_scheme()}://{host_port}/mcp",
            )
            self._send_json(HTTPStatus.OK, meta)
            return

        if path == "/mcp":
            self._send_json(
                HTTPStatus.METHOD_NOT_ALLOWED,
                {"error": "Use POST /mcp or DELETE /mcp."},
                extra_headers={"Allow": "POST, DELETE"},
            )
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})

    def do_POST(self) -> None:  # noqa: N802 - stdlib HTTP dispatch
        host_port = self._check_host()
        if host_port is None:
            return
        if not self._check_origin():
            return
        path = urllib.parse.urlparse(self.path).path
        if path != "/mcp":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})
            return

        principal = self._authenticate_agent(host_port)
        if principal is None:
            return

        sid_ok, session_id = self._read_session_id_header()
        if not sid_ok:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid Mcp-Session-Id header."})
            return

        payload = self._read_json_rpc_body()
        if payload is None:
            return

        method = payload.get("method")
        if method == "initialize":
            if session_id is not None:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "initialize requests must not supply an existing Mcp-Session-Id."},
                )
                return
            try:
                new_sid, entry = self.server.create_session_entry(owner_subject=principal.subject)
            except SessionLimitError as exc:
                self._send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(exc)})
                return
            except PrincipalContainedError:
                self._send_json(HTTPStatus.FORBIDDEN, {"error": _CONTAINED_MESSAGE})
                return
            with entry.lock:
                reply = entry.gateway.handle_message(payload)
            if reply is None:
                self._send_empty(HTTPStatus.ACCEPTED, extra_headers={"Mcp-Session-Id": new_sid})
                return
            proto_ver = SUPPORTED_PROTOCOL_VERSIONS[0]
            if isinstance(reply.get("result"), Mapping):
                neg = reply["result"].get("protocolVersion")
                if isinstance(neg, str) and neg in SUPPORTED_PROTOCOL_VERSIONS:
                    proto_ver = neg
            self._send_json(
                HTTPStatus.OK,
                reply,
                extra_headers={"Mcp-Session-Id": new_sid, "MCP-Protocol-Version": proto_ver},
            )
            return

        if session_id is None:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Mcp-Session-Id header is required."})
            return

        existing, status, err_msg = self.server.resolve_session_entry(session_id, owner_subject=principal.subject)
        if existing is None:
            self._send_json(status, {"error": err_msg})
            return

        with existing.lock:
            reply = existing.gateway.handle_message(payload)
        if reply is None:
            self._send_empty(HTTPStatus.ACCEPTED, extra_headers={"Mcp-Session-Id": session_id})
            return
        self._send_json(HTTPStatus.OK, reply, extra_headers={"Mcp-Session-Id": session_id})

    def do_DELETE(self) -> None:  # noqa: N802 - stdlib HTTP dispatch
        host_port = self._check_host()
        if host_port is None:
            return
        if not self._check_origin():
            return
        path = urllib.parse.urlparse(self.path).path
        if path != "/mcp":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})
            return

        principal = self._authenticate_agent(host_port)
        if principal is None:
            return

        sid_ok, session_id = self._read_session_id_header()
        if not sid_ok or session_id is None:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Valid Mcp-Session-Id header is required."})
            return

        status, err_msg = self.server.delete_session_entry(session_id, owner_subject=principal.subject)
        if status != HTTPStatus.NO_CONTENT:
            self._send_json(status, {"error": err_msg})
            return
        self._send_empty(HTTPStatus.NO_CONTENT)


class StreamableHttpGatewayServer(ThreadingHTTPServer):
    """Fail-closed Streamable HTTP `/mcp` server enforcing AuthN, session isolation, Policy, Scanner, and AAD."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        *,
        authorizer: Authorizer,
        servers: Mapping[str, Downstream],
        auth_config: AuthConfig | None = None,
        credentials: CredentialConfig | None = None,
        oidc_validator: OAuthResourceValidator | None = None,
        approvals: PendingApprovals | None = None,
        scanner_config: ScannerConfig | None = None,
        mode: str = "enforce",
        allow_observe_mode: bool = False,
        host: str = DEFAULT_HTTP_GATEWAY_HOST,
        port: int = 0,
        allow_non_loopback: bool = False,
    ) -> None:
        if host not in ALLOWED_HTTP_GATEWAY_HOSTS:
            raise ValueError(f"HTTP gateway host must be one of {sorted(ALLOWED_HTTP_GATEWAY_HOSTS)}, got '{host}'.")
        if host == NON_LOOPBACK_HTTP_GATEWAY_HOST and not allow_non_loopback:
            raise ValueError(
                f"Binding HTTP gateway to {NON_LOOPBACK_HTTP_GATEWAY_HOST} requires allow_non_loopback=True."
            )
        if mode not in ("enforce", "observe"):
            raise ValueError(f"Unsupported gateway mode {mode!r}; expected 'enforce' or 'observe'.")
        if mode == "observe" and not allow_observe_mode:
            raise ValueError("Observe mode requires explicit allow_observe_mode=True.")
        if not servers:
            raise ValueError("StreamableHttpGatewayServer requires at least one downstream server.")

        resolved_auth = auth_config or AuthConfig()
        eff_validator: OAuthResourceValidator | None
        if resolved_auth.mode == "oidc":
            eff_validator = oidc_validator or OAuthResourceValidator(
                resolved_auth,
                allowed_domains=authorizer.policy.config.allowed_egress_domains,
            )
        else:
            eff_validator = oidc_validator

        allowed_hosts = set(LOOPBACK_HOST_NAMES)
        for item in resolved_auth.allowed_hosts:
            allowed_hosts.add("[::1]" if item == "::1" else item)
        if resolved_auth.resource:
            res_host = (urllib.parse.urlparse(resolved_auth.resource).hostname or "").strip().lower().rstrip(".")
            if res_host:
                allowed_hosts.add(f"[{res_host}]" if ":" in res_host else res_host)

        self.authorizer = authorizer
        self.downstream_servers = dict(servers)
        self.auth_config = resolved_auth
        self.credentials = credentials
        self.oidc_validator = eff_validator
        self.approvals = approvals
        self.scanner_config = scanner_config
        self.mode: Any = mode
        self.allow_observe_mode = allow_observe_mode
        self.allowed_host_names: frozenset[str] = frozenset(allowed_hosts)

        self._registry_lock = threading.Lock()
        self._sessions: dict[str, _SessionEntry] = {}
        # Identities cut off by AAD. In memory only: restarting the gateway is the operator's decision to lift it.
        self._contained_subjects: set[str] = set()

        super().__init__((host, port), _HttpGatewayHandler)

    @property
    def url(self) -> str:
        bound = self.server_address[0]
        bound_host = bound.decode("ascii") if isinstance(bound, bytes) else str(bound)
        host_display = "127.0.0.1" if bound_host == NON_LOOPBACK_HTTP_GATEWAY_HOST else bound_host
        return f"http://{host_display}:{self.server_address[1]}/mcp"

    def is_principal_contained(self, subject: str) -> bool:
        with self._registry_lock:
            return subject in self._contained_subjects

    def _contain_principal(self, subject: str) -> None:
        """
        AAD for a gateway whose downstream servers are shared by every caller.

        Stopping the servers (what the stdio gateway does) would let one caller's canary take down everyone else's
        sessions. Instead the identity that sent the canary is cut off: all of its sessions are severed and it can
        neither open nor resume one until the gateway restarts. Other identities keep working.
        """
        with self._registry_lock:
            self._contained_subjects.add(subject)
            owned = [entry for entry in self._sessions.values() if entry.owner_subject == subject]
        for entry in owned:
            entry.gateway.sever()
        print(f"AAD: contained identity {subject!r}; its MCP sessions are severed.", file=sys.stderr)

    def _build_gateway_for_session(self, session_id: str, owner_subject: str) -> MCPGateway:
        return MCPGateway(
            authorizer=self.authorizer,
            servers=self.downstream_servers,
            approvals=self.approvals,
            notify_client=lambda _msg: None,
            session_id=session_id,
            scanner_config=self.scanner_config,
            mode=self.mode,
            allow_observe_mode=self.allow_observe_mode,
            on_aad=lambda: self._contain_principal(owner_subject),
        )

    def _new_entry(self, session_id: str, owner_subject: str) -> _SessionEntry:
        gateway = self._build_gateway_for_session(session_id, owner_subject)
        return _SessionEntry(gateway=gateway, owner_subject=owner_subject)

    def create_session_entry(self, *, owner_subject: str) -> tuple[str, _SessionEntry]:
        if self.is_principal_contained(owner_subject):
            raise PrincipalContainedError(_CONTAINED_MESSAGE)
        session_id = self.authorizer.create_session(owner_subject=owner_subject)
        entry = self._new_entry(session_id, owner_subject)
        with self._registry_lock:
            if owner_subject in self._contained_subjects:  # contained while this session was being created
                entry.gateway.sever()
            self._sessions[session_id] = entry
        return session_id, entry

    def resolve_session_entry(
        self, session_id: str, *, owner_subject: str
    ) -> tuple[_SessionEntry | None, HTTPStatus, str]:
        snap = self.authorizer.get_session_snapshot(session_id)
        if snap is None:
            with self._registry_lock:
                self._sessions.pop(session_id, None)
            return (None, HTTPStatus.NOT_FOUND, "Unknown or expired MCP session.")
        if snap.owner_subject is None or not hmac.compare_digest(snap.owner_subject, owner_subject):
            return (None, HTTPStatus.FORBIDDEN, "Session belongs to a different authenticated principal.")

        with self._registry_lock:
            if owner_subject in self._contained_subjects:
                return (None, HTTPStatus.FORBIDDEN, _CONTAINED_MESSAGE)
            entry = self._sessions.get(session_id)
            if entry is None:
                entry = self._new_entry(session_id, owner_subject)
                self._sessions[session_id] = entry
            return (entry, HTTPStatus.OK, "")

    def delete_session_entry(self, session_id: str, *, owner_subject: str) -> tuple[HTTPStatus, str]:
        snap = self.authorizer.get_session_snapshot(session_id)
        if snap is None:
            with self._registry_lock:
                self._sessions.pop(session_id, None)
            return (HTTPStatus.NOT_FOUND, "Unknown or expired MCP session.")
        if snap.owner_subject is None or not hmac.compare_digest(snap.owner_subject, owner_subject):
            return (HTTPStatus.FORBIDDEN, "Session belongs to a different authenticated principal.")
        with self._registry_lock:
            self._sessions.pop(session_id, None)
        self.authorizer.delete_session(session_id)
        return (HTTPStatus.NO_CONTENT, "")

    def start_in_background(self) -> threading.Thread:
        thread = threading.Thread(target=self.serve_forever, name="mellyn-http-gateway", daemon=True)
        thread.start()
        return thread


def _positive_int(raw: str) -> int:
    val = int(raw)
    if val <= 0:
        raise argparse.ArgumentTypeError("value must be a positive integer.")
    return val


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Mellyn Security — Upstream MCP Streamable HTTP gateway")
    parser.add_argument(
        "--config", type=Path, required=True, help="Unified mellyn.toml or legacy gateway config (.toml)"
    )
    parser.add_argument("--workspace", type=Path, default=Path.cwd(), help="Workspace root directory")
    parser.add_argument(
        "--host",
        default=DEFAULT_HTTP_GATEWAY_HOST,
        choices=sorted(ALLOWED_HTTP_GATEWAY_HOSTS),
        help="Listen address (127.0.0.1 default; 0.0.0.0 requires --allow-non-loopback)",
    )
    parser.add_argument("--port", type=int, default=DEFAULT_HTTP_GATEWAY_PORT, help="Listen port (default: 8000)")
    parser.add_argument(
        "--allow-non-loopback",
        action="store_true",
        help="Allow binding 0.0.0.0 behind a TLS reverse proxy",
    )
    parser.add_argument(
        "--audit-log",
        type=Path,
        default=None,
        help="Append-only hash-chained JSONL audit file (optional if runtime.audit_log is set in mellyn.toml)",
    )
    parser.add_argument(
        "--state-db",
        type=Path,
        default=None,
        help="Durable SQLite authorizer state file (optional if runtime.state_db is set in mellyn.toml)",
    )
    parser.add_argument(
        "--session-ttl",
        type=_positive_int,
        default=DEFAULT_SESSION_TTL_SECONDS,
        help=f"Idle session TTL in seconds (default: {DEFAULT_SESSION_TTL_SECONDS})",
    )
    parser.add_argument(
        "--mode",
        choices=("enforce", "observe"),
        default=None,
        help="Execution mode (default: enforce; observe requires --mode observe AND allow_observe_mode = true)",
    )
    parser.add_argument("--approval-port", type=int, default=0, help="Local approval server port (0 = any free)")
    parser.add_argument(
        "--approval-host",
        default="127.0.0.1",
        choices=("127.0.0.1", "0.0.0.0"),  # noqa: S104 - 0.0.0.0 only inside isolated internal container
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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for `mellyn serve` / `python -m mellyn.http_gateway`."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    launcher_cwd = Path.cwd()
    try:
        check_no_legacy_env()
        unified = load_mellyn_config(args.config)
        config = unified.gateway
        policy: PolicyConfig = unified.policy
        check_workspace_root(args.workspace, require_mount=os.environ.get("MELLYN_REQUIRE_WORKSPACE_MOUNT") == "1")
        if args.host == NON_LOOPBACK_HTTP_GATEWAY_HOST and not args.allow_non_loopback:
            raise ValueError(
                f"Binding {NON_LOOPBACK_HTTP_GATEWAY_HOST} requires --allow-non-loopback (tls-terminated proxy)."
            )
    except (PolicyLoadError, WorkspaceConfigError, LegacyConfigError, ValueError) as exc:
        print(f"HTTP gateway configuration rejected (fail-closed): {exc}", file=sys.stderr)
        return 2

    try:
        effective_mode = resolve_gateway_mode(
            args.mode, config_mode=unified.runtime.mode, allow_observe_mode=unified.runtime.allow_observe_mode
        )
    except ValueError as exc:
        print(f"Observe mode rejected (fail-closed): {exc}", file=sys.stderr)
        return 2

    raw_audit_path = args.audit_log or unified.runtime.audit_log
    if raw_audit_path is None:
        print("HTTP gateway requires --audit-log (or [runtime].audit_log in mellyn.toml).", file=sys.stderr)
        return 2
    raw_state_db = args.state_db or unified.runtime.state_db

    if policy.allowed_mcp_servers is None:
        print("HTTP gateway requires 'allowed_mcp_servers' in the policy (fail-closed).", file=sys.stderr)
        return 2
    not_allowed = [s.name for s in config.servers if s.name not in policy.allowed_mcp_servers]
    if not_allowed:
        print(f"Servers not in the policy's allowed_mcp_servers: {not_allowed}", file=sys.stderr)
        return 2

    workspace_root = args.workspace.resolve()
    audit_log_path = raw_audit_path.resolve()

    ds_uid: int | None = None
    ds_gid: int | None = None
    ds_home: str | None = None
    ds_name: str | None = None
    try:
        check_token_caches_outside_workspace(config.servers, workspace_root)
        # Same checks as the stdio gateway. This call used to pass the server list positionally and omit is_pid1,
        # so `mellyn serve` died with a TypeError before it could start.
        check_privilege_separation(
            running_as_root=os.name == "posix" and os.geteuid() == 0,
            is_pid1=os.getpid() == 1,
            gateway_user=args.gateway_user,
            downstream_user=args.downstream_user,
        )
        if args.downstream_user is not None:
            if os.name != "posix":
                raise RuntimeError("--downstream-user requires a POSIX platform.")
            # _resolve_posix_account returns (uid, gid, name, home); the swapped order gave servers HOME=<username>.
            ds_uid, ds_gid, ds_name, ds_home = _resolve_posix_account(args.downstream_user)
        if args.gateway_user is not None:
            if os.name != "posix":
                raise RuntimeError("--gateway-user requires a POSIX platform.")
            gw_uid, _, _, _ = _resolve_posix_account(args.gateway_user)
            if ds_uid is not None and ds_uid == gw_uid:
                raise RuntimeError("--downstream-user and --gateway-user must resolve to distinct UIDs.")
    except (KeyError, ValueError, RuntimeError) as exc:
        print(f"HTTP gateway privilege/config check failed (fail-closed): {exc}", file=sys.stderr)
        return 2

    protected_inputs: list[Path] = [config.path, config.policy_path, audit_log_path]
    if raw_state_db is not None:
        protected_inputs.extend(
            [
                raw_state_db,
                raw_state_db.with_name(f"{raw_state_db.name}-wal"),
                raw_state_db.with_name(f"{raw_state_db.name}-shm"),
            ]
        )
    for spec in config.servers:
        if spec.oauth is not None and spec.oauth.token_cache_path is not None:
            protected_inputs.append(spec.oauth.token_cache_path)
    own_files = [_inside(p, workspace_root) for p in protected_inputs]
    policy = dataclasses.replace(policy, protected_paths=(*policy.protected_paths, *[p for p in own_files if p]))

    agent_credentials: CredentialConfig | None = None
    approver_credentials: CredentialConfig | None = None
    if unified.auth.mode == "hmac":
        try:
            agent_credentials = CredentialConfig.from_env(roles=frozenset({Role.AGENT}))
        except CredentialConfigError as exc:
            print(f"HTTP gateway [auth].mode='hmac' missing agent credentials (fail-closed): {exc}", file=sys.stderr)
            return 2
        try:
            approver_credentials = CredentialConfig.from_env(roles=frozenset({Role.APPROVER}))
        except CredentialConfigError as exc:
            print(f"Approvals disabled ({exc}); calls needing approval will be denied.", file=sys.stderr)
    else:
        try:
            approver_credentials = CredentialConfig.from_env(roles=frozenset({Role.APPROVER}))
        except CredentialConfigError:
            approver_credentials = None

    oidc_validator: OAuthResourceValidator | None = None
    if unified.auth.mode == "oidc":
        oidc_validator = OAuthResourceValidator(
            unified.auth,
            allowed_domains=unified.gateway_egress_domains,
        )

    approval_server: ApprovalHTTPServer | None = None
    notifier: ApprovalWebhookNotifier | None = None
    http_server: StreamableHttpGatewayServer | None = None
    servers: dict[str, Downstream] = {}
    audit_file: IO[str] | None = None
    state_store: SqliteStateStore | None = None

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
                    allowed_domains=policy.allowed_egress_domains,
                )

        audit_logger, audit_file = AuditLogger.open_chained(
            audit_log_path,
            canary_tokens=unified.scanner.canary_tokens,
            enforcement_mode=effective_mode,
        )
        if raw_state_db is not None:
            state_store = SqliteStateStore(raw_state_db)

        authorizer = Authorizer(
            workspace_root=workspace_root,
            policy_config=policy,
            audit_logger=audit_logger,
            session_ttl_seconds=args.session_ttl,
            state_store=state_store,
        )
        approvals: PendingApprovals | None = None
        if approver_credentials is not None or oidc_validator is not None:
            if unified.notifications.enabled:
                notifier = ApprovalWebhookNotifier(
                    unified.notifications,
                    allowed_domains=unified.gateway_egress_domains,
                    canary_tokens=unified.scanner.canary_tokens,
                )
            approvals = PendingApprovals(
                authorizer,
                on_new_pending=notifier.on_new_pending if notifier is not None else None,
            )
            approval_server = ApprovalHTTPServer(
                approvals,
                approver_credentials,
                port=args.approval_port,
                host=args.approval_host,
                oidc_validator=oidc_validator,
            )
            approval_server.start_in_background()
            print(f"Approvals endpoint: {approval_server.url}", file=sys.stderr)

        for srv in servers.values():
            initialize_downstream(srv)

        http_server = StreamableHttpGatewayServer(
            authorizer=authorizer,
            servers=servers,
            auth_config=unified.auth,
            credentials=agent_credentials,
            oidc_validator=oidc_validator,
            approvals=approvals,
            scanner_config=unified.scanner,
            mode=effective_mode,
            allow_observe_mode=unified.runtime.allow_observe_mode,
            host=args.host,
            port=args.port,
            allow_non_loopback=args.allow_non_loopback,
        )
        print(f"Mellyn Streamable HTTP MCP gateway listening on {http_server.url}", file=sys.stderr)
        try:
            http_server.serve_forever()
        except KeyboardInterrupt:
            pass
        return 0
    except (OSError, RuntimeError, ValueError, AuditChainError, StateStoreError, OAuthError) as exc:
        print(f"HTTP gateway stopped (fail-closed): {exc}", file=sys.stderr)
        return 2
    finally:
        if http_server is not None:
            http_server.server_close()
        for server in servers.values():
            server.close()
        if approval_server is not None:
            approval_server.shutdown()
            approval_server.server_close()
        if notifier is not None:
            notifier.close()
        if state_store is not None:
            state_store.close()
        if audit_file is not None and not audit_file.closed:
            audit_file.close()


__all__ = [
    "ALLOWED_HTTP_GATEWAY_HOSTS",
    "DEFAULT_HTTP_GATEWAY_HOST",
    "DEFAULT_HTTP_GATEWAY_PORT",
    "LOOPBACK_HOST_NAMES",
    "MAX_HTTP_MCP_BODY_BYTES",
    "NON_LOOPBACK_HTTP_GATEWAY_HOST",
    "StreamableHttpGatewayServer",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
