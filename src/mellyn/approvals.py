"""
Human approval channel for the MCP gateway.

When the authorizer answers REQUIRE_APPROVAL, the gateway records the exact call as a pending approval and
tells the agent its ID. A human lists and approves it through a small HTTP server bound to 127.0.0.1, using
the APPROVER key (see credentials.py), for example with `python -m mellyn.approve`. Approving issues a grant
for that exact call; the agent then retries and the call goes through once (or `max_uses` times).

The agent side of the gateway never holds the approver key, so a prompt-injected agent that can reach the
port (for instance through a shell tool) still cannot approve anything.
"""

from __future__ import annotations

import json
import re
import secrets
import threading
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from mellyn.authorizer import MAX_GRANT_TTL_SECONDS, MAX_GRANT_USES, Authorizer
from mellyn.credentials import CredentialConfig, Role
from mellyn.models import (
    ApprovalGrant,
    AuthorizationResult,
    ToolCallRequest,
    canonical_json,
    effective_mcp_method,
    utc_now,
)

MAX_PENDING = 100
PENDING_TTL_SECONDS = 3600
MAX_BODY_BYTES = 16 * 1024
API_KEY_HEADER = "X-Mellyn-API-Key"
PENDING_LIST_PATH = "/v1/pending"
_APPROVE_PATH = re.compile(r"^/v1/pending/(apr_[A-Za-z0-9_-]{8,64})/(approve|reject)$")


def parse_approval_route(method: str, path: str) -> tuple[str | None, str] | None:
    """
    Parse an exact approval HTTP route shared by the approval server and loopback relay.

    Returns `(None, "list")` for `GET /v1/pending`, `(approval_id, "approve" | "reject")`
    for `POST /v1/pending/apr_.../(approve|reject)`, or `None` for any other method/path.
    """
    if method == "GET" and path == PENDING_LIST_PATH:
        return (None, "list")
    if method == "POST":
        match = _APPROVE_PATH.fullmatch(path)
        if match is not None:
            approval_id, action = match.groups()
            return (approval_id, action)
    return None


class ApprovalRedirectError(urllib.error.URLError):
    """Raised when an approval endpoint responds with a 3xx redirect (never followed)."""

    def __init__(self, code: int) -> None:
        super().__init__(f"Refusing HTTP {code} redirect from approval endpoint.")
        self.code = code


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuses every HTTP redirect so X-Mellyn-API-Key is never forwarded across origins."""

    def http_error_301(self, req: Any, fp: Any, code: int, msg: str, headers: Any) -> Any:
        if fp is not None:
            fp.close()
        raise ApprovalRedirectError(code)

    http_error_302 = http_error_303 = http_error_307 = http_error_308 = http_error_301

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise ApprovalRedirectError(code)


def build_approval_opener(*extra_handlers: urllib.request.BaseHandler) -> urllib.request.OpenerDirector:
    """Build an HTTP opener that disables environment proxies and refuses every 3xx redirect."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirectHandler(), *extra_handlers)


@dataclass(frozen=True)
class PendingApproval:
    approval_id: str
    session_id: str
    mcp_server: str | None
    tool_name: str
    arguments: dict[str, Any]
    reasons: tuple[str, ...]
    audit_id: str
    created_at: datetime = field(default_factory=utc_now)
    mcp_method: str | None = None

    def to_json(self) -> dict[str, Any]:
        data = asdict(self)
        data["reasons"] = list(self.reasons)
        data["created_at"] = self.created_at.isoformat()
        return data


class PendingApprovals:
    """Thread-safe store of calls waiting for a human. Identical calls share one pending entry."""

    def __init__(self, authorizer: Authorizer, *, max_pending: int = MAX_PENDING) -> None:
        self.authorizer = authorizer
        self.max_pending = max_pending
        self._lock = threading.Lock()
        self._pending: dict[str, PendingApproval] = {}

    def add(
        self, request: ToolCallRequest, result: AuthorizationResult, *, now: datetime | None = None
    ) -> PendingApproval:
        check_time = now or utc_now()
        key = (
            request.session_id,
            request.mcp_server,
            effective_mcp_method(request.tool_name, request.mcp_method),
            request.tool_name,
            canonical_json(request.arguments),
        )
        with self._lock:
            self._expire(check_time)
            for existing in self._pending.values():
                if key == (
                    existing.session_id,
                    existing.mcp_server,
                    effective_mcp_method(existing.tool_name, existing.mcp_method),
                    existing.tool_name,
                    canonical_json(existing.arguments),
                ):
                    return existing
            if len(self._pending) >= self.max_pending:
                oldest = min(self._pending.values(), key=lambda p: p.created_at)
                del self._pending[oldest.approval_id]
            pending = PendingApproval(
                approval_id=f"apr_{secrets.token_urlsafe(12)}",
                session_id=request.session_id,
                mcp_server=request.mcp_server,
                tool_name=request.tool_name,
                arguments=dict(request.arguments),
                reasons=result.reasons,
                audit_id=result.audit_id,
                created_at=check_time,
                mcp_method=request.mcp_method,
            )
            self._pending[pending.approval_id] = pending
            return pending

    def list(self, *, now: datetime | None = None) -> list[PendingApproval]:
        with self._lock:
            self._expire(now or utc_now())
            return sorted(self._pending.values(), key=lambda p: p.created_at)

    def approve(
        self,
        approval_id: str,
        *,
        approved_by: str,
        ttl_seconds: int = 900,
        max_uses: int = 1,
        now: datetime | None = None,
    ) -> ApprovalGrant:
        check_time = now or utc_now()
        with self._lock:
            self._expire(check_time)
            pending = self._pending.pop(approval_id)  # KeyError when unknown or expired
        return self.authorizer.issue_grant(
            session_id=pending.session_id,
            tool_name=pending.tool_name,
            mcp_server=pending.mcp_server,
            mcp_method=pending.mcp_method,
            arguments=pending.arguments,
            approved_by=approved_by,
            ttl_seconds=ttl_seconds,
            max_uses=max_uses,
            now=check_time,
        )

    def reject(self, approval_id: str, *, now: datetime | None = None) -> None:
        check_time = now or utc_now()
        with self._lock:
            self._expire(check_time)
            del self._pending[approval_id]

    def _expire(self, now: datetime | None = None) -> None:
        cutoff = (now or utc_now()) - timedelta(seconds=PENDING_TTL_SECONDS)
        for approval_id in [p.approval_id for p in self._pending.values() if p.created_at <= cutoff]:
            del self._pending[approval_id]


class _ApprovalHandler(BaseHTTPRequestHandler):
    server: ApprovalHTTPServer

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - signature fixed by the stdlib
        """Silence the default per-request stderr logging."""

    def _send(self, status: HTTPStatus, body: dict[str, Any]) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _authorized(self) -> bool:
        if not self.server.credentials.verify(self.headers.get(API_KEY_HEADER), Role.APPROVER):
            self._send(HTTPStatus.FORBIDDEN, {"error": "An approver key is required."})
            return False
        return True

    def _read_json(self) -> dict[str, Any] | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if not 0 <= length <= MAX_BODY_BYTES:
            self._send(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "Body missing or too large."})
            return None
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            body = None
        if not isinstance(body, dict):
            self._send(HTTPStatus.BAD_REQUEST, {"error": "Body must be a JSON object."})
            return None
        return body

    def do_GET(self) -> None:  # noqa: N802 - name fixed by the stdlib
        if not self._authorized():
            return
        if parse_approval_route("GET", self.path) is None:
            self._send(HTTPStatus.NOT_FOUND, {"error": "Not found."})
            return
        self._send(HTTPStatus.OK, {"pending": [p.to_json() for p in self.server.approvals.list()]})

    def do_POST(self) -> None:  # noqa: N802 - name fixed by the stdlib
        if not self._authorized():
            return
        parsed_route = parse_approval_route("POST", self.path)
        if parsed_route is None or parsed_route[0] is None:
            self._send(HTTPStatus.NOT_FOUND, {"error": "Not found."})
            return
        body = self._read_json()
        if body is None:
            return
        approval_id, action = parsed_route
        try:
            if action == "reject":
                self.server.approvals.reject(approval_id)
                self._send(HTTPStatus.OK, {"approval_id": approval_id, "rejected": True})
                return
            approved_by = body.get("approved_by")
            ttl_seconds = body.get("ttl_seconds", 900)
            max_uses = body.get("max_uses", 1)
            if not isinstance(approved_by, str) or not 0 < len(approved_by.strip()) <= 128:
                raise ValueError("'approved_by' must be a non-empty string of at most 128 characters.")
            for name, value, limit in (
                ("ttl_seconds", ttl_seconds, MAX_GRANT_TTL_SECONDS),
                ("max_uses", max_uses, MAX_GRANT_USES),
            ):
                if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= limit:
                    raise ValueError(f"'{name}' must be an integer between 1 and {limit}.")
            grant = self.server.approvals.approve(
                approval_id, approved_by=approved_by.strip(), ttl_seconds=ttl_seconds, max_uses=max_uses
            )
        except KeyError:
            self._send(HTTPStatus.NOT_FOUND, {"error": "Unknown or expired approval ID."})
            return
        except ValueError as exc:
            self._send(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        self._send(
            HTTPStatus.OK,
            {
                "approval_id": approval_id,
                "grant_id": grant.grant_id,
                "max_uses": grant.max_uses,
                "expires_at": grant.expires_at.isoformat(),
            },
        )


# 0.0.0.0 is only for the internal-only gateway container (reached through mellyn-approval-relay).
ALLOWED_BIND_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "0.0.0.0"})  # noqa: S104 - see above


class ApprovalHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        approvals: PendingApprovals,
        credentials: CredentialConfig,
        port: int = 0,
        *,
        host: str = "127.0.0.1",
    ) -> None:
        # Loopback by default on bare metal; 0.0.0.0 is used only inside an internal-only container behind
        # mellyn-approval-relay. Either way, Role.APPROVER HMAC verification is what authorizes an approval.
        if host not in ALLOWED_BIND_HOSTS:
            raise ValueError(f"ApprovalHTTPServer host must be one of {sorted(ALLOWED_BIND_HOSTS)}, got '{host}'.")
        super().__init__((host, port), _ApprovalHandler)
        self.approvals = approvals
        self.credentials = credentials

    @property
    def url(self) -> str:
        # Always the loopback form: the approver CLI only talks to loopback, and when the server is bound to
        # 0.0.0.0 inside the gateway container it is reached as 127.0.0.1 there, or through the relay's
        # 127.0.0.1 port on the host.
        return f"http://127.0.0.1:{self.server_address[1]}"

    def start_in_background(self) -> threading.Thread:
        thread = threading.Thread(target=self.serve_forever, name="mellyn-approvals", daemon=True)
        thread.start()
        return thread
