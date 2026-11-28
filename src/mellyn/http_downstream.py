"""
Fail-closed MCP Streamable HTTP downstream transport (`transport = "streamable-http"`).

Implements the gateway `Downstream` protocol over outbound HTTPS POST + Server-Sent Events (SSE),
with OAuth 2.1 token acquisition (`OAuthTokenProvider`), `Mcp-Session-Id` propagation, strict duplicate-key
JSON parsing, bounded SSE framing, zero HTTP redirects, Squid proxy support, and immediate AAD termination.
"""

from __future__ import annotations

import itertools
import json
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

from mellyn.core.strict_input import strict_json_loads as _strict_json_loads
from mellyn.models import (
    DOWNSTREAM_TIMEOUT_SECONDS,
    MAX_LINE_BYTES,
    SUPPORTED_PROTOCOL_VERSIONS,
    local_downstream_error,
)
from mellyn.oauth_client import (
    OAuthClientConfig,
    OAuthError,
    OAuthTokenProvider,
    _apply_stream_deadline,
    build_safe_opener,
    read_bounded_bytes,
    validate_outbound_url,
)

DEFAULT_MAX_SSE_EVENTS = 256
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_MAX_SESSION_ID_CHARS = 256
_AAD_DELETE_TIMEOUT_SECONDS = 1.0


def _valid_reply_shape(response: Any, expected_id: Any) -> bool:
    if not isinstance(response, dict):
        return False
    resp_id = response.get("id")
    if isinstance(resp_id, bool) or type(resp_id) is not type(expected_id) or resp_id != expected_id:
        return False
    if response.get("jsonrpc") != "2.0":
        return False
    has_result = "result" in response
    has_error = "error" in response
    if has_result == has_error:
        return False
    if has_error and not isinstance(response.get("error"), dict):
        return False
    return True


def _report_detail(server_name: str, what: str, exc: BaseException) -> None:
    """
    Send the full error to the operator's stderr, never to the agent.

    Gateway-authored errors (GatewayLocalError) do not taint the session, so the text the agent receives must be
    fixed. Exception messages here can carry server-written text: a Content-Type value, a duplicate JSON key name,
    an OAuth error code. Relaying that would let a server inject instructions without tainting anything.
    """
    print(f"mellyn-gateway: {what} for downstream server '{server_name}': {exc}", file=sys.stderr)


def _validate_session_id(raw_value: str) -> str:
    clean = raw_value.strip()
    if not clean or len(clean) > _MAX_SESSION_ID_CHARS or _CONTROL_CHARS_RE.search(clean):
        raise ValueError("Downstream server returned an invalid Mcp-Session-Id header.")
    return clean


class StreamableHttpDownstream:
    """
    Remote downstream MCP server reached over Streamable HTTP (POST JSON-RPC + bounded SSE streaming).

    Satisfies the same `Downstream` contract as `StdioDownstream`, including immediate `kill_now()`
    containment (severs transport, wipes OAuth tokens, and attempts `DELETE` on `Mcp-Session-Id`).
    """

    def __init__(
        self,
        name: str,
        url: str,
        *,
        oauth_config: OAuthClientConfig | None = None,
        oauth_provider: OAuthTokenProvider | None = None,
        allowed_domains: frozenset[str] | None = None,
        on_notification: Callable[[str, dict[str, Any]], None] | None = None,
        proxy_url: str | None = None,
        max_response_bytes: int = MAX_LINE_BYTES,
        max_sse_events: int = DEFAULT_MAX_SSE_EVENTS,
        ssl_context: ssl.SSLContext | None = None,
        _allow_loopback_http: bool = False,
    ) -> None:
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive.")
        if max_sse_events <= 0:
            raise ValueError("max_sse_events must be positive.")
        self.name = name
        self._allow_loopback_http = _allow_loopback_http
        self.url = validate_outbound_url(
            url,
            allowed_domains=allowed_domains,
            allow_loopback_http=_allow_loopback_http,
        )
        self.allowed_domains = allowed_domains
        self.on_notification = on_notification or (lambda _server, _msg: None)
        self._max_response_bytes = max_response_bytes
        self._max_sse_events = max_sse_events
        self._opener = build_safe_opener(
            proxy_url=proxy_url,
            ssl_context=ssl_context,
            bypass_ambient_proxy=_allow_loopback_http and proxy_url is None,
        )
        if oauth_provider is not None:
            self.oauth_provider: OAuthTokenProvider | None = oauth_provider
        elif oauth_config is not None:
            self.oauth_provider = OAuthTokenProvider(
                oauth_config,
                resource_url=self.url,
                allowed_domains=allowed_domains,
                proxy_url=proxy_url,
                ssl_context=ssl_context,
                _allow_loopback_http=_allow_loopback_http,
            )
        else:
            self.oauth_provider = None

        self._lock = threading.Lock()
        self._ids = itertools.count(1)
        self._session_id: str | None = None
        self._protocol_version: str = SUPPORTED_PROTOCOL_VERSIONS[0]
        self._severed = False
        self._closed = False

    def _next_id(self) -> int:
        return next(self._ids)

    def _build_headers(
        self, *, session_id: str | None, protocol_version: str, auth_header: str | None
    ) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": protocol_version,
        }
        if session_id is not None:
            headers["Mcp-Session-Id"] = session_id
        if auth_header is not None:
            headers["Authorization"] = auth_header
        return headers

    def _dispatch_sse_event(self, payload_text: str, *, req_id: Any) -> dict[str, Any] | None:
        if not payload_text.strip():
            return None
        parsed = _strict_json_loads(payload_text)
        if not isinstance(parsed, dict):
            raise ValueError("SSE data frame did not decode to a JSON object.")
        if parsed.get("jsonrpc") != "2.0":
            raise ValueError("SSE frame missing jsonrpc='2.0'.")
        has_method = isinstance(parsed.get("method"), str)
        if has_method and "id" not in parsed:
            self.on_notification(self.name, parsed)
            return None
        if has_method and "id" in parsed:
            # Server-initiated requests (sampling/elicitation/roots) are silently dropped.
            return None
        if _valid_reply_shape(parsed, req_id):
            return parsed
        return None

    def _read_sse_reply(self, resp: Any, *, req_id: Any, deadline: float) -> dict[str, Any]:
        total_bytes = 0
        event_count = 0
        data_lines: list[str] = []
        buf = bytearray()
        eof = False
        read_fn = getattr(resp, "read1", None)
        if not callable(read_fn):
            read_fn = resp.read

        def _next_line() -> bytes:
            nonlocal total_bytes, eof
            while True:
                nl = buf.find(b"\n")
                if nl >= 0:
                    line_bytes = bytes(buf[: nl + 1])
                    del buf[: nl + 1]
                    return line_bytes
                if eof:
                    line_bytes = bytes(buf)
                    buf.clear()
                    return line_bytes
                _apply_stream_deadline(resp, deadline)
                remaining_budget = self._max_response_bytes - total_bytes - len(buf) + 1
                if remaining_budget <= 0:
                    raise ValueError(f"SSE stream from '{self.name}' exceeded max_response_bytes.")
                chunk = read_fn(min(4_096, remaining_budget))
                if not chunk:
                    eof = True
                else:
                    if total_bytes + len(buf) + len(chunk) > self._max_response_bytes:
                        raise ValueError(f"SSE stream from '{self.name}' exceeded max_response_bytes.")
                    buf.extend(chunk)

        while True:
            _apply_stream_deadline(resp, deadline)
            raw_line = _next_line()
            if not raw_line:
                if data_lines:
                    event_count += 1
                    if event_count > self._max_sse_events:
                        raise ValueError(f"SSE stream from '{self.name}' exceeded max_sse_events.")
                    reply = self._dispatch_sse_event("\n".join(data_lines), req_id=req_id)
                    if reply is not None:
                        return reply
                raise ValueError(f"Downstream SSE stream '{self.name}' closed before replying to id={req_id}.")

            total_bytes += len(raw_line)
            if total_bytes > self._max_response_bytes:
                raise ValueError(f"SSE stream from '{self.name}' exceeded max_response_bytes.")

            try:
                line = raw_line.decode("utf-8").rstrip("\r\n")
            except UnicodeDecodeError as exc:
                raise ValueError(f"Invalid UTF-8 bytes in SSE stream from '{self.name}'.") from exc

            if line == "":
                if data_lines:
                    event_count += 1
                    if event_count > self._max_sse_events:
                        raise ValueError(f"SSE stream from '{self.name}' exceeded max_sse_events.")
                    payload_text = "\n".join(data_lines)
                    data_lines.clear()
                    reply = self._dispatch_sse_event(payload_text, req_id=req_id)
                    if reply is not None:
                        return reply
                continue
            if line.startswith(":"):
                continue
            if ":" in line:
                field_name, _, val = line.partition(":")
                if val.startswith(" "):
                    val = val[1:]
                if field_name == "data":
                    data_lines.append(val)
            elif line == "data":
                data_lines.append("")

    def _capture_initialize_state(self, *, resp_session_id: str | None, reply: Mapping[str, Any]) -> None:
        validated_sid = _validate_session_id(resp_session_id) if resp_session_id else None
        neg_version: str | None = None
        result = reply.get("result")
        if isinstance(result, Mapping):
            ver = result.get("protocolVersion")
            if isinstance(ver, str) and ver in SUPPORTED_PROTOCOL_VERSIONS:
                neg_version = ver
        with self._lock:
            if self._severed or self._closed:
                return
            if validated_sid is not None:
                self._session_id = validated_sid
            if neg_version is not None:
                self._protocol_version = neg_version

    def request(
        self,
        method: str,
        params: dict[str, Any],
        timeout: float = DOWNSTREAM_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        """Send one JSON-RPC request over Streamable HTTP and return the matching reply or GatewayLocalError."""
        req_id = self._next_id()
        if timeout <= 0:
            return local_downstream_error(req_id, f"Invalid timeout for downstream server '{self.name}'.")

        body = json.dumps({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}).encode("utf-8")
        deadline = time.monotonic() + timeout
        retried_auth = False

        for _attempt in range(2):
            with self._lock:
                if self._severed or self._closed:
                    return local_downstream_error(req_id, f"Downstream MCP server '{self.name}' connection closed.")
                session_id = self._session_id
                protocol_version = self._protocol_version

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return local_downstream_error(req_id, f"Downstream MCP server '{self.name}' timed out.")

            auth_header: str | None = None
            if self.oauth_provider is not None:
                try:
                    auth_header = self.oauth_provider.get_authorization_header()
                except OAuthError as exc:
                    _report_detail(self.name, "OAuth token acquisition failed", exc)
                    return local_downstream_error(req_id, f"OAuth token acquisition failed for '{self.name}'.")

            headers = self._build_headers(
                session_id=session_id,
                protocol_version=protocol_version,
                auth_header=auth_header,
            )
            req = urllib.request.Request(self.url, data=body, method="POST", headers=headers)  # noqa: S310 - validated URL

            try:
                with self._opener.open(req, timeout=remaining) as resp:  # noqa: S310 - validated URL
                    status_code = getattr(resp, "status", resp.getcode())
                    if status_code != 200:
                        return local_downstream_error(
                            req_id, f"Downstream MCP server '{self.name}' returned HTTP {status_code}."
                        )
                    ctype_raw = resp.headers.get("Content-Type") or ""
                    ctype = ctype_raw.split(";", 1)[0].strip().lower()
                    resp_sid = resp.headers.get("Mcp-Session-Id")

                    if ctype == "application/json":
                        raw_bytes = read_bounded_bytes(resp, max_bytes=self._max_response_bytes, deadline=deadline)
                        parsed = _strict_json_loads(raw_bytes.decode("utf-8"))
                        if not _valid_reply_shape(parsed, req_id):
                            return local_downstream_error(
                                req_id, f"Downstream MCP server '{self.name}' returned malformed JSON-RPC response."
                            )
                        reply: dict[str, Any] = parsed
                    elif ctype == "text/event-stream":
                        reply = self._read_sse_reply(resp, req_id=req_id, deadline=deadline)
                    else:
                        # The Content-Type value is server-written text, so it is not echoed to the agent.
                        _report_detail(self.name, "unsupported Content-Type", ValueError(repr(ctype_raw)))
                        return local_downstream_error(
                            req_id, f"Downstream MCP server '{self.name}' returned an unsupported Content-Type."
                        )

                    if method == "initialize":
                        self._capture_initialize_state(resp_session_id=resp_sid, reply=reply)
                    return reply
            except urllib.error.HTTPError as exc:
                http_code = exc.code
                www_auth = exc.headers.get("WWW-Authenticate") if exc.headers else None
                exc.close()
                if http_code == 401 and self.oauth_provider is not None and not retried_auth:
                    retried_auth = True
                    try:
                        self.oauth_provider.handle_unauthorized(www_auth)
                    except OAuthError as oauth_exc:
                        _report_detail(self.name, "OAuth authentication failed", oauth_exc)
                        return local_downstream_error(req_id, f"OAuth authentication failed for '{self.name}'.")
                    continue
                if http_code == 404 and session_id is not None:
                    with self._lock:
                        self._session_id = None
                    return local_downstream_error(
                        req_id, f"Downstream MCP server '{self.name}' session expired (HTTP 404)."
                    )
                return local_downstream_error(req_id, f"Downstream MCP server '{self.name}' returned HTTP {http_code}.")
            except OAuthError as exc:
                _report_detail(self.name, "HTTP policy violation", exc)
                return local_downstream_error(req_id, f"Downstream HTTP policy violation for '{self.name}'.")
            except (urllib.error.URLError, TimeoutError, UnicodeDecodeError, ValueError, OSError) as exc:
                _report_detail(self.name, "HTTP error", exc)
                return local_downstream_error(
                    req_id, f"Downstream MCP HTTP error for '{self.name}' ({type(exc).__name__})."
                )

        return local_downstream_error(req_id, f"Downstream MCP server '{self.name}' authentication retry exhausted.")

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        """Send a one-way JSON-RPC notification over Streamable HTTP (best-effort)."""
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        body = json.dumps(payload).encode("utf-8")
        retried_auth = False

        for _attempt in range(2):
            with self._lock:
                if self._severed or self._closed:
                    return
                session_id = self._session_id
                protocol_version = self._protocol_version

            auth_header: str | None = None
            if self.oauth_provider is not None:
                try:
                    auth_header = self.oauth_provider.get_authorization_header()
                except OAuthError:
                    return
            headers = self._build_headers(
                session_id=session_id,
                protocol_version=protocol_version,
                auth_header=auth_header,
            )
            req = urllib.request.Request(self.url, data=body, method="POST", headers=headers)  # noqa: S310 - validated URL
            try:
                with self._opener.open(req, timeout=5.0):  # noqa: S310 - validated URL
                    return
            except urllib.error.HTTPError as exc:
                http_code = exc.code
                www_auth = exc.headers.get("WWW-Authenticate") if exc.headers else None
                exc.close()
                if http_code == 401 and self.oauth_provider is not None and not retried_auth:
                    retried_auth = True
                    try:
                        self.oauth_provider.handle_unauthorized(www_auth)
                    except OAuthError:
                        return
                    continue
                return
            except (OAuthError, urllib.error.URLError, TimeoutError, OSError):
                return

    def _best_effort_delete(self, session_id: str) -> None:
        headers = {"Mcp-Session-Id": session_id, "MCP-Protocol-Version": self._protocol_version}
        req = urllib.request.Request(self.url, method="DELETE", headers=headers)  # noqa: S310 - validated URL
        try:
            with self._opener.open(req, timeout=_AAD_DELETE_TIMEOUT_SECONDS):  # noqa: S310 - validated URL
                pass
        except (OAuthError, urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
            pass

    def _terminate(self, *, sever: bool) -> None:
        with self._lock:
            if sever:
                self._severed = True
            else:
                self._closed = True
            sid = self._session_id
            self._session_id = None
        if self.oauth_provider is not None:
            if sever:
                self.oauth_provider.clear_tokens()  # AAD: the cached credential goes too
            else:
                self.oauth_provider.forget_in_memory()  # clean close: keep the cache for the next start
        if sid is not None:
            self._best_effort_delete(sid)

    def kill_now(self) -> None:
        """Immediately sever transport, wipe OAuth tokens, and terminate the remote session (AAD)."""
        self._terminate(sever=True)

    def close(self) -> None:
        """Close transport cleanly, terminate any active `Mcp-Session-Id`, and wipe cached tokens."""
        self._terminate(sever=False)


__all__ = ["DEFAULT_MAX_SSE_EVENTS", "StreamableHttpDownstream"]
