"""
Narrow loopback-to-internal HTTP relay for containerized MCP gateway approvals.

In Docker deployments (`deploy/docker-compose.yml`), `mellyn-gateway` sits exclusively on
`mellyn-internal` (`internal: true`) so MCP servers have zero direct route to the internet.
Docker does not publish host ports for containers that are only on internal networks.

`mellyn-approval-relay` bridges ONLY the three exact approval routes (`GET /v1/pending` and
`POST /v1/pending/apr_.../(approve|reject)`) from host loopback (`127.0.0.1:8765` on
`mellyn-frontend`) to `mellyn-gateway:8765` on `mellyn-internal`:
  - `mellyn-gateway` keeps zero direct internet access.
  - The human runs `python -m mellyn.approve --url http://127.0.0.1:8765 ...` on the host,
    so the raw approver key never enters `mellyn-gateway`'s container process tree.
  - The relay itself holds zero credentials (`.env` is not mounted); `mellyn-gateway` verifies
    `X-Mellyn-API-Key` against `MELLYN_APPROVER_KEY_DIGEST`.
"""

from __future__ import annotations

import argparse
import json
import re
import urllib.error
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from mellyn.approvals import (
    API_KEY_HEADER,
    MAX_BODY_BYTES,
    MAX_PENDING,
    ApprovalRedirectError,
    build_approval_opener,
    parse_approval_route,
)

# Largest reply the relay will pass back. GET /v1/pending can hold MAX_PENDING calls, each with up to 64 KiB of
# arguments plus their reasons, so this must comfortably exceed MAX_PENDING * 64 KiB. A larger reply is
# refused with 502 rather than cut short, which would hand the approver CLI broken JSON.
MAX_RELAY_RESPONSE_BYTES = MAX_PENDING * 80 * 1024

_HOST_TOKEN_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def is_allowed_approval_route(method: str, path: str) -> bool:
    """Return True only for the exact pending-approval endpoints."""
    return parse_approval_route(method, path) is not None


def validate_upstream(host: str, port: int) -> str:
    if not isinstance(host, str) or not _HOST_TOKEN_RE.fullmatch(host):
        raise ValueError(f"Invalid upstream hostname '{host}'.")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError(f"Invalid upstream port '{port}'.")
    return f"http://{host}:{port}"


def _json_error_bytes(message: str) -> bytes:
    return json.dumps({"error": message}).encode("utf-8")


def forward_approval_request(
    upstream_base: str,
    method: str,
    path: str,
    *,
    api_key: str | None = None,
    body: bytes | None = None,
    opener: urllib.request.OpenerDirector | None = None,
) -> tuple[int, bytes]:
    """
    Forward a validated approval request to `upstream_base + path` without following redirects or proxies.
    Never reflects credentials into error messages.
    """
    headers = {"Content-Type": "application/json"}
    if api_key is not None:
        headers[API_KEY_HEADER] = api_key

    req = urllib.request.Request(  # noqa: S310 - fixed internal upstream validated at startup
        upstream_base + path,
        data=body,
        method=method,
        headers=headers,
    )
    active_opener = opener or build_approval_opener()
    try:
        with active_opener.open(req, timeout=10) as resp:
            status, payload = resp.status, resp.read(MAX_RELAY_RESPONSE_BYTES + 1)
    except ApprovalRedirectError as exc:
        return int(HTTPStatus.BAD_GATEWAY), _json_error_bytes(
            f"Approval server returned unexpected redirect ({exc.code}); refusing to follow."
        )
    except urllib.error.HTTPError as exc:
        with exc:
            if 300 <= exc.code < 400:
                return int(HTTPStatus.BAD_GATEWAY), _json_error_bytes(
                    f"Approval server returned unexpected redirect ({exc.code}); refusing to follow."
                )
            status, payload = exc.code, exc.read(MAX_RELAY_RESPONSE_BYTES + 1)
    except (urllib.error.URLError, OSError):
        return int(HTTPStatus.BAD_GATEWAY), _json_error_bytes(
            "MCP gateway approval server is not reachable (ensure mellyn-gateway is running)."
        )

    if 300 <= status < 400:
        return int(HTTPStatus.BAD_GATEWAY), _json_error_bytes(
            f"Approval server returned unexpected redirect ({status}); refusing to follow."
        )
    if len(payload) > MAX_RELAY_RESPONSE_BYTES:
        return int(HTTPStatus.BAD_GATEWAY), _json_error_bytes("Approval server reply is too large to relay.")
    return status, payload


class _RelayHandler(BaseHTTPRequestHandler):
    server: ApprovalRelayServer

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Silence per-request stderr logging."""

    def _send_bytes(self, status: int, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _send_error_json(self, status: HTTPStatus, message: str) -> None:
        self._send_bytes(int(status), _json_error_bytes(message))

    def _forward(self, method: str) -> None:
        if not is_allowed_approval_route(method, self.path):
            self._send_error_json(HTTPStatus.NOT_FOUND, "Not found.")
            return

        body: bytes | None = None
        if method == "POST":
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if not 0 <= length <= MAX_BODY_BYTES:
                self._send_error_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Body missing or too large.")
                return
            body = self.rfile.read(length)

        status, payload = forward_approval_request(
            self.server.upstream_base,
            method,
            self.path,
            api_key=self.headers.get(API_KEY_HEADER),
            body=body,
            opener=self.server.opener,
        )
        self._send_bytes(status, payload)

    def do_GET(self) -> None:  # noqa: N802
        self._forward("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._forward("POST")


class ApprovalRelayServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        *,
        listen_host: str,
        listen_port: int,
        upstream_host: str,
        upstream_port: int,
        opener: urllib.request.OpenerDirector | None = None,
    ) -> None:
        self.upstream_base = validate_upstream(upstream_host, upstream_port)
        self.opener = opener or build_approval_opener()
        super().__init__((listen_host, listen_port), _RelayHandler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mellyn Security — Loopback-to-internal approval relay")
    parser.add_argument("--listen-host", default="0.0.0.0", choices=("127.0.0.1", "0.0.0.0"))  # noqa: S104
    parser.add_argument("--listen-port", type=int, default=8765)
    parser.add_argument("--upstream-host", default="mellyn-gateway")
    parser.add_argument("--upstream-port", type=int, default=8765)
    args = parser.parse_args(argv)

    relay = ApprovalRelayServer(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        upstream_host=args.upstream_host,
        upstream_port=args.upstream_port,
    )
    try:
        relay.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        relay.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
