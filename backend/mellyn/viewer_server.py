"""
Loopback BFF & static SPA server for the Mellyn Security B2B Posture, Audit & Approval Viewer (Plane 4).

Security invariants:
  - Binds to 127.0.0.1 by default. Binding to 0.0.0.0 needs an explicit `allow_non_loopback` opt-in, because
    keys then cross the network in cleartext HTTP.
  - Rejects any request whose Host header is not an allowed hostname (127.0.0.1, localhost, [::1], plus any
    explicitly allowed names), so a DNS-rebinding page cannot talk to the server.
  - Fails closed (503) when the needed credential is missing or invalid; only /api/v1/healthz is public.
  - Read-only endpoints (status, reports, audit logs, assurance) require the Role.VIEWER key. Listing, approving
    and rejecting held calls require the Role.APPROVER key. The roles never substitute for each other.
  - Never reflects raw host filesystem paths in responses, including error messages.
  - Emits strict CSP, X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Referrer-Policy: no-referrer,
    and Cache-Control: no-store on all API responses.
  - Rejects HTTP redirects when relaying pending-approval actions via forward_approval_request.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import re
import sys
import threading
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any

from mellyn.approval_relay import forward_approval_request, validate_upstream
from mellyn.approvals import API_KEY_HEADER, MAX_BODY_BYTES, parse_approval_route
from mellyn.credentials import CredentialConfig, CredentialConfigError, Role
from mellyn.legacy_env import check_no_legacy_env

DEFAULT_VIEWER_HOST = "127.0.0.1"
NON_LOOPBACK_VIEWER_HOST = "0.0.0.0"  # noqa: S104 - container opt-in only (allow_non_loopback)
ALLOWED_VIEWER_HOSTS: frozenset[str] = frozenset({DEFAULT_VIEWER_HOST, NON_LOOPBACK_VIEWER_HOST})
DEFAULT_VIEWER_PORT = 8080
# Hostnames accepted in the Host header (port ignored). Anything else, such as a DNS-rebinding domain, gets 421.
LOOPBACK_HOST_NAMES: frozenset[str] = frozenset({"127.0.0.1", "localhost", "[::1]"})
MAX_GATEWAY_AUDIT_FILE_BYTES = 16 * 1024 * 1024
MAX_ASSURANCE_FILE_BYTES = 4 * 1024 * 1024
DEFAULT_GATEWAY_AUDIT_LIMIT = 500
MAX_GATEWAY_AUDIT_LIMIT = 2000

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_CONTENT_TYPES: dict[str, str] = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".mjs": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
}

CSP_HEADER_VALUE = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


def _reconstruct_airlock_report(ledger_path: Path) -> dict[str, Any]:
    """Import `mcp_airlock.ir_lab.reconstruct` (adding repo `src/` if editable install is absent) and reconstruct."""
    try:
        from mcp_airlock.ir_lab.reconstruct import reconstruct_incident
    except ModuleNotFoundError:
        src_dir = str(Path(__file__).resolve().parents[2] / "src")
        if src_dir not in sys.path:
            sys.path.insert(0, src_dir)
        from mcp_airlock.ir_lab.reconstruct import reconstruct_incident

    report = reconstruct_incident(ledger_path)
    # Never expose host-specific directory paths; keep only the ledger filename.
    sanitized_verification = report.verification.model_copy(update={"ledger_path": ledger_path.name})
    sanitized_report = report.model_copy(update={"verification": sanitized_verification})
    return sanitized_report.model_dump(mode="json")


def _load_gateway_audit(audit_path: Path, *, limit: int) -> dict[str, Any]:
    if not audit_path.exists():
        return {"events": [], "total_lines": 0, "returned_count": 0, "malformed_lines": 0}
    if not audit_path.is_file():
        raise OSError("Gateway audit path is not a regular file.")
    size = audit_path.stat().st_size
    if size > MAX_GATEWAY_AUDIT_FILE_BYTES:
        raise ValueError(f"Gateway audit file exceeds viewer cap of {MAX_GATEWAY_AUDIT_FILE_BYTES} bytes.")

    try:
        raw_text = audit_path.read_bytes().decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Gateway audit file is not valid UTF-8.") from exc
    parsed: list[dict[str, Any]] = []
    total_lines = 0
    malformed_lines = 0
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        total_lines += 1
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            malformed_lines += 1
            continue
        if isinstance(obj, dict):
            parsed.append(obj)
        else:
            malformed_lines += 1

    recent = parsed[-limit:]
    return {
        "events": recent,
        "total_lines": total_lines,
        "returned_count": len(recent),
        "malformed_lines": malformed_lines,
    }


def _load_assurance_report(report_path: Path) -> dict[str, Any]:
    size = report_path.stat().st_size
    if size > MAX_ASSURANCE_FILE_BYTES:
        raise ValueError(f"Assurance report exceeds viewer cap of {MAX_ASSURANCE_FILE_BYTES} bytes.")
    raw = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("cases"), list):
        raise ValueError("Assurance report JSON must be an object containing a 'cases' list.")
    return raw


class _ViewerHandler(BaseHTTPRequestHandler):
    server: ViewerHTTPServer

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        """Silence per-request stderr logging so API keys or routes never hit logs."""

    def _apply_security_headers(self, *, is_api: bool) -> None:
        self.send_header("Content-Security-Policy", CSP_HEADER_VALUE)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        if is_api:
            self.send_header("Cache-Control", "no-store")

    def _send_bytes(self, status: int, content_type: str, payload: bytes, *, is_api: bool) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self._apply_security_headers(is_api=is_api)
        self.end_headers()
        self.wfile.write(payload)

    def _send_json(self, status: HTTPStatus | int, body: Any) -> None:
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self._send_bytes(int(status), "application/json; charset=utf-8", payload, is_api=True)

    def _host_allowed(self) -> bool:
        """
        Accept only requests addressed to an allowed hostname. A DNS-rebinding page reaches this server under its
        own domain name, so checking the Host header (the port is ignored) shuts that path, including for the
        public healthz route and the static app.
        """
        raw_host = (self.headers.get("Host") or "").strip().lower()
        if raw_host.startswith("["):
            hostname = raw_host.split("]", 1)[0] + "]"
        else:
            hostname = raw_host.rsplit(":", 1)[0] if ":" in raw_host else raw_host
        if hostname and hostname in self.server.allowed_host_names:
            return True
        self._send_json(HTTPStatus.MISDIRECTED_REQUEST, {"error": "Unexpected Host header."})
        return False

    def _require_role(self, role: Role) -> str | None:
        """Return the request's API key if it is the key for `role`; otherwise send an error and return None."""
        creds = self.server.viewer_credentials if role is Role.VIEWER else self.server.approver_credentials
        if creds is None:
            self._send_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": f"The {role} key is not configured on this viewer (fail-closed)."},
            )
            return None
        api_key = self.headers.get(API_KEY_HEADER)
        if not api_key:
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": f"Missing {API_KEY_HEADER} header."})
            return None
        if not creds.verify(api_key, role):
            self._send_json(HTTPStatus.FORBIDDEN, {"error": f"A {role} key is required."})
            return None
        return api_key

    def _handle_pending_proxy(self, method: str, path: str, api_key: str) -> None:
        upstream_path = path.removeprefix("/api")
        parsed_route = parse_approval_route(method, upstream_path)
        if parsed_route is None:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})
            return
        if self.server.approval_upstream is None:
            self._send_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "Approval relay upstream is not configured."},
            )
            return

        body: bytes | None = None
        if method == "POST":
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if not 0 <= length <= MAX_BODY_BYTES:
                self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "Body missing or too large."})
                return
            body = self.rfile.read(length)

        status, payload = forward_approval_request(
            self.server.approval_upstream,
            method,
            upstream_path,
            api_key=api_key,
            body=body,
            opener=self.server.approval_opener,
        )
        self._send_bytes(status, "application/json; charset=utf-8", payload, is_api=True)

    def _serve_static(self, raw_path: str) -> None:
        static_dir = self.server.static_dir
        if static_dir is None:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Static viewer assets are not configured."})
            return

        decoded = urllib.parse.unquote(raw_path)
        if _CONTROL_CHARS_RE.search(decoded) or "\\" in decoded:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})
            return

        rel_str = decoded.lstrip("/")
        if rel_str == "":
            rel_str = "index.html"
        parts = PurePosixPath(rel_str).parts
        if any(part in ("", ".", "..") for part in parts):
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})
            return

        static_root = static_dir.resolve()
        candidate = (static_root / Path(*parts)).resolve()
        if not candidate.is_relative_to(static_root):
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})
            return

        if not candidate.is_file():
            # SPA fallback for extensionless client routes only; missing JS/CSS assets still 404.
            if "." in parts[-1]:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})
                return
            candidate = (static_root / "index.html").resolve()
            if not candidate.is_relative_to(static_root) or not candidate.is_file():
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})
                return

        content_type = _CONTENT_TYPES.get(candidate.suffix.lower())
        if content_type is None:
            guessed, _ = mimetypes.guess_type(candidate.name)
            content_type = guessed or "application/octet-stream"
        self._send_bytes(int(HTTPStatus.OK), content_type, candidate.read_bytes(), is_api=False)

    def do_GET(self) -> None:  # noqa: N802 - stdlib method name
        if not self._host_allowed():
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/v1/healthz":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return

        if not path.startswith("/api/"):
            self._serve_static(path)
            return

        if path == "/api/v1/pending":
            # Listing held calls is an approval-surface action: approver key only.
            approver_key = self._require_role(Role.APPROVER)
            if approver_key is not None:
                self._handle_pending_proxy("GET", path, approver_key)
            return

        if self._require_role(Role.VIEWER) is None:
            return

        if path == "/api/v1/status":
            self._send_json(
                HTTPStatus.OK,
                {
                    "airlock_ledger_configured": self.server.airlock_audit_path is not None,
                    "gateway_audit_configured": self.server.gateway_audit_path is not None,
                    "assurance_report_configured": self.server.assurance_report_path is not None,
                    "approval_relay_configured": self.server.approval_upstream is not None,
                },
            )
            return

        if path == "/api/v1/airlock/report":
            ledger_path = self.server.airlock_audit_path
            if ledger_path is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Airlock audit ledger is not configured."})
                return
            try:
                report = _reconstruct_airlock_report(ledger_path)
            except Exception as exc:  # noqa: BLE001 - fail closed cleanly over HTTP
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"error": f"Failed to reconstruct airlock ledger ({type(exc).__name__})."},
                )
                return
            self._send_json(HTTPStatus.OK, report)
            return

        if path == "/api/v1/gateway/audit":
            gw_path = self.server.gateway_audit_path
            if gw_path is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Gateway audit ledger is not configured."})
                return
            qs = urllib.parse.parse_qs(parsed.query)
            raw_limit = qs.get("limit", [str(DEFAULT_GATEWAY_AUDIT_LIMIT)])[0]
            try:
                limit = int(raw_limit)
            except ValueError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid limit parameter."})
                return
            clamped_limit = max(1, min(MAX_GATEWAY_AUDIT_LIMIT, limit))
            try:
                payload = _load_gateway_audit(gw_path, limit=clamped_limit)
            except ValueError as exc:  # messages raised by _load_gateway_audit itself, which hold no paths
                self._send_json(HTTPStatus.UNPROCESSABLE_ENTITY, {"error": str(exc)})
                return
            except OSError as exc:  # OSError text includes the file path; report only the error type
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"error": f"Gateway audit log could not be read ({type(exc).__name__})."},
                )
                return
            self._send_json(HTTPStatus.OK, payload)
            return

        if path == "/api/v1/assurance":
            assurance_path = self.server.assurance_report_path
            if assurance_path is None or not assurance_path.is_file():
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Control assurance report is not available."})
                return
            try:
                report = _load_assurance_report(assurance_path)
            except (OSError, ValueError) as exc:  # includes JSONDecodeError; OSError text would hold the path
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"error": f"Invalid or unreadable control assurance report ({type(exc).__name__})."},
                )
                return
            self._send_json(HTTPStatus.OK, report)
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})

    def do_POST(self) -> None:  # noqa: N802 - stdlib method name
        if not self._host_allowed():
            return
        path = urllib.parse.urlparse(self.path).path
        if not path.startswith("/api/"):
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})
            return

        api_key = self._require_role(Role.APPROVER)
        if api_key is None:
            return

        self._handle_pending_proxy("POST", path, api_key)


class ViewerHTTPServer(ThreadingHTTPServer):
    """Fail-closed loopback HTTP server serving the B2B posture, audit, and approval UI."""

    daemon_threads = True

    def __init__(
        self,
        *,
        host: str = DEFAULT_VIEWER_HOST,
        port: int = DEFAULT_VIEWER_PORT,
        viewer_credentials: CredentialConfig | None = None,
        approver_credentials: CredentialConfig | None = None,
        airlock_audit_path: Path | None = None,
        gateway_audit_path: Path | None = None,
        assurance_report_path: Path | None = None,
        approval_upstream: str | None = None,
        approval_opener: urllib.request.OpenerDirector | None = None,
        static_dir: Path | None = None,
        allow_non_loopback: bool = False,
        extra_allowed_host_names: frozenset[str] = frozenset(),
    ) -> None:
        if host not in ALLOWED_VIEWER_HOSTS:
            raise ValueError(f"Viewer host must be one of {sorted(ALLOWED_VIEWER_HOSTS)}, got '{host}'.")
        if host == NON_LOOPBACK_VIEWER_HOST and not allow_non_loopback:
            raise ValueError(
                "Binding the viewer to 0.0.0.0 sends API keys over plain HTTP on the network; "
                "pass allow_non_loopback=True (CLI: --allow-non-loopback) to do it deliberately."
            )
        # Each role is loaded on its own, so a deployment that only views (no approver key) still works and a
        # missing key fails closed for just the routes that need it.
        if viewer_credentials is None:
            viewer_credentials = _credentials_for(Role.VIEWER)
        if approver_credentials is None:
            approver_credentials = _credentials_for(Role.APPROVER)

        self.viewer_credentials = viewer_credentials
        self.approver_credentials = approver_credentials
        self.allowed_host_names: frozenset[str] = LOOPBACK_HOST_NAMES | frozenset(
            name.strip().lower() for name in extra_allowed_host_names if name.strip()
        )
        self.airlock_audit_path = airlock_audit_path
        self.gateway_audit_path = gateway_audit_path
        self.assurance_report_path = assurance_report_path
        self.approval_upstream = approval_upstream
        self.approval_opener = approval_opener
        self.static_dir = static_dir
        super().__init__((host, port), _ViewerHandler)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"

    def start_in_background(self) -> threading.Thread:
        thread = threading.Thread(target=self.serve_forever, name="mellyn-viewer", daemon=True)
        thread.start()
        return thread


def _credentials_for(role: Role) -> CredentialConfig | None:
    try:
        return CredentialConfig.from_env(roles=frozenset({role}))
    except CredentialConfigError:
        return None


def _path_from_env(name: str) -> Path | None:
    raw = os.environ.get(name, "").strip()
    return Path(raw) if raw else None


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Mellyn Security — Posture, Forensic Audit & Approval Viewer")
    parser.add_argument(
        "--listen-host",
        default=DEFAULT_VIEWER_HOST,
        choices=tuple(sorted(ALLOWED_VIEWER_HOSTS)),
    )
    parser.add_argument("--listen-port", type=int, default=DEFAULT_VIEWER_PORT)
    parser.add_argument(
        "--allow-non-loopback",
        action="store_true",
        help="Required with --listen-host 0.0.0.0: API keys then cross the network over plain HTTP.",
    )
    parser.add_argument(
        "--allow-host",
        action="append",
        default=[],
        help="Extra hostname accepted in the Host header (repeatable), e.g. a container DNS name.",
    )
    parser.add_argument("--airlock-audit-log", type=Path, default=_path_from_env("MELLYN_AIRLOCK_AUDIT_PATH"))
    parser.add_argument("--gateway-audit-log", type=Path, default=_path_from_env("MELLYN_AUDIT_LOG_PATH"))
    parser.add_argument("--assurance-report", type=Path, default=_path_from_env("MELLYN_ASSURANCE_REPORT_PATH"))
    parser.add_argument("--approval-host", default=os.environ.get("MELLYN_APPROVAL_HOST", "127.0.0.1"))
    parser.add_argument("--approval-port", type=int, default=None)
    parser.add_argument("--static-dir", type=Path, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    check_no_legacy_env()
    args = _build_parser().parse_args(argv)

    approval_upstream: str | None = None
    env_port = os.environ.get("MELLYN_APPROVAL_PORT", "").strip()
    resolved_port = args.approval_port if args.approval_port is not None else (int(env_port) if env_port else None)
    if resolved_port is not None:
        approval_upstream = validate_upstream(args.approval_host, resolved_port)

    static_dir = args.static_dir
    if static_dir is None:
        default_dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
        if default_dist.is_dir():
            static_dir = default_dist

    if args.listen_host == NON_LOOPBACK_VIEWER_HOST and not args.allow_non_loopback:
        print(
            "mellyn-viewer: --listen-host 0.0.0.0 sends API keys over plain HTTP on the network; "
            "add --allow-non-loopback to do this deliberately.",
            file=sys.stderr,
        )
        return 2

    server = ViewerHTTPServer(
        host=args.listen_host,
        port=args.listen_port,
        airlock_audit_path=args.airlock_audit_log,
        gateway_audit_path=args.gateway_audit_log,
        assurance_report_path=args.assurance_report,
        approval_upstream=approval_upstream,
        static_dir=static_dir,
        allow_non_loopback=args.allow_non_loopback,
        extra_allowed_host_names=frozenset(args.allow_host),
    )
    if args.listen_host == NON_LOOPBACK_VIEWER_HOST:
        print(
            "[mellyn-viewer WARNING] Listening on all interfaces over plain HTTP: viewer and approver keys are "
            "sent unencrypted. Put a TLS-terminating proxy in front, or use this only inside a container network.",
            file=sys.stderr,
        )
    print(f"Mellyn Viewer listening on {server.url} (fail-closed)", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


__all__ = [
    "CSP_HEADER_VALUE",
    "DEFAULT_GATEWAY_AUDIT_LIMIT",
    "DEFAULT_VIEWER_HOST",
    "DEFAULT_VIEWER_PORT",
    "MAX_ASSURANCE_FILE_BYTES",
    "MAX_GATEWAY_AUDIT_FILE_BYTES",
    "MAX_GATEWAY_AUDIT_LIMIT",
    "ViewerHTTPServer",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
