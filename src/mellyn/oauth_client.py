"""
Stdlib OAuth 2.1 client and fail-closed outbound HTTPS helpers for Streamable HTTP MCP transports.

Supports RFC 9728 Protected Resource Metadata discovery (constrained to policy-pinned authorization
servers), RFC 8414 Authorization Server metadata validation, RFC 7636 PKCE (`S256`), RFC 8707
`resource` binding, `client_credentials`, `bearer_env`, zero-redirect HTTP handling, and Squid proxy routing.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import ssl
import stat
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Literal

from mellyn.core.strict_input import StrictJsonError, strict_json_loads
from mellyn.egress import EgressValidator
from mellyn.egress_proxy import validate_egress_domain
from mellyn.legacy_env import LEGACY_ENV_PREFIX

MAX_OAUTH_RESPONSE_BYTES = 1_048_576
DEFAULT_OAUTH_TIMEOUT_SECONDS = 15.0
DEFAULT_PKCE_TIMEOUT_SECONDS = 120.0

_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_SENSITIVE_ENV_PREFIXES: tuple[str, ...] = ("MELLYN_", LEGACY_ENV_PREFIX)
_AUTH_PARAM_RE = re.compile(r'([A-Za-z0-9_.-]+)\s*=\s*(?:"([^"]*)"|([^,\s]+))')
_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "::1"})


class OAuthError(RuntimeError):
    """Raised fail-closed when OAuth 2.1 discovery, validation, or token acquisition fails."""


def _validate_env_var_name(raw_name: str, field_label: str) -> str:
    if not isinstance(raw_name, str) or not raw_name.strip():
        raise ValueError(f"{field_label} must be a non-empty environment variable name.")
    clean = raw_name.strip()
    if not _ENV_KEY_RE.fullmatch(clean):
        raise ValueError(f"{field_label} '{clean}' is not a valid environment variable name.")
    if clean.upper().startswith(_SENSITIVE_ENV_PREFIXES):
        raise ValueError(f"Refusing reserved Mellyn variable '{clean}' for {field_label}.")
    return clean


def canonical_resource_uri(raw_url: str) -> str:
    """Return an RFC 8707 canonical resource URI (normalized scheme/host, no fragment)."""
    parsed = urllib.parse.urlparse(raw_url.strip())
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    port = parsed.port
    if ":" in host:
        host_fmt = f"[{host}]"
    else:
        host_fmt = host
    netloc = f"{host_fmt}:{port}" if port is not None else host_fmt
    return urllib.parse.urlunparse((scheme, netloc, parsed.path, parsed.params, parsed.query, ""))


def validate_outbound_url(
    raw_url: str,
    *,
    allowed_domains: frozenset[str] | None = None,
    allow_loopback_http: bool = False,
) -> str:
    """
    Validate an outbound MCP/OAuth endpoint URL fail-closed.

    Requires `https://`, rejects userinfo credentials, fragments, control characters, IP literals,
    `.localhost`/`.local`, invalid ports, and hosts missing from `allowed_domains` when supplied.
    Loopback `http://127.0.0.1` / `http://[::1]` is permitted only when `allow_loopback_http=True`.
    """
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise ValueError("Outbound URL must be a non-empty string.")
    if _CONTROL_CHARS_RE.search(raw_url):
        raise ValueError("Outbound URL contains control characters.")

    trimmed = raw_url.strip()
    try:
        parsed = urllib.parse.urlparse(trimmed)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Malformed outbound URL authority or port.") from exc

    if parsed.fragment:
        raise ValueError("Outbound URL must not contain a fragment identifier.")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise ValueError("Outbound URLs with embedded credentials/userinfo are forbidden.")

    hostport = parsed.netloc
    if "]" in hostport:
        _, _, after_bracket = hostport.rpartition("]")
        has_colon_port = ":" in after_bracket
    else:
        has_colon_port = ":" in hostport
    if has_colon_port and (port is None or port <= 0):
        raise ValueError("Outbound URL specifies an empty or invalid port.")

    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").strip().lower().rstrip(".")
    if not hostname:
        raise ValueError("Outbound URL is missing a valid hostname.")

    if allow_loopback_http and hostname in _LOOPBACK_HOSTS and scheme in ("http", "https"):
        return canonical_resource_uri(trimmed)

    if scheme != "https":
        raise ValueError(f"Disallowed URL scheme '{parsed.scheme}'; only https is permitted.")
    if hostname == "localhost" or hostname.endswith(".localhost") or hostname.endswith(".local"):
        raise ValueError("Loopback or .local hostname is forbidden.")
    if EgressValidator._is_ip_literal(hostname):
        raise ValueError("Direct IP literals are forbidden in remote URLs; use an allowlisted domain.")

    norm_host = validate_egress_domain(hostname)
    if allowed_domains is not None and not EgressValidator(allowed_domains).is_domain_allowlisted(norm_host):
        raise ValueError(f"Destination host '{norm_host}' is not in the egress domain allowlist.")

    return canonical_resource_uri(trimmed)


def extract_url_host(raw_url: str) -> str:
    """Return lowercase normalized hostname from a validated URL."""
    return (urllib.parse.urlparse(raw_url.strip()).hostname or "").strip().lower().rstrip(".")


def _origin_tuple(raw_url: str) -> tuple[str, str]:
    parsed = urllib.parse.urlparse(raw_url.strip())
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme.lower() == "https" else 80
    return parsed.scheme.lower(), f"{host}:{port}"


def _well_known_urls(base_url: str, suffix_name: str) -> tuple[str, ...]:
    parsed = urllib.parse.urlparse(canonical_resource_uri(base_url))
    path = parsed.path.rstrip("/")
    origin = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    if not path:
        return (f"{origin}/.well-known/{suffix_name}",)
    return (
        f"{origin}/.well-known/{suffix_name}{path}",
        f"{origin}/.well-known/{suffix_name}",
    )


def _apply_stream_deadline(stream: Any, deadline: float | None) -> None:
    """Enforce an absolute monotonic `deadline` across chunked reads by tightening any underlying socket timeout."""
    if deadline is None:
        return
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("HTTP response read exceeded total deadline.")
    for candidate in (
        stream,
        getattr(stream, "fp", None),
        getattr(getattr(stream, "fp", None), "raw", None),
        getattr(stream, "raw", None),
    ):
        sock = getattr(candidate, "_sock", None)
        settimeout = getattr(sock, "settimeout", None)
        if callable(settimeout):
            settimeout(remaining)
            return


def read_bounded_bytes(stream: Any, *, max_bytes: int, deadline: float | None = None) -> bytes:
    """Read an HTTP response stream in bounded chunks within optional `deadline` and `max_bytes`."""
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive.")
    buf = bytearray()
    chunk_size = min(4_096, max_bytes + 1)
    read_fn = getattr(stream, "read1", None)
    if not callable(read_fn):
        read_fn = stream.read
    while True:
        _apply_stream_deadline(stream, deadline)
        chunk = read_fn(chunk_size)
        if not chunk:
            break
        if len(buf) + len(chunk) > max_bytes:
            raise ValueError(f"HTTP response exceeded maximum size of {max_bytes} bytes.")
        buf.extend(chunk)
    return bytes(buf)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse all HTTP 3xx redirects fail-closed so requests never follow cross-host redirects."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        del req, fp, msg, headers, newurl
        raise OAuthError(f"Outbound HTTP redirect ({code}) rejected (fail-closed).")


def build_safe_opener(
    *,
    proxy_url: str | None = None,
    ssl_context: ssl.SSLContext | None = None,
    bypass_ambient_proxy: bool = False,
) -> urllib.request.OpenerDirector:
    """
    Build a strict `urllib.request.OpenerDirector` that refuses redirects and honors Squid proxies.
    """
    handlers: list[urllib.request.BaseHandler] = [
        _NoRedirectHandler(),
        urllib.request.HTTPSHandler(context=ssl_context or ssl.create_default_context()),
    ]
    if proxy_url is not None:
        handlers.append(urllib.request.ProxyHandler({"https": proxy_url, "http": proxy_url}))
    elif bypass_ambient_proxy:
        handlers.append(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener(*handlers)


def parse_www_authenticate_bearer(header_value: str) -> dict[str, str]:
    """Extract Bearer challenge parameters from a `WWW-Authenticate` header."""
    if not isinstance(header_value, str):
        return {}
    stripped = header_value.strip()
    if not stripped.lower().startswith("bearer"):
        return {}
    tail = stripped[len("bearer") :].strip()
    if not tail:
        return {}
    params: dict[str, str] = {}
    for match in _AUTH_PARAM_RE.finditer(tail):
        key = match.group(1).lower()
        val = match.group(2) if match.group(2) is not None else (match.group(3) or "")
        params[key] = val
    return params


@dataclass(frozen=True)
class OAuthToken:
    """Short-lived OAuth 2.1 access token container (redacts secrets in `__repr__`)."""

    access_token: str
    token_type: str = "Bearer"  # noqa: S105 - OAuth RFC 6750 scheme name
    expires_at: float | None = None
    refresh_token: str | None = None
    scope: str | None = None

    def is_expired(self, now: float | None = None, *, skew_seconds: float = 30.0) -> bool:
        if self.expires_at is None:
            return False
        current = time.time() if now is None else now
        return current >= self.expires_at - skew_seconds

    def __repr__(self) -> str:
        return (
            f"OAuthToken(token_type={self.token_type!r}, expires_at={self.expires_at!r}, "
            f"has_refresh={self.refresh_token is not None}, scope={self.scope!r}, access_token='[REDACTED]')"
        )


@dataclass(frozen=True)
class OAuthClientConfig:
    """Fail-closed OAuth 2.1 client configuration for a downstream `streamable-http` MCP server."""

    flow: Literal["client_credentials", "pkce", "bearer_env"]
    allowed_authorization_servers: tuple[str, ...] = ()
    client_id: str | None = None
    client_id_env: str | None = None
    client_secret_env: str | None = None
    bearer_token_env: str | None = None
    scopes: tuple[str, ...] = ()
    resource: str | None = None
    token_endpoint: str | None = None
    authorization_endpoint: str | None = None
    token_cache_path: Path | None = None
    allow_insecure_loopback_for_tests: bool = False

    def __post_init__(self) -> None:
        if self.flow not in ("client_credentials", "pkce", "bearer_env"):
            raise ValueError(
                f"Unsupported OAuth flow {self.flow!r}; expected 'client_credentials', 'pkce', or 'bearer_env'."
            )

        allow_lb = self.allow_insecure_loopback_for_tests
        norm_as: list[str] = []
        for idx, raw_as in enumerate(self.allowed_authorization_servers):
            clean_as = validate_outbound_url(raw_as, allow_loopback_http=allow_lb).rstrip("/")
            if urllib.parse.urlparse(clean_as).query:
                raise ValueError(f"allowed_authorization_servers[{idx}] must not contain a query string.")
            norm_as.append(clean_as)
        object.__setattr__(self, "allowed_authorization_servers", tuple(norm_as))

        if self.client_id_env is not None:
            object.__setattr__(self, "client_id_env", _validate_env_var_name(self.client_id_env, "oauth.client_id_env"))
        if self.client_secret_env is not None:
            object.__setattr__(
                self,
                "client_secret_env",
                _validate_env_var_name(self.client_secret_env, "oauth.client_secret_env"),
            )
        if self.bearer_token_env is not None:
            object.__setattr__(
                self,
                "bearer_token_env",
                _validate_env_var_name(self.bearer_token_env, "oauth.bearer_token_env"),
            )

        if self.client_id is not None and not self.client_id.strip():
            raise ValueError("oauth.client_id must be non-empty when set.")
        if self.client_id is not None and self.client_id_env is not None:
            raise ValueError("Specify either oauth.client_id or oauth.client_id_env, not both.")

        if self.resource is not None:
            object.__setattr__(self, "resource", validate_outbound_url(self.resource, allow_loopback_http=allow_lb))
        if self.token_endpoint is not None:
            object.__setattr__(
                self, "token_endpoint", validate_outbound_url(self.token_endpoint, allow_loopback_http=allow_lb)
            )
        if self.authorization_endpoint is not None:
            object.__setattr__(
                self,
                "authorization_endpoint",
                validate_outbound_url(self.authorization_endpoint, allow_loopback_http=allow_lb),
            )

        if self.flow == "bearer_env":
            if self.bearer_token_env is None:
                raise ValueError("oauth.flow='bearer_env' requires oauth.bearer_token_env.")
        else:
            if self.client_id is None and self.client_id_env is None:
                raise ValueError(f"oauth.flow={self.flow!r} requires oauth.client_id or oauth.client_id_env.")
            if not self.allowed_authorization_servers:
                raise ValueError(f"oauth.flow={self.flow!r} requires non-empty oauth.allowed_authorization_servers.")
            if self.flow == "client_credentials" and self.client_secret_env is None:
                raise ValueError("oauth.flow='client_credentials' requires oauth.client_secret_env.")


def generate_pkce_pair() -> tuple[str, str]:
    """Generate `(code_verifier, code_challenge)` per RFC 7636 using `S256`."""
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _http_get_json(
    url: str,
    *,
    opener: urllib.request.OpenerDirector,
    timeout: float,
    max_bytes: int = MAX_OAUTH_RESPONSE_BYTES,
) -> dict[str, Any]:
    req = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})  # noqa: S310 - validated URL
    deadline = time.monotonic() + timeout
    try:
        with opener.open(req, timeout=timeout) as resp:  # noqa: S310 - scheme/host validated by validate_outbound_url
            raw = read_bounded_bytes(resp, max_bytes=max_bytes, deadline=deadline)
    except OAuthError:
        raise
    except urllib.error.HTTPError as exc:
        raise OAuthError(f"Metadata GET '{url}' failed with HTTP {exc.code}.") from exc
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        raise OAuthError(f"Metadata GET '{url}' failed: {exc}") from exc

    try:
        parsed = strict_json_loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, StrictJsonError) as exc:
        raise OAuthError(f"Malformed JSON metadata from '{url}': {exc}") from exc
    if not isinstance(parsed, dict):
        raise OAuthError(f"Metadata from '{url}' must be a JSON object.")
    return parsed


def discover_protected_resource(
    resource_url: str,
    *,
    allowed_authorization_servers: Sequence[str],
    www_authenticate: str | None = None,
    allowed_domains: frozenset[str] | None = None,
    timeout: float = DEFAULT_OAUTH_TIMEOUT_SECONDS,
    opener: urllib.request.OpenerDirector | None = None,
    allow_loopback_http: bool = False,
) -> tuple[str, tuple[str, ...]]:
    """
    Perform RFC 9728 Protected Resource Metadata discovery and enforce policy-pinned AS selection.

    Raises `OAuthError` if `resource` mismatches or no advertised authorization server is in
    `allowed_authorization_servers` (RFC 9728 mix-up defense).
    """
    canonical_res = validate_outbound_url(
        resource_url, allowed_domains=allowed_domains, allow_loopback_http=allow_loopback_http
    )
    pinned_set = {
        validate_outbound_url(item, allow_loopback_http=allow_loopback_http).rstrip("/")
        for item in allowed_authorization_servers
    }
    if not pinned_set:
        raise OAuthError("allowed_authorization_servers must not be empty.")

    eff_opener = opener or build_safe_opener(bypass_ambient_proxy=allow_loopback_http)
    candidates: list[str] = []
    if www_authenticate:
        chal = parse_www_authenticate_bearer(www_authenticate)
        meta_uri = chal.get("resource_metadata")
        if meta_uri:
            validated_meta = validate_outbound_url(
                meta_uri, allowed_domains=allowed_domains, allow_loopback_http=allow_loopback_http
            )
            if _origin_tuple(validated_meta) != _origin_tuple(canonical_res):
                raise OAuthError("WWW-Authenticate resource_metadata URL origin does not match MCP server.")
            candidates.append(validated_meta)
    for well_known in _well_known_urls(canonical_res, "oauth-protected-resource"):
        validate_outbound_url(well_known, allowed_domains=allowed_domains, allow_loopback_http=allow_loopback_http)
        if well_known not in candidates:
            candidates.append(well_known)

    metadata: dict[str, Any] | None = None
    last_err: OAuthError | None = None
    for candidate in candidates:
        try:
            metadata = _http_get_json(candidate, opener=eff_opener, timeout=timeout)
            break
        except OAuthError as exc:
            last_err = exc
            if "HTTP 404" in str(exc) and candidate != candidates[-1]:
                continue
            raise
    if metadata is None:
        raise last_err or OAuthError("Protected resource metadata discovery failed.")

    meta_resource = metadata.get("resource")
    if not isinstance(meta_resource, str) or canonical_resource_uri(meta_resource) != canonical_res:
        raise OAuthError("Protected resource metadata 'resource' mismatch (RFC 9728 mix-up protection failed closed).")

    raw_servers = metadata.get("authorization_servers")
    if not isinstance(raw_servers, list) or not raw_servers:
        raise OAuthError("Protected resource metadata missing non-empty 'authorization_servers'.")

    selected_as: str | None = None
    for entry in raw_servers:
        if not isinstance(entry, str) or not entry.strip():
            continue
        try:
            norm_entry = validate_outbound_url(
                entry, allowed_domains=allowed_domains, allow_loopback_http=allow_loopback_http
            ).rstrip("/")
        except ValueError:
            continue
        if norm_entry in pinned_set:
            selected_as = norm_entry
            break
    if selected_as is None:
        raise OAuthError(
            "No authorization server in protected resource metadata is allowlisted by policy (fail-closed)."
        )

    scopes_raw = metadata.get("scopes_supported")
    scopes: list[str] = []
    if isinstance(scopes_raw, list):
        scopes = [s.strip() for s in scopes_raw if isinstance(s, str) and s.strip()]
    return selected_as, tuple(scopes)


def _as_well_known_candidates(issuer_url: str) -> tuple[str, ...]:
    parsed = urllib.parse.urlparse(canonical_resource_uri(issuer_url))
    path = parsed.path.rstrip("/")
    origin = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    if not path:
        return (
            f"{origin}/.well-known/oauth-authorization-server",
            f"{origin}/.well-known/openid-configuration",
        )
    return (
        f"{origin}/.well-known/oauth-authorization-server{path}",
        f"{origin}/.well-known/openid-configuration{path}",
        f"{origin}{path}/.well-known/openid-configuration",
    )


def discover_authorization_server(
    issuer_url: str,
    *,
    allowed_domains: frozenset[str] | None = None,
    timeout: float = DEFAULT_OAUTH_TIMEOUT_SECONDS,
    opener: urllib.request.OpenerDirector | None = None,
    allow_loopback_http: bool = False,
    require_same_origin_endpoints: bool = True,
) -> dict[str, Any]:
    """
    Fetch and validate RFC 8414 / OIDC authorization server metadata fail-closed.

    Verifies `metadata["issuer"]` exact match (RFC 8414 Section 3.3) and validates advertised endpoints.
    """
    norm_issuer = validate_outbound_url(
        issuer_url, allowed_domains=allowed_domains, allow_loopback_http=allow_loopback_http
    ).rstrip("/")
    eff_opener = opener or build_safe_opener(bypass_ambient_proxy=allow_loopback_http)
    candidates = _as_well_known_candidates(norm_issuer)

    metadata: dict[str, Any] | None = None
    last_err: OAuthError | None = None
    for idx, candidate in enumerate(candidates):
        try:
            metadata = _http_get_json(candidate, opener=eff_opener, timeout=timeout)
            break
        except OAuthError as exc:
            last_err = exc
            if "HTTP 404" in str(exc) and idx < len(candidates) - 1:
                continue
            raise
    if metadata is None:
        raise last_err or OAuthError("Authorization server metadata discovery failed.")

    meta_issuer = metadata.get("issuer")
    if not isinstance(meta_issuer, str) or canonical_resource_uri(meta_issuer).rstrip("/") != norm_issuer:
        raise OAuthError("Authorization server metadata 'issuer' mismatch (RFC 8414 validation failed).")

    token_ep = metadata.get("token_endpoint")
    if not isinstance(token_ep, str):
        raise OAuthError("Authorization server metadata missing string 'token_endpoint'.")
    validated_token_ep = validate_outbound_url(
        token_ep, allowed_domains=allowed_domains, allow_loopback_http=allow_loopback_http
    )
    issuer_origin = _origin_tuple(norm_issuer)
    if require_same_origin_endpoints and _origin_tuple(validated_token_ep) != issuer_origin:
        raise OAuthError("Authorization server 'token_endpoint' origin does not match issuer.")

    out = dict(metadata)
    out["token_endpoint"] = validated_token_ep
    auth_ep = metadata.get("authorization_endpoint")
    if auth_ep is not None:
        if not isinstance(auth_ep, str):
            raise OAuthError("Authorization server 'authorization_endpoint' must be a string.")
        validated_auth_ep = validate_outbound_url(
            auth_ep, allowed_domains=allowed_domains, allow_loopback_http=allow_loopback_http
        )
        if require_same_origin_endpoints and _origin_tuple(validated_auth_ep) != issuer_origin:
            raise OAuthError("Authorization server 'authorization_endpoint' origin does not match issuer.")
        out["authorization_endpoint"] = validated_auth_ep
    return out


def _post_token_form(
    token_endpoint: str,
    form: Mapping[str, str],
    *,
    allowed_domains: frozenset[str] | None,
    timeout: float,
    opener: urllib.request.OpenerDirector,
    allow_loopback_http: bool,
) -> OAuthToken:
    endpoint = validate_outbound_url(
        token_endpoint, allowed_domains=allowed_domains, allow_loopback_http=allow_loopback_http
    )
    body = urllib.parse.urlencode(dict(form)).encode("utf-8")
    req = urllib.request.Request(  # noqa: S310 - endpoint validated by validate_outbound_url
        endpoint,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    deadline = time.monotonic() + timeout
    try:
        with opener.open(req, timeout=timeout) as resp:  # noqa: S310 - scheme/host validated
            raw = read_bounded_bytes(resp, max_bytes=MAX_OAUTH_RESPONSE_BYTES, deadline=deadline)
    except OAuthError:
        raise
    except urllib.error.HTTPError as exc:
        raise OAuthError(f"Token endpoint returned HTTP {exc.code}.") from exc
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        raise OAuthError(f"Token request failed: {exc}") from exc

    try:
        parsed = strict_json_loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, StrictJsonError) as exc:
        raise OAuthError(f"Malformed JSON from token endpoint: {exc}") from exc
    if not isinstance(parsed, dict):
        raise OAuthError("Token endpoint response must be a JSON object.")

    err_code = parsed.get("error")
    if isinstance(err_code, str) and err_code:
        raise OAuthError(f"Token endpoint returned OAuth error '{err_code}'.")

    access_token = parsed.get("access_token")
    token_type = parsed.get("token_type", "Bearer")
    if not isinstance(access_token, str) or not access_token or _CONTROL_CHARS_RE.search(access_token):
        raise OAuthError("Token endpoint did not return a valid 'access_token'.")
    if not isinstance(token_type, str) or token_type.strip().lower() != "bearer":
        raise OAuthError(f"Unsupported OAuth token_type {token_type!r}; expected Bearer.")

    expires_at: float | None = None
    expires_in = parsed.get("expires_in")
    if expires_in is not None:
        if (
            isinstance(expires_in, bool)
            or not isinstance(expires_in, int | float)
            or not math.isfinite(float(expires_in))
            or expires_in <= 0
        ):
            raise OAuthError("Token endpoint returned invalid 'expires_in'.")
        expires_at = time.time() + float(expires_in)

    refresh_token = parsed.get("refresh_token")
    if refresh_token is not None and (not isinstance(refresh_token, str) or not refresh_token):
        refresh_token = None
    scope = parsed.get("scope")
    if scope is not None and not isinstance(scope, str):
        scope = None

    return OAuthToken(
        access_token=access_token,
        token_type="Bearer",  # noqa: S106 - OAuth RFC 6750 scheme name
        expires_at=expires_at,
        refresh_token=refresh_token,
        scope=scope,
    )


def fetch_client_credentials_token(
    token_endpoint: str,
    *,
    client_id: str,
    client_secret: str,
    resource: str | None = None,
    scopes: Sequence[str] = (),
    allowed_domains: frozenset[str] | None = None,
    timeout: float = DEFAULT_OAUTH_TIMEOUT_SECONDS,
    opener: urllib.request.OpenerDirector | None = None,
    allow_loopback_http: bool = False,
) -> OAuthToken:
    """Acquire an OAuth 2.1 token using the `client_credentials` grant with optional RFC 8707 `resource`."""
    form: dict[str, str] = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    if scopes:
        form["scope"] = " ".join(scopes)
    if resource:
        form["resource"] = canonical_resource_uri(resource)
    eff_opener = opener or build_safe_opener(bypass_ambient_proxy=allow_loopback_http)
    return _post_token_form(
        token_endpoint,
        form,
        allowed_domains=allowed_domains,
        timeout=timeout,
        opener=eff_opener,
        allow_loopback_http=allow_loopback_http,
    )


def exchange_authorization_code(
    token_endpoint: str,
    *,
    client_id: str,
    code: str,
    redirect_uri: str,
    code_verifier: str,
    client_secret: str | None = None,
    resource: str | None = None,
    allowed_domains: frozenset[str] | None = None,
    timeout: float = DEFAULT_OAUTH_TIMEOUT_SECONDS,
    opener: urllib.request.OpenerDirector | None = None,
    allow_loopback_http: bool = False,
) -> OAuthToken:
    """Exchange a PKCE `authorization_code` for an OAuth 2.1 access token (RFC 7636 + RFC 8707)."""
    form: dict[str, str] = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    if client_secret:
        form["client_secret"] = client_secret
    if resource:
        form["resource"] = canonical_resource_uri(resource)
    eff_opener = opener or build_safe_opener(bypass_ambient_proxy=allow_loopback_http)
    return _post_token_form(
        token_endpoint,
        form,
        allowed_domains=allowed_domains,
        timeout=timeout,
        opener=eff_opener,
        allow_loopback_http=allow_loopback_http,
    )


def refresh_access_token(
    token_endpoint: str,
    *,
    client_id: str,
    refresh_token: str,
    client_secret: str | None = None,
    resource: str | None = None,
    scopes: Sequence[str] = (),
    allowed_domains: frozenset[str] | None = None,
    timeout: float = DEFAULT_OAUTH_TIMEOUT_SECONDS,
    opener: urllib.request.OpenerDirector | None = None,
    allow_loopback_http: bool = False,
) -> OAuthToken:
    """Refresh an expired OAuth 2.1 token fail-closed."""
    form: dict[str, str] = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh_token,
    }
    if client_secret:
        form["client_secret"] = client_secret
    if scopes:
        form["scope"] = " ".join(scopes)
    if resource:
        form["resource"] = canonical_resource_uri(resource)
    eff_opener = opener or build_safe_opener(bypass_ambient_proxy=allow_loopback_http)
    return _post_token_form(
        token_endpoint,
        form,
        allowed_domains=allowed_domains,
        timeout=timeout,
        opener=eff_opener,
        allow_loopback_http=allow_loopback_http,
    )


def run_pkce_flow(
    authorization_endpoint: str,
    token_endpoint: str,
    *,
    client_id: str,
    client_secret: str | None = None,
    resource: str | None = None,
    scopes: Sequence[str] = (),
    allowed_domains: frozenset[str] | None = None,
    timeout: float = DEFAULT_PKCE_TIMEOUT_SECONDS,
    opener: urllib.request.OpenerDirector | None = None,
    authorize_callback: Callable[[str], None] | None = None,
    allow_loopback_http: bool = False,
) -> OAuthToken:
    """Run an OAuth 2.1 Authorization Code + PKCE (`S256`) flow via an ephemeral loopback callback."""
    auth_ep = validate_outbound_url(
        authorization_endpoint, allowed_domains=allowed_domains, allow_loopback_http=allow_loopback_http
    )
    verifier, challenge = generate_pkce_pair()
    expected_state = secrets.token_urlsafe(32)
    done_event = threading.Event()
    result_box: dict[str, str] = {}

    class _CallbackHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            del format, args

        def do_GET(self) -> None:  # noqa: N802 - stdlib HTTP method
            host_hdr = (self.headers.get("Host") or "").strip().lower()
            host_only = host_hdr.partition(":")[0]
            if host_only not in ("127.0.0.1", "localhost"):
                self.send_response(HTTPStatus.MISDIRECTED_REQUEST)
                self.end_headers()
                return
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != "/callback":
                self.send_response(HTTPStatus.NOT_FOUND)
                self.end_headers()
                return
            qs = urllib.parse.parse_qs(parsed.query)
            recv_state = qs.get("state", [""])[0]
            if not recv_state or not hmac.compare_digest(recv_state, expected_state):
                result_box["error"] = "OAuth state mismatch (possible CSRF callback)."
                self.send_response(HTTPStatus.BAD_REQUEST)
                self.end_headers()
                self.wfile.write(b"Invalid OAuth state.")
                done_event.set()
                return
            if "error" in qs:
                result_box["error"] = f"Authorization error: {qs['error'][0]}"
            elif "code" in qs and qs["code"][0]:
                result_box["code"] = qs["code"][0]
            else:
                result_box["error"] = "Authorization callback missing code parameter."
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Mellyn Security authorization complete. You may close this window.")
            done_event.set()

    server = ThreadingHTTPServer(("127.0.0.1", 0), _CallbackHandler)
    server.daemon_threads = True
    port = server.server_port
    redirect_uri = f"http://127.0.0.1:{port}/callback"
    srv_thread = threading.Thread(target=server.serve_forever, name="mellyn-oauth-pkce", daemon=True)
    srv_thread.start()

    try:
        query_params: dict[str, str] = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": expected_state,
        }
        if scopes:
            query_params["scope"] = " ".join(scopes)
        if resource:
            query_params["resource"] = canonical_resource_uri(resource)
        sep = "&" if "?" in auth_ep else "?"
        authorize_url = f"{auth_ep}{sep}{urllib.parse.urlencode(query_params)}"

        if authorize_callback is not None:
            authorize_callback(authorize_url)
        else:
            print(f"Authorize Mellyn MCP client in browser: {authorize_url}", file=sys.stderr)

        if not done_event.wait(timeout=timeout):
            raise OAuthError("Timed out waiting for OAuth PKCE authorization callback.")
    finally:
        server.shutdown()
        server.server_close()
        srv_thread.join(timeout=2.0)

    if "error" in result_box:
        raise OAuthError(result_box["error"])
    code = result_box.get("code")
    if not code:
        raise OAuthError("OAuth callback completed without an authorization code.")

    return exchange_authorization_code(
        token_endpoint,
        client_id=client_id,
        code=code,
        redirect_uri=redirect_uri,
        code_verifier=verifier,
        client_secret=client_secret,
        resource=resource,
        allowed_domains=allowed_domains,
        timeout=min(timeout, DEFAULT_OAUTH_TIMEOUT_SECONDS),
        opener=opener,
        allow_loopback_http=allow_loopback_http,
    )


class OAuthTokenProvider:
    """Thread-safe OAuth 2.1 credential manager for one remote Streamable HTTP MCP server."""

    def __init__(
        self,
        config: OAuthClientConfig,
        *,
        resource_url: str,
        allowed_domains: frozenset[str] | None = None,
        proxy_url: str | None = None,
        ssl_context: ssl.SSLContext | None = None,
        authorize_callback: Callable[[str], None] | None = None,
        timeout: float = DEFAULT_OAUTH_TIMEOUT_SECONDS,
        _allow_loopback_http: bool = False,
    ) -> None:
        self.config = config
        self.allow_loopback_http = _allow_loopback_http or config.allow_insecure_loopback_for_tests
        self.resource_url = validate_outbound_url(
            resource_url,
            allowed_domains=allowed_domains,
            allow_loopback_http=self.allow_loopback_http,
        )
        self.resource = canonical_resource_uri(config.resource or self.resource_url)
        self.allowed_domains = allowed_domains
        self.opener = build_safe_opener(
            proxy_url=proxy_url,
            ssl_context=ssl_context,
            bypass_ambient_proxy=self.allow_loopback_http and proxy_url is None,
        )
        self.authorize_callback = authorize_callback
        self.timeout = timeout
        self._lock = threading.Lock()
        self._cache_write_warned = False
        self._token: OAuthToken | None = self._load_cached_token()

    @staticmethod
    def _is_link_or_junction(path: Path) -> bool:
        return path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)())

    def _load_cached_token(self) -> OAuthToken | None:
        path = self.config.token_cache_path
        if path is None or not path.exists():
            return None
        if self._is_link_or_junction(path) or self._is_link_or_junction(path.parent) or not path.is_file():
            raise OAuthError(f"Refusing unsafe OAuth token cache path '{path}'.")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise OAuthError(f"Refusing unsafe OAuth token cache path '{path}': {exc}") from exc
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise OAuthError(f"Refusing non-regular OAuth token cache '{path}'.")
            if os.name == "posix" and (st.st_uid != os.getuid() or (st.st_mode & 0o077) != 0):
                raise OAuthError(f"Refusing insecure permissions or ownership on OAuth token cache '{path}'.")
            if st.st_size > 65_536:
                return None
            with os.fdopen(fd, "rb") as handle:
                raw = handle.read(65_537)
                fd = -1
            if len(raw) > 65_536:
                return None
            data = strict_json_loads(raw)
        except OAuthError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, StrictJsonError):
            return None
        finally:
            if fd >= 0:
                os.close(fd)

        if not isinstance(data, dict):
            return None
        if data.get("binding") != self._cache_binding():
            # Issued for another server, authorization server, client, flow, or scopes:
            # sending it here would hand one server's credential to another or widen scopes.
            return None
        access = data.get("access_token")
        if not isinstance(access, str) or not access or _CONTROL_CHARS_RE.search(access):
            return None
        exp = data.get("expires_at")
        if isinstance(exp, bool) or not isinstance(exp, int | float):
            expires_at = None
        else:
            exp_f = float(exp)
            if not math.isfinite(exp_f):
                return None
            expires_at = exp_f
        raw_refresh = data.get("refresh_token")
        refresh = (
            raw_refresh
            if isinstance(raw_refresh, str) and raw_refresh and not _CONTROL_CHARS_RE.search(raw_refresh)
            else None
        )
        scope = data.get("scope") if isinstance(data.get("scope"), str) else None
        return OAuthToken(access_token=access, expires_at=expires_at, refresh_token=refresh, scope=scope)

    def _cache_binding(self) -> dict[str, Any]:
        """What a cached token was issued for. A cache is only reused when all of it matches."""
        client = self.config.client_id if self.config.client_id is not None else f"env:{self.config.client_id_env}"
        return {
            "resource": self.resource,
            "authorization_servers": sorted(self.config.allowed_authorization_servers),
            "client": client,
            "flow": self.config.flow,
            "scopes": sorted(self.config.scopes),
        }

    def _save_cached_token(self, token: OAuthToken | None) -> None:
        path = self.config.token_cache_path
        if path is None:
            return
        if self._is_link_or_junction(path) or self._is_link_or_junction(path.parent):
            raise OAuthError(f"Refusing symlink or junction OAuth token cache path '{path}'.")
        if token is None:
            if path.is_file():
                try:
                    path.unlink()
                except OSError:
                    pass
            return
        tmp_path: Path | None = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            tmp_path = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(tmp_path, flags, 0o600)
            try:
                if os.name == "posix":
                    os.fchmod(fd, 0o600)
                payload = (
                    json.dumps(
                        {
                            "binding": self._cache_binding(),
                            "access_token": token.access_token,
                            "token_type": token.token_type,
                            "expires_at": token.expires_at,
                            "refresh_token": token.refresh_token,
                            "scope": token.scope,
                        },
                        sort_keys=True,
                    )
                    + "\n"
                ).encode("utf-8")
                view = memoryview(payload)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp_path, path)
            tmp_path = None
        except OSError as exc:
            # A cache is an optimisation. Failing here (for example a path inside a read-only config mount) used to
            # fail every call after a fresh token had been fetched; the token is kept in memory instead.
            if not self._cache_write_warned:
                self._cache_write_warned = True
                print(
                    f"mellyn: could not write OAuth token cache '{path}' ({exc}); keeping the token in memory only.",
                    file=sys.stderr,
                )
        finally:
            if tmp_path is not None:
                try:
                    tmp_path.unlink(missing_ok=True)
                except OSError:
                    pass

    def _resolve_client_id(self) -> str:
        if self.config.client_id is not None:
            return self.config.client_id
        env_name = self.config.client_id_env or ""
        val = os.environ.get(env_name, "").strip()
        if not val:
            raise OAuthError(f"Missing OAuth client_id environment variable '{env_name}'.")
        return val

    def _resolve_client_secret(self) -> str | None:
        if self.config.client_secret_env is None:
            return None
        val = os.environ.get(self.config.client_secret_env, "").strip()
        if not val:
            raise OAuthError(f"Missing OAuth client_secret environment variable '{self.config.client_secret_env}'.")
        return val

    def _resolve_endpoints(self, www_authenticate: str | None = None) -> tuple[str | None, str, tuple[str, ...]]:
        if self.config.token_endpoint is not None:
            return self.config.authorization_endpoint, self.config.token_endpoint, self.config.scopes

        try:
            issuer, prm_scopes = discover_protected_resource(
                self.resource_url,
                allowed_authorization_servers=self.config.allowed_authorization_servers,
                www_authenticate=www_authenticate,
                allowed_domains=self.allowed_domains,
                timeout=self.timeout,
                opener=self.opener,
                allow_loopback_http=self.allow_loopback_http,
            )
        except OAuthError as exc:
            if "HTTP 404" in str(exc) and len(self.config.allowed_authorization_servers) == 1 and not www_authenticate:
                issuer = self.config.allowed_authorization_servers[0]
                prm_scopes = ()
            else:
                raise

        as_meta = discover_authorization_server(
            issuer,
            allowed_domains=self.allowed_domains,
            timeout=self.timeout,
            opener=self.opener,
            allow_loopback_http=self.allow_loopback_http,
        )
        if self.config.flow == "pkce":
            methods = as_meta.get("code_challenge_methods_supported")
            if isinstance(methods, list) and "S256" not in methods:
                raise OAuthError("Authorization server does not advertise PKCE S256 support.")
        eff_scopes = self.config.scopes if self.config.scopes else prm_scopes
        return as_meta.get("authorization_endpoint"), str(as_meta["token_endpoint"]), eff_scopes

    def _acquire_locked(self, *, www_authenticate: str | None = None, force_refresh: bool = False) -> OAuthToken:
        if self.config.flow == "bearer_env":
            env_name = self.config.bearer_token_env or ""
            raw = os.environ.get(env_name, "").strip()
            if not raw or _CONTROL_CHARS_RE.search(raw):
                raise OAuthError(f"Missing or invalid OAuth bearer token in environment variable '{env_name}'.")
            token = OAuthToken(access_token=raw)
            self._token = token
            return token

        if not force_refresh and self._token is not None and not self._token.is_expired():
            return self._token

        auth_ep, token_ep, scopes = self._resolve_endpoints(www_authenticate=www_authenticate)
        client_id = self._resolve_client_id()
        client_secret = self._resolve_client_secret()

        if self._token is not None and self._token.refresh_token:
            try:
                refreshed = refresh_access_token(
                    token_ep,
                    client_id=client_id,
                    refresh_token=self._token.refresh_token,
                    client_secret=client_secret,
                    resource=self.resource,
                    scopes=scopes,
                    allowed_domains=self.allowed_domains,
                    timeout=self.timeout,
                    opener=self.opener,
                    allow_loopback_http=self.allow_loopback_http,
                )
                self._token = refreshed
                self._save_cached_token(refreshed)
                return refreshed
            except OAuthError:
                self._token = None

        if self.config.flow == "client_credentials":
            secret_val = client_secret or ""
            if not secret_val:
                raise OAuthError("Missing client_secret for client_credentials grant.")
            acquired = fetch_client_credentials_token(
                token_ep,
                client_id=client_id,
                client_secret=secret_val,
                resource=self.resource,
                scopes=scopes,
                allowed_domains=self.allowed_domains,
                timeout=self.timeout,
                opener=self.opener,
                allow_loopback_http=self.allow_loopback_http,
            )
        else:
            if not auth_ep:
                raise OAuthError("Authorization server metadata missing 'authorization_endpoint' for PKCE flow.")
            acquired = run_pkce_flow(
                auth_ep,
                token_ep,
                client_id=client_id,
                client_secret=client_secret,
                resource=self.resource,
                scopes=scopes,
                allowed_domains=self.allowed_domains,
                opener=self.opener,
                authorize_callback=self.authorize_callback,
                allow_loopback_http=self.allow_loopback_http,
            )

        self._token = acquired
        self._save_cached_token(acquired)
        return acquired

    def get_authorization_header(self) -> str:
        """Return `"Bearer <token>"`, acquiring or refreshing when needed."""
        with self._lock:
            token = self._acquire_locked()
            return f"Bearer {token.access_token}"

    def handle_unauthorized(self, www_authenticate: str | None = None) -> str:
        """Acquire a fresh token after HTTP 401 (running RFC 9728 discovery on the challenge)."""
        with self._lock:
            token = self._acquire_locked(www_authenticate=www_authenticate, force_refresh=True)
            return f"Bearer {token.access_token}"

    def clear_tokens(self) -> None:
        """Wipe in-memory and cached tokens immediately (AAD containment)."""
        with self._lock:
            self._token = None
            try:
                self._save_cached_token(None)
            except OAuthError:
                pass

    def forget_in_memory(self) -> None:
        """Drop the in-memory token on a clean close, keeping the cache so the next start need not sign in again."""
        with self._lock:
            self._token = None


__all__ = [
    "DEFAULT_OAUTH_TIMEOUT_SECONDS",
    "DEFAULT_PKCE_TIMEOUT_SECONDS",
    "MAX_OAUTH_RESPONSE_BYTES",
    "OAuthClientConfig",
    "OAuthError",
    "OAuthToken",
    "OAuthTokenProvider",
    "build_safe_opener",
    "canonical_resource_uri",
    "discover_authorization_server",
    "discover_protected_resource",
    "exchange_authorization_code",
    "extract_url_host",
    "fetch_client_credentials_token",
    "generate_pkce_pair",
    "parse_www_authenticate_bearer",
    "read_bounded_bytes",
    "refresh_access_token",
    "run_pkce_flow",
    "validate_outbound_url",
]
