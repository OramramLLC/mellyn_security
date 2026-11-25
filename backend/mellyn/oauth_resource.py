"""
Stdlib OAuth 2.1 Resource Server (RFC 9728) and JWT/JWKS validator for upstream Streamable HTTP.

Supports pure-stdlib RSA PKCS#1 v1.5 (`RS256`, `RS384`, `RS512`) and optional `cryptography`-backed
ECDSA / EdDSA (`ES256`, `ES384`, `ES512`, `EdDSA`), strict header/claim checks (`iss`, `aud`, `exp`,
`nbf`, `sub`, `scope`/`scp`), RFC 9728 Protected Resource Metadata generation, and dual-mode `[auth]`
configuration (`hmac` quickstart or `oidc` SSO).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import ssl
import threading
import time
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from mellyn.audit import redact_text
from mellyn.credentials import Role
from mellyn.egress import EgressValidator
from mellyn.egress_proxy import validate_egress_domain
from mellyn.oauth_client import (
    DEFAULT_OAUTH_TIMEOUT_SECONDS,
    MAX_OAUTH_RESPONSE_BYTES,
    OAuthError,
    build_safe_opener,
    canonical_resource_uri,
    discover_authorization_server,
    read_bounded_bytes,
    validate_outbound_url,
)

MAX_JWT_CHARS = 16_384
MAX_SUB_CHARS = 256
MAX_DISPLAY_ID_CHARS = 128
MAX_CLOCK_SKEW_SECONDS = 300
DEFAULT_JWKS_CACHE_TTL_SECONDS = 300.0
MIN_JWKS_REFRESH_INTERVAL_SECONDS = 30.0

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_ALLOWED_TYP: frozenset[str] = frozenset({"jwt", "at+jwt", "application/jwt", "application/at+jwt"})
_FORBIDDEN_HDR_KEYS: frozenset[str] = frozenset({"jwk", "jku", "x5u", "x5c"})

# RFC 8017 Section 9.2 EMSA-PKCS1-v1_5 DER DigestInfo prefixes paired with hashlib digest factory.
_RSA_DIGEST_SPECS: dict[str, tuple[bytes, Callable[[bytes], Any]]] = {
    "RS256": (bytes.fromhex("3031300d060960864801650304020105000420"), hashlib.sha256),
    "RS384": (bytes.fromhex("3041300d060960864801650304020205000430"), hashlib.sha384),
    "RS512": (bytes.fromhex("3051300d060960864801650304020305000440"), hashlib.sha512),
}
_ECDSA_ALGS: frozenset[str] = frozenset({"ES256", "ES384", "ES512"})
_EDDSA_ALGS: frozenset[str] = frozenset({"EdDSA"})
_SUPPORTED_ALGS: frozenset[str] = frozenset(_RSA_DIGEST_SPECS) | _ECDSA_ALGS | _EDDSA_ALGS


class OAuthResourceError(RuntimeError):
    """Fail-closed error raised when OIDC bearer authentication or authorization fails."""

    def __init__(
        self,
        message: str,
        *,
        http_status: int = 401,
        oauth_error: str = "invalid_token",
        required_scope: str | None = None,
    ) -> None:
        super().__init__(message)
        self.http_status = http_status
        self.oauth_error = oauth_error
        self.required_scope = required_scope


def _strict_json_loads(raw_text: str, *, label: str) -> Any:
    def _reject_dup_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise OAuthResourceError(f"Duplicate JSON key '{key}' in {label}.")
            out[key] = value
        return out

    try:
        return json.loads(raw_text, object_pairs_hook=_reject_dup_keys)
    except OAuthResourceError:
        raise
    except (ValueError, json.JSONDecodeError) as exc:
        raise OAuthResourceError(f"Malformed JSON in {label}: {exc}") from exc


def _b64url_decode(segment: str, *, label: str) -> bytes:
    if not isinstance(segment, str) or not segment or not _B64URL_RE.fullmatch(segment):
        raise OAuthResourceError(f"Malformed base64url segment in {label}.")
    pad_len = (4 - (len(segment) % 4)) % 4
    if pad_len == 3:
        raise OAuthResourceError(f"Invalid base64url length in {label}.")
    try:
        return base64.urlsafe_b64decode(segment + ("=" * pad_len))
    except ValueError as exc:
        raise OAuthResourceError(f"Invalid base64url encoding in {label}: {exc}") from exc


def _clean_str_tuple(values: Sequence[str], *, field_label: str) -> tuple[str, ...]:
    cleaned: list[str] = []
    seen: set[str] = set()
    for item in values:
        if not isinstance(item, str) or not item.strip() or _CONTROL_CHARS_RE.search(item):
            raise ValueError(f"{field_label} entries must be non-empty strings without control characters.")
        val = item.strip()
        if val not in seen:
            seen.add(val)
            cleaned.append(val)
    return tuple(cleaned)


def normalize_origin(raw_origin: str) -> str:
    """
    Validate and normalize a browser HTTP `Origin` (`scheme://host[:port]`).

    Allows `http://` only for explicit loopback origins (`127.0.0.1`, `localhost`, `[::1]`)
    and requires `https://` for all non-loopback origins. Rejects paths, queries, fragments,
    embedded credentials, IPv6 syntax errors, and `.local` hosts.
    """
    if not isinstance(raw_origin, str) or not raw_origin.strip() or _CONTROL_CHARS_RE.search(raw_origin):
        raise ValueError("Origin must be a non-empty string without control characters.")
    trimmed = raw_origin.strip()
    try:
        parsed = urllib.parse.urlparse(trimmed)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Malformed Origin URL authority or port.") from exc

    if parsed.path or parsed.params or parsed.query or parsed.fragment:
        raise ValueError(f"Origin '{trimmed}' must not include a path, query string, or fragment.")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise ValueError("Origin must not include embedded credentials/userinfo.")

    hostport = parsed.netloc
    if "]" in hostport:
        _, _, after_bracket = hostport.rpartition("]")
        has_colon_port = ":" in after_bracket
    else:
        has_colon_port = ":" in hostport
    if has_colon_port and (port is None or port <= 0):
        raise ValueError("Origin specifies an empty or invalid port.")

    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").strip().lower().rstrip(".")
    if not hostname:
        raise ValueError("Origin is missing a valid hostname.")

    is_loopback = hostname in ("127.0.0.1", "localhost", "::1")
    if is_loopback:
        if scheme not in ("http", "https"):
            raise ValueError(f"Disallowed Origin scheme '{parsed.scheme}'; expected http or https.")
    else:
        if scheme != "https":
            raise ValueError(f"Disallowed Origin scheme '{parsed.scheme}'; non-loopback origins require https.")
        if hostname.endswith(".localhost") or hostname.endswith(".local"):
            raise ValueError(f"Disallowed .local/.localhost origin host '{hostname}'.")
        if EgressValidator._is_ip_literal(hostname):
            raise ValueError("Direct non-loopback IP literals are forbidden in allowed_origins.")
        hostname = validate_egress_domain(hostname)

    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        port = None
    host_fmt = f"[{hostname}]" if ":" in hostname else hostname
    return f"{scheme}://{host_fmt}:{port}" if port is not None else f"{scheme}://{host_fmt}"


def normalize_allowed_host(raw_host: str) -> str:
    """Validate and normalize a bare HTTP `Host` allowlist entry (hostname without scheme/path/port)."""
    if not isinstance(raw_host, str) or not raw_host.strip() or _CONTROL_CHARS_RE.search(raw_host):
        raise ValueError("allowed_hosts entries must be non-empty hostnames without control characters.")
    candidate = raw_host.strip().lower().rstrip(".")
    if any(ch in candidate for ch in ("/", "\\", "?", "#", "@", " ")):
        raise ValueError(f"allowed_hosts entry '{raw_host}' must be a bare hostname without scheme, path, or userinfo.")
    if candidate.startswith("[") and candidate.endswith("]"):
        inner = candidate[1:-1]
        if inner == "::1":
            return "::1"
        raise ValueError(f"Invalid IPv6 host literal '{raw_host}' in allowed_hosts.")
    if ":" in candidate and candidate != "::1":
        raise ValueError(f"allowed_hosts entry '{raw_host}' must not contain a port number.")
    if candidate in ("127.0.0.1", "localhost", "::1"):
        return candidate
    if candidate.endswith(".localhost") or candidate.endswith(".local"):
        raise ValueError(f"allowed_hosts cannot contain '.local' or '.localhost': '{raw_host}'.")
    return validate_egress_domain(candidate)


@dataclass(frozen=True)
class AuthConfig:
    """Dual-mode `[auth]` configuration (`hmac` quickstart or `oidc` OAuth 2.1 Resource Server)."""

    mode: Literal["hmac", "oidc"] = "hmac"
    issuer: str | None = None
    audience: str | None = None
    resource: str | None = None
    jwks_uri: str | None = None
    required_scopes: tuple[str, ...] = ()
    approver_scopes: tuple[str, ...] = ()
    approver_subjects: tuple[str, ...] = ()
    approver_groups: tuple[str, ...] = ()
    allowed_origins: tuple[str, ...] = ()
    allowed_hosts: tuple[str, ...] = ()
    clock_skew_seconds: int = 60
    allow_insecure_loopback_for_tests: bool = False

    def __post_init__(self) -> None:
        if self.mode not in ("hmac", "oidc"):
            raise ValueError(f"Unsupported auth.mode {self.mode!r}; expected 'hmac' or 'oidc'.")
        if (
            isinstance(self.clock_skew_seconds, bool)
            or not isinstance(self.clock_skew_seconds, int)
            or not 0 <= self.clock_skew_seconds <= MAX_CLOCK_SKEW_SECONDS
        ):
            raise ValueError(f"auth.clock_skew_seconds must be an integer between 0 and {MAX_CLOCK_SKEW_SECONDS}.")

        norm_origins: list[str] = []
        seen_origins: set[str] = set()
        for raw_origin in self.allowed_origins:
            norm = normalize_origin(raw_origin)
            if norm not in seen_origins:
                seen_origins.add(norm)
                norm_origins.append(norm)
        object.__setattr__(self, "allowed_origins", tuple(norm_origins))

        norm_hosts: list[str] = []
        seen_hosts: set[str] = set()
        for raw_host in self.allowed_hosts:
            norm = normalize_allowed_host(raw_host)
            if norm not in seen_hosts:
                seen_hosts.add(norm)
                norm_hosts.append(norm)
        object.__setattr__(self, "allowed_hosts", tuple(norm_hosts))

        req_scopes = _clean_str_tuple(self.required_scopes, field_label="auth.required_scopes")
        app_scopes = _clean_str_tuple(self.approver_scopes, field_label="auth.approver_scopes")
        app_subjects = _clean_str_tuple(self.approver_subjects, field_label="auth.approver_subjects")
        app_groups = _clean_str_tuple(self.approver_groups, field_label="auth.approver_groups")
        object.__setattr__(self, "required_scopes", req_scopes)
        object.__setattr__(self, "approver_scopes", app_scopes)
        object.__setattr__(self, "approver_subjects", app_subjects)
        object.__setattr__(self, "approver_groups", app_groups)

        if self.mode == "hmac":
            if any(
                (
                    self.issuer is not None,
                    self.audience is not None,
                    self.resource is not None,
                    self.jwks_uri is not None,
                    req_scopes,
                    app_scopes,
                    app_subjects,
                    app_groups,
                )
            ):
                raise ValueError(
                    "OIDC settings (issuer, audience, resource, jwks_uri, scopes, approvers) "
                    "require auth.mode = 'oidc'."
                )
            return

        allow_lb = self.allow_insecure_loopback_for_tests
        if self.issuer is None or not self.issuer.strip():
            raise ValueError("auth.mode = 'oidc' requires a valid auth.issuer URL.")
        norm_issuer = validate_outbound_url(self.issuer, allow_loopback_http=allow_lb).rstrip("/")
        if urllib.parse.urlparse(norm_issuer).query:
            raise ValueError("auth.issuer must not contain a query string.")
        object.__setattr__(self, "issuer", norm_issuer)

        if (app_subjects or app_groups) and not app_scopes:
            raise ValueError(
                "auth.approver_subjects / auth.approver_groups need auth.approver_scopes: approval must use a token "
                "carrying an approver scope, distinct from the agent's token, or the agent could approve its own calls."
            )
        if app_scopes and set(app_scopes) & set(req_scopes):
            raise ValueError("auth.approver_scopes must not overlap auth.required_scopes (the agent token's scopes).")

        if self.audience is None or not self.audience.strip() or _CONTROL_CHARS_RE.search(self.audience):
            raise ValueError("auth.mode = 'oidc' requires a non-empty auth.audience without control characters.")
        object.__setattr__(self, "audience", self.audience.strip())

        if self.resource is not None:
            object.__setattr__(self, "resource", validate_outbound_url(self.resource, allow_loopback_http=allow_lb))
        if self.jwks_uri is not None:
            object.__setattr__(self, "jwks_uri", validate_outbound_url(self.jwks_uri, allow_loopback_http=allow_lb))


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """Verified caller identity produced by HMAC or OIDC request authentication."""

    subject: str
    auth_mode: Literal["hmac", "oidc"]
    display_identity: str
    scopes: frozenset[str]
    roles: frozenset[Role]
    issuer: str | None = None
    expires_at: float | None = None


def _verify_rsa_pkcs1v15(signing_input: bytes, signature: bytes, jwk: Mapping[str, Any], alg: str) -> bool:
    """Verify RSA PKCS#1 v1.5 (`RS256`, `RS384`, `RS512`) using pure Python stdlib arithmetic."""
    if jwk.get("kty") != "RSA":
        raise OAuthResourceError(f"JWK kty mismatch for algorithm '{alg}'.")
    n_raw = jwk.get("n")
    e_raw = jwk.get("e")
    if not isinstance(n_raw, str) or not isinstance(e_raw, str):
        raise OAuthResourceError("RSA JWK missing 'n' or 'e' modulus/exponent.")

    n_bytes = _b64url_decode(n_raw, label="JWK.n")
    e_bytes = _b64url_decode(e_raw, label="JWK.e")
    n = int.from_bytes(n_bytes, "big")
    e = int.from_bytes(e_bytes, "big")
    if n.bit_length() < 2048:
        raise OAuthResourceError("RSA JWK modulus must be at least 2048 bits.")
    if e < 3 or e % 2 == 0:
        raise OAuthResourceError("RSA JWK exponent must be an odd integer >= 3.")

    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    sig_int = int.from_bytes(signature, "big")
    if sig_int < 0 or sig_int >= n:
        return False

    em = pow(sig_int, e, n).to_bytes(k, "big")
    digest_prefix, hash_fn = _RSA_DIGEST_SPECS[alg]
    digest_info = digest_prefix + hash_fn(signing_input).digest()
    ps_len = k - len(digest_info) - 3
    if ps_len < 8:
        return False
    expected_em = b"\x00\x01" + (b"\xff" * ps_len) + b"\x00" + digest_info
    return hmac.compare_digest(em, expected_em)


def _verify_ec_or_eddsa(signing_input: bytes, signature: bytes, jwk: Mapping[str, Any], alg: str) -> bool:
    """Verify ES256/ES384/ES512 or EdDSA via optional `cryptography` package (fail-closed if absent)."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    except ImportError as exc:
        raise OAuthResourceError(f"Token algorithm '{alg}' requires optional 'cryptography' package.") from exc

    if alg in _ECDSA_ALGS:
        if jwk.get("kty") != "EC":
            raise OAuthResourceError(f"JWK kty mismatch for algorithm '{alg}'.")
        ec_specs: dict[str, tuple[str, Any, Any, int]] = {
            "ES256": ("P-256", ec.SECP256R1(), hashes.SHA256(), 32),
            "ES384": ("P-384", ec.SECP384R1(), hashes.SHA384(), 48),
            "ES512": ("P-521", ec.SECP521R1(), hashes.SHA512(), 66),
        }
        exp_crv, curve_obj, hash_obj, coord_bytes = ec_specs[alg]
        if jwk.get("crv") != exp_crv:
            raise OAuthResourceError(f"EC JWK curve must be '{exp_crv}' for '{alg}'.")
        x_raw = jwk.get("x")
        y_raw = jwk.get("y")
        if not isinstance(x_raw, str) or not isinstance(y_raw, str):
            raise OAuthResourceError("EC JWK missing 'x' or 'y' coordinate.")
        x_bytes = _b64url_decode(x_raw, label="JWK.x")
        y_bytes = _b64url_decode(y_raw, label="JWK.y")
        if len(x_bytes) != coord_bytes or len(y_bytes) != coord_bytes:
            raise OAuthResourceError("EC JWK coordinate length does not match curve.")
        if len(signature) != 2 * coord_bytes:
            return False
        numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x_bytes, "big"),
            int.from_bytes(y_bytes, "big"),
            curve_obj,
        )
        pub_key = numbers.public_key()
        r = int.from_bytes(signature[:coord_bytes], "big")
        s = int.from_bytes(signature[coord_bytes:], "big")
        der_sig = encode_dss_signature(r, s)
        try:
            pub_key.verify(der_sig, signing_input, ec.ECDSA(hash_obj))
            return True
        except (InvalidSignature, ValueError):
            return False

    if jwk.get("kty") != "OKP":
        raise OAuthResourceError(f"JWK kty mismatch for algorithm '{alg}'.")
    crv = jwk.get("crv")
    x_raw = jwk.get("x")
    if not isinstance(x_raw, str):
        raise OAuthResourceError("OKP JWK missing 'x' public key.")
    x_bytes = _b64url_decode(x_raw, label="JWK.x")
    if crv == "Ed25519":
        okp_key: Any = ed25519.Ed25519PublicKey.from_public_bytes(x_bytes)
    elif crv == "Ed448":
        okp_key = ed448.Ed448PublicKey.from_public_bytes(x_bytes)
    else:
        raise OAuthResourceError(f"Unsupported EdDSA JWK curve '{crv}'.")
    try:
        okp_key.verify(signature, signing_input)
        return True
    except (InvalidSignature, ValueError):
        return False


def _verify_jws_signature(signing_input: bytes, signature: bytes, jwk: Mapping[str, Any], alg: str) -> bool:
    if alg in _RSA_DIGEST_SPECS:
        return _verify_rsa_pkcs1v15(signing_input, signature, jwk, alg)
    if alg in _ECDSA_ALGS or alg in _EDDSA_ALGS:
        return _verify_ec_or_eddsa(signing_input, signature, jwk, alg)
    raise OAuthResourceError(f"Unsupported JWT signature algorithm '{alg}'.")


def _select_jwk(keys: Sequence[Mapping[str, Any]], *, kid: str | None, alg: str) -> Mapping[str, Any]:
    if alg in _RSA_DIGEST_SPECS:
        expected_kty = "RSA"
    elif alg in _ECDSA_ALGS:
        expected_kty = "EC"
    else:
        expected_kty = "OKP"

    candidates: list[Mapping[str, Any]] = []
    for key in keys:
        if not isinstance(key, Mapping):
            continue
        if kid is not None and key.get("kid") != kid:
            continue
        use = key.get("use")
        if use is not None and use != "sig":
            continue
        key_ops = key.get("key_ops")
        if key_ops is not None and (not isinstance(key_ops, list) or "verify" not in key_ops):
            continue
        jwk_alg = key.get("alg")
        if jwk_alg is not None and jwk_alg != alg:
            continue
        if key.get("kty") != expected_kty:
            continue
        candidates.append(key)

    if not candidates:
        raise OAuthResourceError("No compatible signing JWK found for token.")
    if kid is None and len(candidates) > 1:
        raise OAuthResourceError("JWT missing 'kid' while JWKS contains multiple compatible signing keys.")
    if len(candidates) > 1:
        raise OAuthResourceError("JWKS contains ambiguous duplicate keys for 'kid'.")
    return candidates[0]


def _extract_scopes(claims: Mapping[str, Any]) -> frozenset[str]:
    found: set[str] = set()
    scope_str = claims.get("scope")
    if scope_str is not None:
        if not isinstance(scope_str, str):
            raise OAuthResourceError("JWT 'scope' claim must be a string when present.")
        for part in scope_str.split():
            if part and not _CONTROL_CHARS_RE.search(part):
                found.add(part)
    scp_val = claims.get("scp")
    if scp_val is not None:
        if not isinstance(scp_val, list) or not all(isinstance(s, str) for s in scp_val):
            raise OAuthResourceError("JWT 'scp' claim must be a list of strings when present.")
        for item in scp_val:
            clean = item.strip()
            if clean and not _CONTROL_CHARS_RE.search(clean):
                found.add(clean)
    return frozenset(found)


def _extract_groups(claims: Mapping[str, Any]) -> frozenset[str]:
    found: set[str] = set()
    for claim_name in ("groups", "roles"):
        val = claims.get(claim_name)
        if val is None:
            continue
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str) and item.strip() and not _CONTROL_CHARS_RE.search(item):
                    found.add(item.strip())
    return frozenset(found)


def _require_numeric_claim(claims: Mapping[str, Any], name: str, *, required: bool) -> float | None:
    if name not in claims:
        if required:
            raise OAuthResourceError(f"JWT missing required numeric claim '{name}'.")
        return None
    val = claims[name]
    if isinstance(val, bool) or not isinstance(val, int | float) or not math.isfinite(float(val)):
        raise OAuthResourceError(f"JWT claim '{name}' must be a finite numeric timestamp.")
    return float(val)


def build_protected_resource_metadata(config: AuthConfig, *, resource_url: str) -> dict[str, Any]:
    """Build RFC 9728 Protected Resource Metadata payload for an OIDC-protected upstream gateway."""
    if config.mode != "oidc" or not config.issuer:
        raise ValueError("Protected Resource Metadata requires auth.mode = 'oidc' with a valid issuer.")
    resolved = canonical_resource_uri(config.resource or resource_url)
    meta: dict[str, Any] = {
        "resource": resolved,
        "authorization_servers": [config.issuer],
        "bearer_methods_supported": ["header"],
    }
    if config.required_scopes:
        meta["scopes_supported"] = list(config.required_scopes)
    return meta


def build_www_authenticate_challenge(
    resource_metadata_url: str | None = None,
    *,
    realm: str | None = None,
    error: str | None = None,
    scope: str | None = None,
) -> str:
    """Format an RFC 6750 / RFC 9728 `WWW-Authenticate: Bearer ...` challenge header safely."""

    def _safe_attr_val(raw: str) -> str:
        return _CONTROL_CHARS_RE.sub("", raw).replace('"', "'")

    parts: list[str] = []
    if realm:
        parts.append(f'realm="{_safe_attr_val(realm)}"')
    if resource_metadata_url:
        parts.append(f'resource_metadata="{_safe_attr_val(resource_metadata_url)}"')
    if error:
        parts.append(f'error="{_safe_attr_val(error)}"')
    if scope:
        parts.append(f'scope="{_safe_attr_val(scope)}"')
    if not parts:
        return "Bearer"
    return "Bearer " + ", ".join(parts)


class OAuthResourceValidator:
    """Thread-safe OAuth 2.1 / OIDC JWT + JWKS validator with bounded rate-limited refresh."""

    def __init__(
        self,
        config: AuthConfig,
        *,
        allowed_domains: frozenset[str] | None = None,
        proxy_url: str | None = None,
        ssl_context: ssl.SSLContext | None = None,
        opener: urllib.request.OpenerDirector | None = None,
        timeout: float = DEFAULT_OAUTH_TIMEOUT_SECONDS,
        jwks_cache_ttl: float = DEFAULT_JWKS_CACHE_TTL_SECONDS,
        min_refresh_interval: float = MIN_JWKS_REFRESH_INTERVAL_SECONDS,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if config.mode != "oidc":
            raise ValueError("OAuthResourceValidator requires auth.mode = 'oidc'.")
        if jwks_cache_ttl <= 0:
            raise ValueError("jwks_cache_ttl must be positive.")
        if min_refresh_interval < 0:
            raise ValueError("min_refresh_interval must be non-negative.")

        self.config = config
        self.allow_loopback_http = config.allow_insecure_loopback_for_tests
        eff_domains = allowed_domains
        if eff_domains is not None:
            extras = {
                host.lower().rstrip(".")
                for u in (config.issuer, config.jwks_uri)
                if u and (host := urllib.parse.urlparse(u).hostname)
            }
            eff_domains = eff_domains | extras
        self.allowed_domains = eff_domains
        self.opener = opener or build_safe_opener(
            proxy_url=proxy_url,
            ssl_context=ssl_context,
            bypass_ambient_proxy=self.allow_loopback_http and proxy_url is None,
        )
        self.timeout = timeout
        self.jwks_cache_ttl = jwks_cache_ttl
        self.min_refresh_interval = min_refresh_interval
        self._clock = clock or time.time

        self._lock = threading.Lock()
        self._resolved_jwks_uri: str | None = config.jwks_uri
        self._cached_keys: tuple[dict[str, Any], ...] = ()
        self._cache_expires_at: float = 0.0
        self._last_refresh_mono: float = -1e9

    def _resolve_jwks_uri_locked(self) -> str:
        if self._resolved_jwks_uri is not None:
            return validate_outbound_url(
                self._resolved_jwks_uri,
                allowed_domains=self.allowed_domains,
                allow_loopback_http=self.allow_loopback_http,
            )
        if self.config.issuer is None:
            raise OAuthResourceError("OIDC issuer is not configured.")
        try:
            as_meta = discover_authorization_server(
                self.config.issuer,
                allowed_domains=self.allowed_domains,
                timeout=self.timeout,
                opener=self.opener,
                allow_loopback_http=self.allow_loopback_http,
            )
        except OAuthError as exc:
            raise OAuthResourceError(f"OIDC authorization server discovery failed: {exc}") from exc
        raw_jwks = as_meta.get("jwks_uri")
        if not isinstance(raw_jwks, str) or not raw_jwks.strip():
            raise OAuthResourceError("Authorization server metadata missing string 'jwks_uri'.")
        try:
            validated = validate_outbound_url(
                raw_jwks,
                allowed_domains=self.allowed_domains,
                allow_loopback_http=self.allow_loopback_http,
            )
        except ValueError as exc:
            raise OAuthResourceError(f"Invalid authorization server 'jwks_uri': {exc}") from exc
        self._resolved_jwks_uri = validated
        return validated

    def _fetch_jwks_locked(self) -> tuple[dict[str, Any], ...]:
        jwks_url = self._resolve_jwks_uri_locked()
        req = urllib.request.Request(  # noqa: S310 - validated URL
            jwks_url,
            method="GET",
            headers={"Accept": "application/json"},
        )
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:  # noqa: S310 - scheme/host validated
                raw_bytes = read_bounded_bytes(resp, max_bytes=MAX_OAUTH_RESPONSE_BYTES)
        except OAuthError as exc:
            raise OAuthResourceError(f"JWKS fetch rejected: {exc}") from exc
        except urllib.error.HTTPError as exc:
            exc.close()
            raise OAuthResourceError(f"JWKS endpoint returned HTTP {exc.code}.") from exc
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            raise OAuthResourceError(f"JWKS fetch failed: {exc}") from exc

        try:
            parsed = _strict_json_loads(raw_bytes.decode("utf-8"), label="JWKS")
        except UnicodeDecodeError as exc:
            raise OAuthResourceError(f"JWKS response is not valid UTF-8: {exc}") from exc
        if not isinstance(parsed, dict) or not isinstance(parsed.get("keys"), list):
            raise OAuthResourceError("JWKS document must be a JSON object with a 'keys' list.")
        keys = tuple(dict(k) for k in parsed["keys"] if isinstance(k, Mapping))
        if not keys:
            raise OAuthResourceError("JWKS document contains no usable JWK entries.")

        now_mono = time.monotonic()
        self._cached_keys = keys
        self._cache_expires_at = now_mono + self.jwks_cache_ttl
        self._last_refresh_mono = now_mono
        return keys

    def _get_keys(self, *, kid: str | None) -> tuple[dict[str, Any], ...]:
        with self._lock:
            now_mono = time.monotonic()
            has_cache = bool(self._cached_keys) and now_mono < self._cache_expires_at
            if has_cache:
                if kid is None or any(k.get("kid") == kid for k in self._cached_keys):
                    return self._cached_keys
                if now_mono - self._last_refresh_mono < self.min_refresh_interval:
                    return self._cached_keys
            return self._fetch_jwks_locked()

    def validate_token(
        self,
        raw_token: str,
        *,
        require_agent_scopes: bool = True,
    ) -> AuthenticatedPrincipal:
        """
        Validate a compact JWS bearer access token fail-closed and return an `AuthenticatedPrincipal`.
        """
        if not isinstance(raw_token, str) or not raw_token or len(raw_token) > MAX_JWT_CHARS:
            raise OAuthResourceError("Bearer token is missing or exceeds maximum size.")
        if _CONTROL_CHARS_RE.search(raw_token) or any(ch.isspace() for ch in raw_token):
            raise OAuthResourceError("Bearer token contains invalid whitespace or control characters.")

        parts = raw_token.split(".")
        if len(parts) != 3 or not all(parts):
            raise OAuthResourceError("Bearer token is not a valid compact JWS.")
        hdr_b64, pay_b64, sig_b64 = parts

        try:
            hdr_text = _b64url_decode(hdr_b64, label="JWT header").decode("utf-8")
            pay_bytes = _b64url_decode(pay_b64, label="JWT payload")
        except UnicodeDecodeError as exc:
            raise OAuthResourceError(f"JWT segment is not valid UTF-8: {exc}") from exc
        sig_bytes = _b64url_decode(sig_b64, label="JWT signature")

        header = _strict_json_loads(hdr_text, label="JWT header")
        if not isinstance(header, dict):
            raise OAuthResourceError("JWT header must be a JSON object.")

        for forbidden_key in _FORBIDDEN_HDR_KEYS:
            if forbidden_key in header:
                raise OAuthResourceError(f"JWT header contains forbidden embedded key field '{forbidden_key}'.")

        crit = header.get("crit")
        if crit is not None:
            if not isinstance(crit, list) or crit:
                raise OAuthResourceError("JWT contains unsupported critical header parameters.")

        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in _SUPPORTED_ALGS:
            raise OAuthResourceError(f"Disallowed or unsupported JWT algorithm {alg!r}.")

        typ = header.get("typ")
        if typ is not None:
            if not isinstance(typ, str) or typ.strip().lower() not in _ALLOWED_TYP:
                raise OAuthResourceError(f"Unsupported JWT media type {typ!r}.")

        kid = header.get("kid")
        if kid is not None and (not isinstance(kid, str) or not kid.strip() or _CONTROL_CHARS_RE.search(kid)):
            raise OAuthResourceError("JWT 'kid' header must be a non-empty string.")

        keys = self._get_keys(kid=kid)
        jwk = _select_jwk(keys, kid=kid, alg=alg)
        signing_input = f"{hdr_b64}.{pay_b64}".encode("ascii")
        if not _verify_jws_signature(signing_input, sig_bytes, jwk, alg):
            raise OAuthResourceError("JWT cryptographic signature verification failed.")

        try:
            claims = _strict_json_loads(pay_bytes.decode("utf-8"), label="JWT payload")
        except UnicodeDecodeError as exc:
            raise OAuthResourceError(f"JWT payload is not valid UTF-8: {exc}") from exc
        if not isinstance(claims, dict):
            raise OAuthResourceError("JWT payload must be a JSON object.")

        iss = claims.get("iss")
        if not isinstance(iss, str) or not iss.strip():
            raise OAuthResourceError("JWT missing valid 'iss' claim.")
        try:
            norm_iss = canonical_resource_uri(iss).rstrip("/")
        except ValueError as exc:
            raise OAuthResourceError(f"Malformed JWT 'iss' URI: {exc}") from exc
        if norm_iss != self.config.issuer:
            raise OAuthResourceError("JWT 'iss' does not match configured issuer.")

        allowed_audiences: set[str] = set()
        if self.config.audience:
            allowed_audiences.add(self.config.audience)
        if self.config.resource:
            allowed_audiences.add(canonical_resource_uri(self.config.resource))

        aud = claims.get("aud")
        if isinstance(aud, str):
            token_audiences = [aud] if aud else []
        elif isinstance(aud, list) and all(isinstance(a, str) and a for a in aud):
            token_audiences = list(aud)
        else:
            raise OAuthResourceError("JWT missing valid 'aud' claim.")
        if not any(a in allowed_audiences for a in token_audiences):
            raise OAuthResourceError("JWT 'aud' does not include configured resource or audience.")

        now = self._clock()
        skew = self.config.clock_skew_seconds
        exp = _require_numeric_claim(claims, "exp", required=True)
        if exp is None or exp <= now - skew:
            raise OAuthResourceError("JWT bearer token has expired.")

        nbf = _require_numeric_claim(claims, "nbf", required=False)
        if nbf is not None and now + skew < nbf:
            raise OAuthResourceError("JWT bearer token is not yet valid (nbf).")

        iat = _require_numeric_claim(claims, "iat", required=False)
        if iat is not None and iat > now + skew:
            raise OAuthResourceError("JWT 'iat' timestamp is in the future.")

        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub.strip() or len(sub) > MAX_SUB_CHARS or _CONTROL_CHARS_RE.search(sub):
            raise OAuthResourceError("JWT missing valid 'sub' subject claim.")
        clean_sub = sub.strip()

        scopes = _extract_scopes(claims)
        groups = _extract_groups(claims)

        if require_agent_scopes and self.config.required_scopes:
            missing = set(self.config.required_scopes) - scopes
            if missing:
                raise OAuthResourceError(
                    f"JWT bearer token missing required scope(s): {sorted(missing)}",
                    http_status=403,
                    oauth_error="insufficient_scope",
                    required_scope=" ".join(self.config.required_scopes),
                )

        email_raw = claims.get("email")
        verified_email: str | None = None
        if (
            claims.get("email_verified") is True
            and isinstance(email_raw, str)
            and email_raw.strip()
            and not _CONTROL_CHARS_RE.search(email_raw)
        ):
            verified_email = email_raw.strip()

        # `approved_by` and audit labels lead with the subject, the identifier the IdP guarantees. A verified email is a
        # readable hint only: it never decides anything, since some IdPs let users set it.
        raw_display = f"oidc:{clean_sub}" + (f" <{verified_email}>" if verified_email else "")
        display_identity = redact_text(raw_display)[:MAX_DISPLAY_ID_CHARS]

        roles = frozenset(self._roles_for(clean_sub, scopes, groups))

        subject = f"oidc:{self.config.issuer}|{clean_sub}"
        return AuthenticatedPrincipal(
            subject=subject,
            auth_mode="oidc",
            display_identity=display_identity,
            scopes=scopes,
            roles=roles,
            issuer=self.config.issuer,
            expires_at=exp,
        )

    def _roles_for(self, subject: str, scopes: frozenset[str], groups: frozenset[str]) -> set[Role]:
        """
        Give each token exactly one role, so the token an agent's MCP client holds can never approve its own calls.

        A token carrying an `approver_scopes` scope is an approver token: it may approve, and `/mcp` refuses it. Any
        other valid token is an agent token. When `approver_subjects` or `approver_groups` is set, an approver token
        must also match one of them (a listed `sub`, or a listed group); they never grant approval to a token without
        the scope. Subjects are matched on `sub` only, never on an email claim.
        """
        if not (self.config.approver_scopes and scopes & set(self.config.approver_scopes)):
            return {Role.AGENT}
        allowlisted = bool(self.config.approver_subjects or self.config.approver_groups)
        if allowlisted and not (subject in self.config.approver_subjects or groups & set(self.config.approver_groups)):
            return set()  # approver-scoped but not an allowed approver: neither role
        return {Role.APPROVER}


__all__ = [
    "AuthConfig",
    "AuthenticatedPrincipal",
    "DEFAULT_JWKS_CACHE_TTL_SECONDS",
    "MAX_CLOCK_SKEW_SECONDS",
    "MAX_JWT_CHARS",
    "MIN_JWKS_REFRESH_INTERVAL_SECONDS",
    "OAuthResourceError",
    "OAuthResourceValidator",
    "build_protected_resource_metadata",
    "build_www_authenticate_challenge",
    "normalize_allowed_host",
    "normalize_origin",
]
