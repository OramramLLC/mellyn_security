"""Tests for upstream Streamable HTTP `/mcp` gateway, OAuth 2.1 Resource Server, and SQLite v2."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import http.client
import http.server
import importlib.util
import io
import json
import os
import socketserver
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from pathlib import Path
from typing import Any
from unittest import mock

# `cryptography` only signs test tokens (the validator under test verifies RSA with the standard library). CI installs
# it from deploy/requirements-ci-tests.lock and sets MELLYN_REQUIRE_API_TESTS=1, so it can never be silently skipped
# there; a bare pre-commit venv without it skips this module instead of failing to import.
if importlib.util.find_spec("cryptography") is None and os.environ.get("MELLYN_REQUIRE_API_TESTS") != "1":
    raise unittest.SkipTest("cryptography is not installed; OIDC and HTTP gateway tests skipped")

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402

# Importable on its own without requiring PYTHONPATH.
_REPO_ROOT = Path(__file__).resolve().parent.parent
for _import_dir in (_REPO_ROOT / "backend", _REPO_ROOT / "src"):
    if str(_import_dir) not in sys.path:
        sys.path.insert(0, str(_import_dir))

from mellyn import (  # noqa: E402
    AuditLogger,
    AuthConfig,
    Authorizer,
    CredentialConfig,
    OAuthClientConfig,
    OAuthResourceError,
    OAuthResourceValidator,
    PolicyConfig,
    PolicyLoadError,
    RiskTier,
    Role,
    ScannerConfig,
    SqliteStateStore,
    StateStoreError,
    StreamableHttpDownstream,
    load_unified_config,
    verify_gateway_audit_file,
)
from mellyn.approvals import ApprovalHTTPServer, PendingApprovals  # noqa: E402
from mellyn.cli import main as cli_main  # noqa: E402
from mellyn.credentials import key_digest  # noqa: E402
from mellyn.egress_proxy import main as egress_main  # noqa: E402
from mellyn.http_gateway import StreamableHttpGatewayServer  # noqa: E402
from mellyn.mcp_gateway import (  # noqa: E402
    MELLYN_AAD_CONTAINED,
    initialize_downstream,
)
from mellyn.oauth_client import build_safe_opener  # noqa: E402
from mellyn.pin_gateway import GatewayPinResult, upsert_server_in_unified_toml  # noqa: E402


def _synth_value(*parts: str) -> str:
    """Construct synthetic credential/canary strings dynamically without raw test literals."""
    return "".join(parts)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_b64url(value: int, *, min_bytes: int = 0) -> str:
    length = max(min_bytes, (value.bit_length() + 7) // 8 or 1)
    return _b64url(value.to_bytes(length, "big"))


def _rsa_to_jwk(pub: rsa.RSAPublicKey, *, kid: str, alg: str | None = None, use: str | None = "sig") -> dict[str, Any]:
    nums = pub.public_numbers()
    jwk: dict[str, Any] = {
        "kty": "RSA",
        "kid": kid,
        "n": _int_b64url(nums.n),
        "e": _int_b64url(nums.e),
    }
    if use is not None:
        jwk["use"] = use
    if alg is not None:
        jwk["alg"] = alg
    return jwk


def _ec_to_jwk(pub: ec.EllipticCurvePublicKey, *, kid: str, alg: str = "ES256") -> dict[str, Any]:
    nums = pub.public_numbers()
    return {
        "kty": "EC",
        "kid": kid,
        "crv": "P-256",
        "use": "sig",
        "alg": alg,
        "x": _int_b64url(nums.x, min_bytes=32),
        "y": _int_b64url(nums.y, min_bytes=32),
    }


def _sign_rsa_jwt(
    claims: Mapping[str, Any],
    priv: rsa.RSAPrivateKey,
    *,
    kid: str | None = "rsa-k1",
    alg: str = "RS256",
    typ: str | None = "JWT",
    extra_hdr: Mapping[str, Any] | None = None,
) -> str:
    hash_map: dict[str, hashes.HashAlgorithm] = {
        "RS256": hashes.SHA256(),
        "RS384": hashes.SHA384(),
        "RS512": hashes.SHA512(),
    }
    hdr: dict[str, Any] = {"alg": alg}
    if typ is not None:
        hdr["typ"] = typ
    if kid is not None:
        hdr["kid"] = kid
    if extra_hdr:
        hdr.update(extra_hdr)
    signing_input = f"{_b64url(json.dumps(hdr).encode())}.{_b64url(json.dumps(claims).encode())}"
    sig = priv.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hash_map[alg])
    return f"{signing_input}.{_b64url(sig)}"


def _sign_ec_jwt(claims: Mapping[str, Any], priv: ec.EllipticCurvePrivateKey, *, kid: str = "ec-k1") -> str:
    hdr = {"alg": "ES256", "typ": "JWT", "kid": kid}
    signing_input = f"{_b64url(json.dumps(hdr).encode())}.{_b64url(json.dumps(claims).encode())}"
    der_sig = priv.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{signing_input}.{_b64url(raw_sig)}"


class _ReusableHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


@dataclass
class _MockOidcState:
    rsa_k1_priv: rsa.RSAPrivateKey
    rsa_k2_priv: rsa.RSAPrivateKey
    rsa_weak_priv: rsa.RSAPrivateKey
    ec_k1_priv: ec.EllipticCurvePrivateKey
    expected_client_id: str
    expected_client_cred: str
    lock: threading.Lock = field(default_factory=threading.Lock)
    base_url: str = ""
    jwks_keys: list[dict[str, Any]] = field(default_factory=list)
    jwks_hits: int = 0
    discovery_hits: int = 0
    token_hits: int = 0
    issued_scopes: str = "mcp:use"
    issued_sub: str = "svc-remote-client"


class _MockOidcIdpHarness:
    """In-process OIDC Authorization Server serving discovery metadata, JWKS, and signed RS256 tokens."""

    def __init__(self, expected_client_id: str = "client-oidc", expected_client_cred: str = "") -> None:
        rsa_k1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_k2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505 - weak key fixture
        ec_k1 = ec.generate_private_key(ec.SECP256R1())
        cred = expected_client_cred or _synth_value("oidc_cred_", "alpha_7")
        self.state = _MockOidcState(
            rsa_k1_priv=rsa_k1,
            rsa_k2_priv=rsa_k2,
            rsa_weak_priv=rsa_weak,
            ec_k1_priv=ec_k1,
            expected_client_id=expected_client_id,
            expected_client_cred=cred,
            jwks_keys=[
                _rsa_to_jwk(rsa_k1.public_key(), kid="rsa-k1"),
                _rsa_to_jwk(rsa_weak.public_key(), kid="rsa-weak"),
                _ec_to_jwk(ec_k1.public_key(), kid="ec-k1"),
            ],
        )
        state = self.state

        class _Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, _format: str, *_args: Any) -> None:
                return

            def _send_json(self, status: int, body: Any) -> None:
                payload = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler dispatch
                path = urllib.parse.urlparse(self.path).path
                if path in ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"):
                    with state.lock:
                        state.discovery_hits += 1
                        base = state.base_url
                    self._send_json(
                        HTTPStatus.OK,
                        {
                            "issuer": base,
                            "token_endpoint": f"{base}/token",
                            "jwks_uri": f"{base}/jwks.json",
                        },
                    )
                    return
                if path == "/jwks.json":
                    with state.lock:
                        state.jwks_hits += 1
                        keys = list(state.jwks_keys)
                    self._send_json(HTTPStatus.OK, {"keys": keys})
                    return
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

            def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler dispatch
                path = urllib.parse.urlparse(self.path).path
                if path != "/token":
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                    return
                length = int(self.headers.get("Content-Length") or "0")
                raw = self.rfile.read(length) if length > 0 else b""
                parsed_qs = urllib.parse.parse_qs(raw.decode("utf-8"), keep_blank_values=True)
                form = {k: v[0] for k, v in parsed_qs.items()}
                with state.lock:
                    state.token_hits += 1
                    expected_cid = state.expected_client_id
                    expected_cred = state.expected_client_cred
                    scopes = state.issued_scopes
                    sub = state.issued_sub
                    priv = state.rsa_k1_priv
                    issuer = state.base_url
                if form.get("client_id") != expected_cid or form.get("client_secret") != expected_cred:
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "invalid_client"})
                    return
                resource = form.get("resource") or "https://default.example/mcp"
                now = int(time.time())
                jwt_val = _sign_rsa_jwt(
                    {
                        "iss": issuer,
                        "aud": resource,
                        "sub": sub,
                        "scope": scopes,
                        "iat": now,
                        "exp": now + 600,
                    },
                    priv,
                    kid="rsa-k1",
                    alg="RS256",
                )
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "access_token": jwt_val,
                        "token_type": "Bearer",
                        "expires_in": 600,
                        "scope": scopes,
                    },
                )

        self._server = _ReusableHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self._server.server_port
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.state.base_url = self.base_url
        self._thread = threading.Thread(target=self._server.serve_forever, name="mock-oidc-idp", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2.0)


class _FakeDownstream:
    """In-process Downstream supporting benign tool calls, remote tainting, and canary leakage."""

    def __init__(self, name: str = "remote") -> None:
        self.name = name
        self.canary_text: str | None = None
        self.killed = False
        self.closed = False

    def request(self, method: str, params: dict[str, Any], timeout: float = 10.0) -> dict[str, Any]:
        del timeout
        if method == "tools/list":
            tool_name = "get_issue" if self.name == "remote" else "write_file"
            return {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "tools": [
                        {
                            "name": tool_name,
                            "description": "Test downstream tool.",
                            "inputSchema": {"type": "object", "properties": {}},
                        }
                    ]
                },
            }
        if self.canary_text is not None:
            return {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"content": [{"type": "text", "text": f"exfil={self.canary_text}"}]},
            }
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [{"type": "text", "text": f"ok:{self.name}:{params.get('name', '')}"}], "ok": True},
        }

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        del method, params

    def close(self) -> None:
        self.closed = True

    def kill_now(self) -> None:
        self.killed = True


def _http_call(
    url: str,
    *,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, data=body, method=method, headers=dict(headers or {}))  # noqa: S310 - test URL
    opener = build_safe_opener(bypass_ambient_proxy=True)
    try:
        with opener.open(req, timeout=5.0) as resp:  # noqa: S310 - test loopback URL
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        try:
            err_body = exc.read()
            err_hdrs = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
            return exc.code, err_hdrs, err_body
        finally:
            exc.close()


class TestOAuthResourceValidator(unittest.TestCase):
    """Tests for pure-stdlib RSA + optional ECDSA JWKS validation, refresh limits, and fail-closed checks."""

    def test_rs256_rs384_rs512_es256_rotation_and_rate_limit(self) -> None:
        idp = _MockOidcIdpHarness()
        idp.start()
        try:
            cfg = AuthConfig(
                mode="oidc",
                issuer=idp.base_url,
                audience="https://mellyn.example/mcp",
                required_scopes=("mcp:use",),
                allow_insecure_loopback_for_tests=True,
            )
            validator = OAuthResourceValidator(cfg, jwks_cache_ttl=300.0, min_refresh_interval=30.0)
            now = int(time.time())
            base_claims: dict[str, Any] = {
                "iss": idp.base_url,
                "aud": ["other-aud", "https://mellyn.example/mcp"],
                "sub": "user-123",
                "scp": ["mcp:use", "extra"],
                "exp": now + 300,
                "nbf": now - 10,
                "iat": now - 5,
            }
            for alg in ("RS256", "RS384", "RS512"):
                tok = _sign_rsa_jwt(base_claims, idp.state.rsa_k1_priv, kid="rsa-k1", alg=alg)
                principal = validator.validate_token(tok)
                self.assertEqual(principal.subject, f"oidc:{idp.base_url}|user-123")
                self.assertIn("mcp:use", principal.scopes)
                self.assertEqual(principal.roles, frozenset({Role.AGENT}))

            es_tok = _sign_ec_jwt(base_claims, idp.state.ec_k1_priv, kid="ec-k1")
            es_principal = validator.validate_token(es_tok)
            self.assertEqual(es_principal.subject, f"oidc:{idp.base_url}|user-123")
            self.assertEqual(idp.state.jwks_hits, 1)

            # Rotating in rsa-k2 triggers a single JWKS refresh when min_refresh_interval allows it.
            with idp.state.lock:
                idp.state.jwks_keys.append(_rsa_to_jwk(idp.state.rsa_k2_priv.public_key(), kid="rsa-k2"))
            validator.min_refresh_interval = 0.0
            tok_k2 = _sign_rsa_jwt(base_claims, idp.state.rsa_k2_priv, kid="rsa-k2", alg="RS256")
            self.assertEqual(validator.validate_token(tok_k2).subject, f"oidc:{idp.base_url}|user-123")
            self.assertEqual(idp.state.jwks_hits, 2)

            # With min_refresh_interval=60, unknown kid does not trigger a second JWKS fetch.
            validator.min_refresh_interval = 60.0
            tok_unknown = _sign_rsa_jwt(base_claims, idp.state.rsa_k2_priv, kid="unknown-kid", alg="RS256")
            with self.assertRaises(OAuthResourceError):
                validator.validate_token(tok_unknown)
            self.assertEqual(idp.state.jwks_hits, 2)
        finally:
            idp.stop()

    def test_security_rejections_and_approver_role_binding(self) -> None:
        idp = _MockOidcIdpHarness()
        idp.start()
        try:
            cfg = AuthConfig(
                mode="oidc",
                issuer=idp.base_url,
                audience="https://mellyn.example/mcp",
                required_scopes=("mcp:use",),
                approver_subjects=("alice@corp.example", "sub-approver"),
                approver_scopes=("mcp:approve",),
                approver_groups=("sec-approvers",),
                clock_skew_seconds=30,
                allow_insecure_loopback_for_tests=True,
            )
            validator = OAuthResourceValidator(cfg)
            now = int(time.time())
            good_claims: dict[str, Any] = {
                "iss": idp.base_url,
                "aud": "https://mellyn.example/mcp",
                "sub": "bob",
                "scope": "mcp:use",
                "exp": now + 300,
            }

            # Warm JWKS cache once
            validator.validate_token(_sign_rsa_jwt(good_claims, idp.state.rsa_k1_priv))

            # 1) alg="none" rejected
            none_hdr = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
            none_pay = _b64url(json.dumps(good_claims).encode())
            with self.assertRaises(OAuthResourceError):
                validator.validate_token(f"{none_hdr}.{none_pay}.sig")

            # 2) HS256 algorithm confusion with RSA modulus rejected
            hs_hdr = _b64url(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "rsa-k1"}).encode())
            hs_input = f"{hs_hdr}.{none_pay}".encode("ascii")
            hs_sig = _b64url(hmac.new(b"public-modulus", hs_input, hashlib.sha256).digest())
            with self.assertRaises(OAuthResourceError):
                validator.validate_token(f"{hs_hdr}.{none_pay}.{hs_sig}")

            # 3) Embedded JWK/JKU/crit/bad typ/weak RSA key rejected
            for bad_extra in (
                {"jwk": _rsa_to_jwk(idp.state.rsa_k1_priv.public_key(), kid="x")},
                {"jku": f"{idp.base_url}/jwks.json"},
                {"x5c": ["MIIB"]},
                {"crit": ["exp"]},
                {"typ": "secevent+jwt"},
            ):
                with self.subTest(bad_extra=bad_extra), self.assertRaises(OAuthResourceError):
                    bad_tok = _sign_rsa_jwt(good_claims, idp.state.rsa_k1_priv, extra_hdr=bad_extra)
                    validator.validate_token(bad_tok)

            with self.assertRaises(OAuthResourceError):
                validator.validate_token(_sign_rsa_jwt(good_claims, idp.state.rsa_weak_priv, kid="rsa-weak"))

            # 4) Bad claims: wrong iss, wrong aud, expired, future nbf, missing sub
            bad_claim_variants: list[dict[str, Any]] = [
                {**good_claims, "iss": "https://other-idp.example"},
                {**good_claims, "aud": "https://wrong.example/mcp"},
                {**good_claims, "exp": now - 120},
                {**good_claims, "nbf": now + 120},
                {k: v for k, v in good_claims.items() if k != "sub"},
            ]
            for claims_variant in bad_claim_variants:
                with self.subTest(claims=claims_variant), self.assertRaises(OAuthResourceError):
                    validator.validate_token(_sign_rsa_jwt(claims_variant, idp.state.rsa_k1_priv))

            # 5) Duplicate JSON key in payload rejected
            dup_pay = _b64url(
                (
                    f'{{"iss":"{idp.base_url}","aud":"https://mellyn.example/mcp","sub":"a","sub":"b",'
                    f'"scope":"mcp:use","exp":{now + 300}}}'
                ).encode()
            )
            hdr_b64 = _b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "rsa-k1"}).encode())
            dup_in = f"{hdr_b64}.{dup_pay}".encode("ascii")
            dup_sig = idp.state.rsa_k1_priv.sign(dup_in, padding.PKCS1v15(), hashes.SHA256())
            with self.assertRaises(OAuthResourceError):
                validator.validate_token(f"{hdr_b64}.{dup_pay}.{_b64url(dup_sig)}")

            # 6) Missing required scope returns 403 insufficient_scope
            no_scope_claims = {**good_claims, "scope": "profile"}
            with self.assertRaises(OAuthResourceError) as scope_ctx:
                validator.validate_token(_sign_rsa_jwt(no_scope_claims, idp.state.rsa_k1_priv))
            self.assertEqual(scope_ctx.exception.http_status, 403)
            self.assertEqual(scope_ctx.exception.oauth_error, "insufficient_scope")

            # 7) Approver role: needs an approver-scoped token AND a listed sub or group; an email never decides it
            unverified_email_claims = {
                **good_claims,
                "email": "alice@corp.example",
                "email_verified": False,
            }
            p_unverified = validator.validate_token(_sign_rsa_jwt(unverified_email_claims, idp.state.rsa_k1_priv))
            self.assertEqual(p_unverified.roles, frozenset({Role.AGENT}))
            self.assertEqual(p_unverified.display_identity, "oidc:bob")

            approve_claims = {**good_claims, "scope": "mcp:approve"}
            verified_email_claims = {**approve_claims, "email": "alice@corp.example", "email_verified": True}
            p_verified = validator.validate_token(
                _sign_rsa_jwt(verified_email_claims, idp.state.rsa_k1_priv), require_agent_scopes=False
            )
            self.assertEqual(p_verified.roles, frozenset())  # sub "bob" is not listed; the email claim is ignored
            self.assertEqual(p_verified.display_identity, "oidc:bob <alice@corp.example>")

            p_sub = validator.validate_token(
                _sign_rsa_jwt({**approve_claims, "sub": "sub-approver"}, idp.state.rsa_k1_priv),
                require_agent_scopes=False,
            )
            self.assertEqual(p_sub.roles, frozenset({Role.APPROVER}))

            group_claims = {**approve_claims, "sub": "carol", "groups": ["sec-approvers"]}
            p_group = validator.validate_token(
                _sign_rsa_jwt(group_claims, idp.state.rsa_k1_priv), require_agent_scopes=False
            )
            self.assertEqual(p_group.roles, frozenset({Role.APPROVER}))

            # A listed approver's agent token (no approver scope) is only an agent token.
            p_agent = validator.validate_token(
                _sign_rsa_jwt(
                    {**good_claims, "sub": "sub-approver", "groups": ["sec-approvers"]}, idp.state.rsa_k1_priv
                )
            )
            self.assertEqual(p_agent.roles, frozenset({Role.AGENT}))
        finally:
            idp.stop()


class TestStateStoreSessionOwnershipAndMigration(unittest.TestCase):
    """Tests for schema_version 1->2 migration, owner_subject persistence, and delete_session."""

    def test_v1_database_migrates_to_v2_preserving_taint_and_grants(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "v1_state.db"
            t0 = datetime(2026, 11, 24, 10, 0, 0, tzinfo=UTC)
            t0_us = int(t0.timestamp() * 1_000_000)
            exp_us = int((t0 + timedelta(minutes=15)).timestamp() * 1_000_000)
            with closing(sqlite3.connect(str(db_path))) as conn:
                conn.executescript(
                    """
                    CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    CREATE TABLE sessions (
                        session_id TEXT PRIMARY KEY,
                        created_at_us INTEGER NOT NULL,
                        last_seen_at_us INTEGER NOT NULL,
                        tainted INTEGER NOT NULL CHECK (tainted IN (0, 1)),
                        taint_count INTEGER NOT NULL CHECK (taint_count >= 0)
                    );
                    CREATE TABLE session_taints (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
                        source_type TEXT NOT NULL,
                        origin TEXT NOT NULL,
                        recorded_at_us INTEGER NOT NULL,
                        formatted_entry TEXT NOT NULL
                    );
                    CREATE INDEX idx_session_taints_session_id ON session_taints (session_id, id);
                    CREATE TABLE grants (
                        grant_id TEXT PRIMARY KEY,
                        session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
                        tool_name TEXT NOT NULL,
                        mcp_server TEXT,
                        mcp_method TEXT,
                        arguments_json TEXT NOT NULL,
                        approved_by TEXT NOT NULL,
                        expires_at_us INTEGER NOT NULL,
                        max_uses INTEGER NOT NULL CHECK (max_uses >= 1),
                        uses INTEGER NOT NULL CHECK (uses >= 0 AND uses <= max_uses)
                    );
                    CREATE INDEX idx_grants_session_id ON grants (session_id);
                    """
                )
                conn.execute("INSERT INTO schema_meta (key, value) VALUES (?, ?)", ("schema_version", "1"))
                conn.execute(
                    "INSERT INTO sessions (session_id, created_at_us, last_seen_at_us, tainted, taint_count) "
                    "VALUES (?, ?, ?, 1, 1)",
                    ("ses_legacy", t0_us, t0_us),
                )
                conn.execute(
                    "INSERT INTO session_taints (session_id, source_type, origin, recorded_at_us, formatted_entry) "
                    "VALUES (?, ?, ?, ?, ?)",
                    ("ses_legacy", "tool_result", "remote:get_issue", t0_us, "tool_result:remote:get_issue"),
                )
                conn.execute(
                    "INSERT INTO grants "
                    "(grant_id, session_id, tool_name, mcp_server, mcp_method, "
                    "arguments_json, approved_by, expires_at_us, max_uses, uses) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0)",
                    ("gr_legacy", "ses_legacy", "write_file", "local", "tools/call", "{}", "alice", exp_us),
                )
                conn.commit()

            with SqliteStateStore(db_path) as store:
                snap = store.get_session_snapshot("ses_legacy")
                self.assertIsNotNone(snap)
                if snap is not None:
                    self.assertTrue(snap.tainted)
                    self.assertEqual(snap.taint_count, 1)
                    self.assertIsNone(snap.owner_subject)
                self.assertEqual(len(store.list_usable_grants("ses_legacy", now=t0)), 1)

                # New owner-bound session persists across restart and deletes cleanly.
                store.create_session(
                    "ses_owned",
                    now=t0,
                    session_ttl_seconds=3600,
                    max_sessions=100,
                    owner_subject="oidc:https://idp.example|alice",
                )

            with SqliteStateStore(db_path) as store2:
                owned = store2.get_session_snapshot("ses_owned")
                self.assertIsNotNone(owned)
                if owned is not None:
                    self.assertEqual(owned.owner_subject, "oidc:https://idp.example|alice")
                self.assertTrue(store2.delete_session("ses_owned"))
                self.assertFalse(store2.delete_session("ses_owned"))
                self.assertIsNone(store2.get_session_snapshot("ses_owned"))

            with closing(sqlite3.connect(str(db_path))) as conn2:
                ver = conn2.execute("SELECT value FROM schema_meta WHERE key = 'schema_version'").fetchone()
                self.assertEqual(ver, ("2",))
                cols = {row[1] for row in conn2.execute("PRAGMA table_info(sessions)").fetchall()}
                self.assertIn("owner_subject", cols)

                # Unknown schema version still fails closed.
                conn2.execute("UPDATE schema_meta SET value = '99' WHERE key = 'schema_version'")
                conn2.commit()
            with self.assertRaises(StateStoreError):
                SqliteStateStore(db_path)


class TestStreamableHttpGatewayServer(unittest.TestCase):
    """Tests for StreamableHttpGatewayServer HTTP hardening, HMAC/OIDC modes, isolation, and AAD."""

    def test_host_origin_headers_framing_and_hmac_quickstart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pepper_val = _synth_value("p_" * 20)
            agent_key = _synth_value("agt_key_", "alpha_99")
            approver_key = _synth_value("apr_key_", "beta_88")
            creds = CredentialConfig(
                pepper=pepper_val,
                digests={
                    Role.AGENT: key_digest(agent_key, pepper_val),
                    Role.APPROVER: key_digest(approver_key, pepper_val),
                },
                roles=frozenset({Role.AGENT, Role.APPROVER}),
            )
            policy = PolicyConfig(
                allowed_mcp_servers=frozenset({"remote"}),
                server_presets={"remote": "github"},
                tool_risk_tiers={"remote/get_issue": RiskTier.LOW},
            )
            authz = Authorizer(workspace_root=root, policy_config=policy)
            ds = _FakeDownstream("remote")

            # 1) Unconfigured credentials in hmac mode returns 503 on POST /mcp
            unconf = StreamableHttpGatewayServer(
                authorizer=authz,
                servers={"remote": ds},
                auth_config=AuthConfig(
                    mode="hmac",
                    allowed_origins=("http://127.0.0.1:3000",),
                    allow_insecure_loopback_for_tests=True,
                ),
                credentials=None,
            )
            unconf.start_in_background()
            try:
                st, _h, _b = _http_call(
                    unconf.url,
                    method="POST",
                    headers={"Content-Type": "application/json"},
                    body=b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}',
                )
                self.assertEqual(st, 503)
            finally:
                unconf.shutdown()
                unconf.server_close()

            # 2) Full Host/Origin/framing/HMAC checks
            srv = StreamableHttpGatewayServer(
                authorizer=authz,
                servers={"remote": ds},
                auth_config=AuthConfig(
                    mode="hmac",
                    allowed_origins=("http://127.0.0.1:3000",),
                    allow_insecure_loopback_for_tests=True,
                ),
                credentials=creds,
            )
            srv.start_in_background()
            try:
                base = f"http://127.0.0.1:{srv.server_address[1]}"

                # DNS rebinding Host rejected (421)
                st_host, hdr_host, _ = _http_call(f"{base}/healthz", headers={"Host": "evil.attacker.example"})
                self.assertEqual(st_host, 421)
                self.assertEqual(hdr_host.get("cache-control"), "no-store")
                self.assertEqual(hdr_host.get("x-content-type-options"), "nosniff")
                self.assertEqual(hdr_host.get("x-frame-options"), "DENY")

                # Unlisted Origin and null Origin rejected (403); allowlisted Origin accepted (200)
                for bad_origin in ("https://evil.example", "null"):
                    st_bad_o, _, _ = _http_call(f"{base}/healthz", headers={"Origin": bad_origin})
                    self.assertEqual(st_bad_o, 403)
                st_ok_o, _, health_raw = _http_call(f"{base}/healthz", headers={"Origin": "http://127.0.0.1:3000"})
                self.assertEqual(st_ok_o, 200)
                self.assertEqual(json.loads(health_raw)["auth_mode"], "hmac")

                # GET /mcp -> 405; PRM -> 404 in hmac mode
                st_get, hdr_get, _ = _http_call(f"{base}/mcp")
                self.assertEqual(st_get, 405)
                self.assertEqual(hdr_get.get("allow"), "POST, DELETE")
                st_prm, _, _ = _http_call(f"{base}/.well-known/oauth-protected-resource")
                self.assertEqual(st_prm, 404)

                # Bad keys & approver key rejected on /mcp (401)
                init_bytes = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode()
                for bad_hdrs in (
                    {"Content-Type": "application/json"},
                    {"Content-Type": "application/json", "X-Mellyn-API-Key": "wrong"},
                    {"Content-Type": "application/json", "X-Mellyn-API-Key": approver_key},
                ):
                    st_auth, _, _ = _http_call(f"{base}/mcp", method="POST", headers=bad_hdrs, body=init_bytes)
                    self.assertEqual(st_auth, 401)

                # Non-JSON / duplicate key / batch array rejected
                st_ct, _, _ = _http_call(
                    f"{base}/mcp",
                    method="POST",
                    headers={"Content-Type": "text/plain", "X-Mellyn-API-Key": agent_key},
                    body=init_bytes,
                )
                self.assertEqual(st_ct, 415)
                for bad_body in (b'{"jsonrpc":"2.0","id":1,"id":2}', b'[{"jsonrpc":"2.0","id":1}]'):
                    st_bad, _, _ = _http_call(
                        f"{base}/mcp",
                        method="POST",
                        headers={"Content-Type": "application/json", "X-Mellyn-API-Key": agent_key},
                        body=bad_body,
                    )
                    self.assertEqual(st_bad, 400)

                # Transfer-Encoding: chunked -> 400; oversized Content-Length -> 413
                with closing(http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)) as conn:
                    conn.putrequest("POST", "/mcp")
                    conn.putheader("Content-Type", "application/json")
                    conn.putheader("X-Mellyn-API-Key", agent_key)
                    conn.putheader("Transfer-Encoding", "chunked")
                    conn.endheaders()
                    self.assertEqual(conn.getresponse().status, 400)
                with closing(http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)) as conn:
                    conn.putrequest("POST", "/mcp")
                    conn.putheader("Content-Type", "application/json")
                    conn.putheader("X-Mellyn-API-Key", agent_key)
                    conn.putheader("Content-Length", str(5 * 1024 * 1024))
                    conn.endheaders()
                    self.assertEqual(conn.getresponse().status, 413)

                # Valid AGENT key succeeds via X-Mellyn-API-Key AND Authorization: Bearer
                st_i, hdr_i, body_i = _http_call(
                    f"{base}/mcp",
                    method="POST",
                    headers={"Content-Type": "application/json", "X-Mellyn-API-Key": agent_key},
                    body=init_bytes,
                )
                self.assertEqual(st_i, 200)
                sid = hdr_i.get("mcp-session-id")
                self.assertIsNotNone(sid)
                self.assertIn("result", json.loads(body_i))

                st_l, _, body_l = _http_call(
                    f"{base}/mcp",
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {agent_key}",
                        "Mcp-Session-Id": sid or "",
                    },
                    body=json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}).encode(),
                )
                self.assertEqual(st_l, 200)
                self.assertEqual([t["name"] for t in json.loads(body_l)["result"]["tools"]], ["remote__get_issue"])
            finally:
                srv.shutdown()
                srv.server_close()

    def test_e2e_oidc_client_to_http_gateway_taint_restart_approvals_and_aad(self) -> None:
        client_id = "svc-agent-client"
        client_cred = _synth_value("e2e_cred_", "z9")
        canary_val = _synth_value("MELLYN_", "HTTP_CANARY_", "55102")
        idp = _MockOidcIdpHarness(expected_client_id=client_id, expected_client_cred=client_cred)
        idp.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                db_path = root / "state.db"
                audit_path = root / "http-gateway-audit.jsonl"
                local_ds = _FakeDownstream("local")
                remote_ds = _FakeDownstream("remote")
                policy = PolicyConfig(
                    trusted_mcp_servers=frozenset({"local"}),
                    allowed_mcp_servers=frozenset({"local", "remote"}),
                    server_presets={"local": "mcp-filesystem", "remote": "github"},
                    tool_risk_tiers={"local/write_file": RiskTier.MEDIUM, "remote/get_issue": RiskTier.LOW},
                )
                scanner_cfg = ScannerConfig(
                    canary_tokens=(canary_val,),
                    block_known_secrets=True,
                    aad_kill_on_leak=True,
                )
                logger, audit_handle = AuditLogger.open_chained(audit_path, canary_tokens=(canary_val,))
                try:
                    # 1) Full Pass 1 StreamableHttpDownstream -> Pass 2 StreamableHttpGatewayServer OIDC E2E
                    with SqliteStateStore(db_path) as store1:
                        authz1 = Authorizer(
                            workspace_root=root, policy_config=policy, audit_logger=logger, state_store=store1
                        )
                        approvals1 = PendingApprovals(authz1)
                        auth_cfg = AuthConfig(
                            mode="oidc",
                            issuer=idp.base_url,
                            audience="http://127.0.0.1:0",  # replaced once bound below
                            required_scopes=("mcp:use",),
                            approver_groups=("sec-approvers",),
                            approver_scopes=("mcp:approve",),
                            allow_insecure_loopback_for_tests=True,
                        )
                        validator = OAuthResourceValidator(auth_cfg)
                        gw1 = StreamableHttpGatewayServer(
                            authorizer=authz1,
                            servers={"local": local_ds, "remote": remote_ds},
                            auth_config=auth_cfg,
                            oidc_validator=validator,
                            approvals=approvals1,
                            scanner_config=scanner_cfg,
                        )
                        gw1.start_in_background()
                        # Set resource metadata/audience to the actual bound loopback gateway URL.
                        bound_auth_cfg = AuthConfig(
                            mode="oidc",
                            issuer=idp.base_url,
                            audience=gw1.url,
                            resource=gw1.url,
                            required_scopes=("mcp:use",),
                            approver_groups=("sec-approvers",),
                            approver_scopes=("mcp:approve",),
                            allow_insecure_loopback_for_tests=True,
                        )
                        bound_validator = OAuthResourceValidator(bound_auth_cfg)
                        gw1.auth_config = bound_auth_cfg
                        gw1.oidc_validator = bound_validator

                        apr_srv = ApprovalHTTPServer(approvals1, credentials=None, oidc_validator=bound_validator)
                        apr_srv.start_in_background()

                        cred_env = _synth_value("TEST_E2E_OIDC_", "CRED")
                        with mock.patch.dict(os.environ, {cred_env: client_cred}):
                            oauth_client = OAuthClientConfig(
                                flow="client_credentials",
                                allowed_authorization_servers=(idp.base_url,),
                                client_id=client_id,
                                client_secret_env=cred_env,
                                scopes=("mcp:use",),
                                allow_insecure_loopback_for_tests=True,
                            )
                            upstream_client = StreamableHttpDownstream(
                                "upstream-gw",
                                gw1.url,
                                oauth_config=oauth_client,
                                _allow_loopback_http=True,
                            )
                            try:
                                initialize_downstream(upstream_client)
                                sid_alice = upstream_client._session_id
                                self.assertIsNotNone(sid_alice)
                                self.assertGreaterEqual(idp.state.token_hits, 1)

                                list_res = upstream_client.request("tools/list", {})
                                self.assertIn("remote__get_issue", [t["name"] for t in list_res["result"]["tools"]])

                                # Closing deletes the session via DELETE /mcp
                                upstream_client.close()
                                if sid_alice is not None:
                                    self.assertIsNone(authz1.get_session_snapshot(sid_alice))
                            finally:
                                upstream_client.close()

                        # 2) Per-user session binding, taint isolation, and restart durability
                        alice_tok = _sign_rsa_jwt(
                            {
                                "iss": idp.base_url,
                                "aud": gw1.url,
                                "sub": "alice",
                                "scope": "mcp:use",
                                "exp": int(time.time()) + 600,
                            },
                            idp.state.rsa_k1_priv,
                        )
                        bob_tok = _sign_rsa_jwt(
                            {
                                "iss": idp.base_url,
                                "aud": gw1.url,
                                "sub": "bob",
                                "scope": "mcp:use",
                                "exp": int(time.time()) + 600,
                            },
                            idp.state.rsa_k1_priv,
                        )
                        st_init, hdr_init, _ = _http_call(
                            gw1.url,
                            method="POST",
                            headers={"Content-Type": "application/json", "Authorization": f"Bearer {alice_tok}"},
                            body=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode(),
                        )
                        self.assertEqual(st_init, 200)
                        alice_sid = hdr_init["mcp-session-id"]

                        # Remote tool call taints Alice's session.
                        st_taint, _, body_taint = _http_call(
                            gw1.url,
                            method="POST",
                            headers={
                                "Content-Type": "application/json",
                                "Authorization": f"Bearer {alice_tok}",
                                "Mcp-Session-Id": alice_sid,
                            },
                            body=json.dumps(
                                {
                                    "jsonrpc": "2.0",
                                    "id": 2,
                                    "method": "tools/call",
                                    "params": {"name": "remote__get_issue", "arguments": {"id": 1}},
                                }
                            ).encode(),
                        )
                        self.assertEqual(st_taint, 200)
                        self.assertTrue(json.loads(body_taint)["result"]["ok"])

                        # Bob cannot hijack or delete Alice's Mcp-Session-Id (403 Forbidden).
                        for m in ("POST", "DELETE"):
                            st_bob, _, _ = _http_call(
                                gw1.url,
                                method=m,
                                headers={
                                    "Content-Type": "application/json",
                                    "Authorization": f"Bearer {bob_tok}",
                                    "Mcp-Session-Id": alice_sid,
                                },
                                body=(
                                    json.dumps(
                                        {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}
                                    ).encode()
                                    if m == "POST"
                                    else None
                                ),
                            )
                            self.assertEqual(st_bob, 403)

                        apr_srv.shutdown()
                        apr_srv.server_close()
                        gw1.shutdown()
                        gw1.server_close()

                    # 3) Restart over SAME SqliteStateStore preserves Alice's ownership, taint & IdP-verified approvals
                    with SqliteStateStore(db_path) as store2:
                        authz2 = Authorizer(
                            workspace_root=root, policy_config=policy, audit_logger=logger, state_store=store2
                        )
                        approvals2 = PendingApprovals(authz2)
                        gw2_auth_cfg = AuthConfig(
                            mode="oidc",
                            issuer=idp.base_url,
                            audience="https://mellyn.internal/mcp",
                            required_scopes=("mcp:use",),
                            approver_groups=("sec-approvers",),
                            approver_scopes=("mcp:approve",),
                            allow_insecure_loopback_for_tests=True,
                        )
                        validator2 = OAuthResourceValidator(gw2_auth_cfg)
                        gw2 = StreamableHttpGatewayServer(
                            authorizer=authz2,
                            servers={"local": local_ds, "remote": remote_ds},
                            auth_config=gw2_auth_cfg,
                            oidc_validator=validator2,
                            approvals=approvals2,
                            scanner_config=scanner_cfg,
                        )
                        gw2.start_in_background()
                        apr_srv2 = ApprovalHTTPServer(approvals2, credentials=None, oidc_validator=validator2)
                        apr_srv2.start_in_background()
                        try:
                            alice_tok2 = _sign_rsa_jwt(
                                {
                                    "iss": idp.base_url,
                                    "aud": "https://mellyn.internal/mcp",
                                    "sub": "alice",
                                    "scope": "mcp:use",
                                    "exp": int(time.time()) + 600,
                                },
                                idp.state.rsa_k1_priv,
                            )
                            bob_tok2 = _sign_rsa_jwt(
                                {
                                    "iss": idp.base_url,
                                    "aud": "https://mellyn.internal/mcp",
                                    "sub": "bob",
                                    "scope": "mcp:use",
                                    "exp": int(time.time()) + 600,
                                },
                                idp.state.rsa_k1_priv,
                            )
                            # Bob still rejected on restored session.
                            st_bob2, _, _ = _http_call(
                                gw2.url,
                                method="POST",
                                headers={
                                    "Content-Type": "application/json",
                                    "Authorization": f"Bearer {bob_tok2}",
                                    "Mcp-Session-Id": alice_sid,
                                },
                                body=json.dumps(
                                    {"jsonrpc": "2.0", "id": 10, "method": "tools/list", "params": {}}
                                ).encode(),
                            )
                            self.assertEqual(st_bob2, 403)

                            # Alice calling MEDIUM local tool now requires approval due to persisted SQLite taint!
                            call_local = {
                                "jsonrpc": "2.0",
                                "id": 11,
                                "method": "tools/call",
                                "params": {"name": "local__write_file", "arguments": {"path": "draft.txt"}},
                            }
                            st_hold, _, body_hold = _http_call(
                                gw2.url,
                                method="POST",
                                headers={
                                    "Content-Type": "application/json",
                                    "Authorization": f"Bearer {alice_tok2}",
                                    "Mcp-Session-Id": alice_sid,
                                },
                                body=json.dumps(call_local).encode(),
                            )
                            self.assertEqual(st_hold, 200)
                            hold_rpc = json.loads(body_hold)
                            apr_id = hold_rpc["error"]["data"]["approval_id"]

                            # Non-approver OIDC token gets 403 on ApprovalHTTPServer
                            st_noapr, _, _ = _http_call(
                                f"{apr_srv2.url}/v1/pending/{apr_id}/approve",
                                method="POST",
                                headers={"Content-Type": "application/json", "Authorization": f"Bearer {alice_tok2}"},
                                body=b'{"approved_by":"spoofed-admin"}',
                            )
                            self.assertEqual(st_noapr, 403)

                            # Approver OIDC token overrides spoofed body approved_by with IdP-verified identity!
                            approver_tok = _sign_rsa_jwt(
                                {
                                    "iss": idp.base_url,
                                    "aud": "https://mellyn.internal/mcp",
                                    "sub": "user-apr-99",
                                    "scope": "mcp:approve",
                                    "email": "sec.lead@corp.example",
                                    "email_verified": True,
                                    "groups": ["sec-approvers"],
                                    "exp": int(time.time()) + 600,
                                },
                                idp.state.rsa_k1_priv,
                            )
                            st_apr, _, body_apr = _http_call(
                                f"{apr_srv2.url}/v1/pending/{apr_id}/approve",
                                method="POST",
                                headers={
                                    "Content-Type": "application/json",
                                    "Authorization": f"Bearer {approver_tok}",
                                },
                                body=b'{"approved_by":"spoofed-ceo"}',
                            )
                            self.assertEqual(st_apr, 200)
                            self.assertEqual(
                                json.loads(body_apr)["approved_by"], "oidc:user-apr-99 <sec.lead@corp.example>"
                            )

                            # Retry succeeds cleanly with verified grant!
                            st_retry, _, body_retry = _http_call(
                                gw2.url,
                                method="POST",
                                headers={
                                    "Content-Type": "application/json",
                                    "Authorization": f"Bearer {alice_tok2}",
                                    "Mcp-Session-Id": alice_sid,
                                },
                                body=json.dumps(call_local).encode(),
                            )
                            self.assertEqual(st_retry, 200)
                            self.assertTrue(json.loads(body_retry)["result"]["ok"])

                            # 4) Canary leak fires AAD over HTTP `/mcp`: returns -32099 and contains Alice only
                            remote_ds.canary_text = canary_val
                            st_aad, _, body_aad = _http_call(
                                gw2.url,
                                method="POST",
                                headers={
                                    "Content-Type": "application/json",
                                    "Authorization": f"Bearer {alice_tok2}",
                                    "Mcp-Session-Id": alice_sid,
                                },
                                body=json.dumps(
                                    {
                                        "jsonrpc": "2.0",
                                        "id": 12,
                                        "method": "tools/call",
                                        "params": {"name": "remote__get_issue", "arguments": {"id": 2}},
                                    }
                                ).encode(),
                            )
                            self.assertEqual(st_aad, 200)
                            self.assertEqual(json.loads(body_aad)["error"]["code"], MELLYN_AAD_CONTAINED)
                            # The downstream servers are shared by every caller, so they keep running.
                            self.assertFalse(remote_ds.killed)
                            self.assertFalse(local_ds.killed)
                        finally:
                            apr_srv2.shutdown()
                            apr_srv2.server_close()
                            gw2.shutdown()
                            gw2.server_close()
                finally:
                    audit_handle.close()

                audit_text = audit_path.read_text(encoding="utf-8")
                self.assertNotIn(canary_val, audit_text)
                self.assertNotIn("spoofed-ceo", audit_text)
                self.assertIn("approved_by=oidc:user-apr-99 <sec.lead@corp.example>", audit_text)
                self.assertTrue(verify_gateway_audit_file(audit_path).valid)
        finally:
            idp.stop()


class TestUnifiedAuthConfigAndServeCli(unittest.TestCase):
    """Tests for [auth] config compilation, Squid allowlist sync, fail-closed rejections, and `mellyn serve` CLI."""

    def test_auth_section_compiles_syncs_squid_and_survives_upsert(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg_path = root / "mellyn.toml"
            squid_path = root / "squid.conf"
            cfg_path.write_text(
                "\n".join(
                    [
                        "schema_version = 2",
                        "",
                        "[auth]",
                        'mode = "oidc"',
                        'issuer = "https://idp.corp.example/oauth2"',
                        'audience = "https://mcp.corp.example/mcp"',
                        'resource = "https://mcp.corp.example/mcp"',
                        'jwks_uri = "https://keys.corp.example/jwks.json"',
                        'required_scopes = ["mcp:use"]',
                        'approver_scopes = ["mcp:approve"]',
                        'approver_groups = ["sec-approvers"]',
                        'allowed_origins = ["https://console.corp.example:8443"]',
                        'allowed_hosts = ["mcp.corp.example"]',
                        "clock_skew_seconds = 30",
                        "",
                        "[[servers]]",
                        'name = "local-ws"',
                        'transport = "stdio"',
                        'preset = "mcp-filesystem"',
                        "trusted = true",
                        'command = ["mcp-fs", "--root", "."]',
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            loaded = load_unified_config(cfg_path)
            self.assertEqual(loaded.auth.mode, "oidc")
            self.assertEqual(loaded.auth.issuer, "https://idp.corp.example/oauth2")
            self.assertEqual(loaded.auth.allowed_origins, ("https://console.corp.example:8443",))
            # Identity-provider hosts are for the gateway, not for tools.
            self.assertEqual(loaded.gateway_egress_domains, frozenset({"idp.corp.example", "keys.corp.example"}))
            self.assertNotIn("idp.corp.example", loaded.policy.allowed_egress_domains)

            with contextlib.redirect_stdout(io.StringIO()):
                rc = egress_main(["--policy", str(cfg_path), "--output", str(squid_path)])
            self.assertEqual(rc, 0)
            squid_text = squid_path.read_text(encoding="utf-8")
            self.assertIn("acl gateway_domains dstdomain idp.corp.example", squid_text)
            self.assertIn("acl gateway_domains dstdomain keys.corp.example", squid_text)

            # Pinning a server preserves [auth] cleanly.
            pin_res = GatewayPinResult(
                server_name="local-ws",
                command=("mcp-fs", "--root", "."),
                preset="mcp-filesystem",
                trusted=True,
                tools=(),
                tools_sha256="c" * 64,
                warnings=(),
            )
            upsert_server_in_unified_toml(cfg_path, pin_res)
            reloaded = load_unified_config(cfg_path)
            self.assertEqual(reloaded.auth.mode, "oidc")
            self.assertEqual(reloaded.auth.approver_groups, ("sec-approvers",))

    def test_auth_fail_closed_rejections_and_serve_cli_help(self) -> None:
        base_server = (
            'schema_version = 2\n[[servers]]\nname = "ws"\ntransport = "stdio"\ncommand = ["mcp-fs", "--root", "."]\n'
        )
        bad_auth_blocks = [
            '[auth]\nmode = "oidc"\nissuer = "http://idp.example"\naudience = "aud"\n',
            '[auth]\nmode = "oidc"\nissuer = "https://127.0.0.1/auth"\naudience = "aud"\n',
            '[auth]\nmode = "hmac"\nissuer = "https://idp.example"\n',
            '[auth]\nmode = "oidc"\nissuer = "https://idp.example"\naudience = "aud"\npepper = "x"\n',
            '[auth]\nmode = "oidc"\nissuer = "https://idp.example"\naudience = "aud"\njwt_secret = "x"\n',
            '[auth]\nmode = "oidc"\nissuer = "https://idp.example"\naudience = "aud"\n'
            "allow_insecure_loopback_for_tests = true\n",
            # Approvers listed without an approver scope: the agent's own token would be the approver's token.
            '[auth]\nmode = "oidc"\nissuer = "https://idp.example"\naudience = "aud"\napprover_subjects = ["alice"]\n',
            '[auth]\nmode = "oidc"\nissuer = "https://idp.example"\naudience = "aud"\napprover_groups = ["sec"]\n',
            # The approver scope must not also be an agent scope.
            '[auth]\nmode = "oidc"\nissuer = "https://idp.example"\naudience = "aud"\n'
            'required_scopes = ["mcp:use"]\napprover_scopes = ["mcp:use"]\n',
        ]
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "bad_auth.toml"
            for idx, auth_block in enumerate(bad_auth_blocks):
                cfg_path.write_text(f"{auth_block}\n{base_server}", encoding="utf-8")
                with self.subTest(case=idx), self.assertRaises((PolicyLoadError, ValueError)):
                    load_unified_config(cfg_path)

        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli_main(["serve", "--help"]), 0)

        proc = subprocess.run(
            [sys.executable, "-W", "error", "-m", "mellyn.http_gateway", "--help"],
            cwd=str(_REPO_ROOT),
            env={"PATH": "", "PYTHONPATH": str(_REPO_ROOT / "backend"), "PYTHONUTF8": "1"},
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=15,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertEqual(proc.stderr, "")


if __name__ == "__main__":
    unittest.main()
