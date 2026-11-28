"""Regression tests for all 17 Critical and High findings remediated in SEC-AUDIT-2026-001."""

from __future__ import annotations

import base64
import importlib.util
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

HAS_PYDANTIC = importlib.util.find_spec("pydantic") is not None

if HAS_PYDANTIC or os.environ.get("MELLYN_REQUIRE_API_TESTS") == "1":
    from mellyn.airlock.engine import evaluate_tool_call  # noqa: E402
    from mellyn.airlock.models import AirlockPolicy, JsonRpcRequest, parse_jsonrpc_bytes  # noqa: E402
    from mellyn.core.audit import AuditLedger  # noqa: E402
    from mellyn.core.schemas import ZoneEvent  # noqa: E402
    from mellyn.egress.scanner import scan_payload  # noqa: E402

from mellyn.audit import AuditLogger, format_taint_entry  # noqa: E402
from mellyn.authorizer import Authorizer  # noqa: E402
from mellyn.core.scan import ScannerConfig, redact_core_secrets, scan_value  # noqa: E402
from mellyn.core.strict_input import StrictJsonError, strict_json_loads  # noqa: E402
from mellyn.egress.guards import EgressValidator  # noqa: E402
from mellyn.egress_proxy import generate_squid_config  # noqa: E402
from mellyn.http_downstream import StreamableHttpDownstream  # noqa: E402
from mellyn.mcp_gateway import AAD_EXIT_CODE, MCPGateway, run_stdio_proxy  # noqa: E402
from mellyn.models import Decision, RiskTier, TaintSource, ToolCallRequest, canonical_json  # noqa: E402
from mellyn.oauth_client import OAuthClientConfig, OAuthTokenProvider, read_bounded_bytes  # noqa: E402
from mellyn.pin_gateway import GatewayPinResult, _starter_unified_dict  # noqa: E402
from mellyn.policy import PolicyConfig  # noqa: E402
from mellyn.policy_loader import PolicyLoadError  # noqa: E402
from mellyn.state_store import SqliteStateStore  # noqa: E402
from mellyn.unified_config import parse_unified_dict  # noqa: E402
from tests.fakes import FakeDownstream  # noqa: E402


class _SlowChunkStream:
    """Mock HTTP stream yielding small chunks with controlled monotonic delay."""

    def __init__(self, chunks: list[bytes], delay_s: float) -> None:
        self._chunks = list(chunks)
        self._delay_s = delay_s
        self.raw = self

        class _Sock:
            def __init__(self) -> None:
                self.timeouts: list[float] = []

            def settimeout(self, val: float) -> None:
                self.timeouts.append(val)

        self._sock = _Sock()

    def read1(self, _n: int) -> bytes:
        if not self._chunks:
            return b""
        time.sleep(self._delay_s)
        return self._chunks.pop(0)

    def read(self, n: int = -1) -> bytes:
        return self.read1(n)


class TestCriticalRemediations(unittest.TestCase):
    @unittest.skipUnless(HAS_PYDANTIC, "pydantic is not installed")
    def test_sec01_airlock_rejects_colon_prefixed_relative_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            policy = AirlockPolicy(
                allowed_tools=["read_file", "write_file"],
                workspace_roots=[str(ws)],
            ).with_owned_files(((ws / "airlock_policy.toml", ("",)),))
            for tool, target in (
                ("write_file", "x0:/../airlock_policy.toml"),
                ("read_file", "x0:/../../../etc/passwd"),
                ("read_file", "https://docs.python.org/../../.env"),
            ):
                with self.subTest(tool=tool, target=target):
                    req = JsonRpcRequest(
                        jsonrpc="2.0",
                        id=1,
                        method="tools/call",
                        params={"name": tool, "arguments": {"path": target}},
                    )
                    verdict = evaluate_tool_call(req, policy)
                    self.assertFalse(verdict.verdict_allow)
                    self.assertEqual(verdict.rule_id, "airlock.path_boundary_violation")

            # Clean heuristic `uri` key with https:// still allowed for pure/URL tools
            uri_policy = AirlockPolicy(allowed_tools=["fetch_doc"], workspace_roots=[str(ws)])
            ok_req = JsonRpcRequest(
                jsonrpc="2.0",
                id=2,
                method="tools/call",
                params={"name": "fetch_doc", "arguments": {"uri": "https://docs.python.org/3/library/"}},
            )
            self.assertTrue(evaluate_tool_call(ok_req, uri_policy).verdict_allow)

    def test_sec02_egress_validator_blocks_backslash_and_malformed_authorities(self) -> None:
        ev = EgressValidator(frozenset({"docs.python.org"}))
        for bad_url in (
            r"https://169.254.169.254\.docs.python.org/latest/meta-data/",
            r"https://evil.com\.docs.python.org/exfil",
            "https://evil.com%5c.docs.python.org/exfil",
            "https://bad host.docs.python.org/",
        ):
            with self.subTest(bad_url=bad_url):
                allowed, _ = ev.validate_url(bad_url)
                self.assertFalse(allowed)
        self.assertTrue(ev.validate_url("https://docs.python.org/3/")[0])

    def test_sec03_authorizer_blocks_slash_smuggling_when_mcp_method_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = PolicyConfig(
                allowed_mcp_servers=frozenset({"local-workspace"}),
                trusted_mcp_servers=frozenset({"local-workspace"}),
                server_presets={"local-workspace": "mcp-filesystem", "github": "github"},
                tool_risk_tiers={"local-workspace/read_file": RiskTier.LOW, "github/get_issue": RiskTier.LOW},
            )
            az = Authorizer(workspace_root=Path(tmp), policy_config=cfg)
            sid = az.create_session()
            r1 = az.authorize(ToolCallRequest(sid, "github/get_issue", {}, mcp_server=None))
            r2 = az.authorize(
                ToolCallRequest(sid, "local-workspace/read_file", {"target": "../../.ssh/id_rsa"}, mcp_server=None)
            )
            r3 = az.authorize(
                ToolCallRequest(sid, "resources/read", {"uri": "file:///etc/passwd"}, mcp_server="local-workspace")
            )
            self.assertEqual(r1.decision, Decision.DENY)
            self.assertEqual(r2.decision, Decision.DENY)
            self.assertEqual(r3.decision, Decision.DENY)
            self.assertFalse(az.is_tainted(sid))


class TestHighRemediations(unittest.TestCase):
    def test_sec04_strict_json_loads_linear_on_unclosed_escaped_quotes(self) -> None:
        payload = '"' + '\\"' * 20_000
        start = time.perf_counter()
        with self.assertRaises(json.JSONDecodeError):
            strict_json_loads(payload)
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 0.2)

    def test_sec05_squid_gates_dns_behind_dstdomain_allowlist(self) -> None:
        cfg_allow = generate_squid_config(PolicyConfig(allowed_egress_domains=frozenset({"docs.python.org"})))
        lines = cfg_allow.splitlines()
        self.assertLess(lines.index("http_access deny !allowed_domains"), lines.index("http_access deny blocked_dst"))

        cfg_empty = generate_squid_config(PolicyConfig(allowed_egress_domains=frozenset()))
        self.assertNotIn("http_access deny blocked_dst", cfg_empty)
        self.assertTrue(cfg_empty.rstrip().endswith("http_access deny all"))

    def test_sec06_run_stdio_proxy_exits_aad_exit_code_after_aad(self) -> None:
        canary = "MELLYN_GATEWAY_CANARY_7788"
        with tempfile.TemporaryDirectory() as tmp:
            from mellyn.policy import ToolCapability

            az = Authorizer(
                workspace_root=Path(tmp),
                policy_config=PolicyConfig(
                    allowed_mcp_servers=frozenset({"fs"}),
                    trusted_mcp_servers=frozenset({"fs"}),
                    tool_risk_tiers={"fs/echo": RiskTier.LOW},
                    tool_capabilities={"fs/echo": ToolCapability(pure=True)},
                ),
                audit_logger=AuditLogger(canary_tokens=(canary,)),
            )
            srv = FakeDownstream("fs", ["echo"])
            gw = MCPGateway(
                authorizer=az,
                servers={"fs": srv},
                scanner_config=ScannerConfig(canary_tokens=(canary,), aad_kill_on_leak=True),
            )
            frame1 = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "fs__echo", "arguments": {"x": canary}},
                }
            )
            frame2 = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {}})
            buf_out = io.StringIO()
            rc = run_stdio_proxy(gateway=gw, client_in=io.StringIO(frame1 + "\n" + frame2 + "\n"), client_out=buf_out)
            self.assertEqual(rc, AAD_EXIT_CODE)
            replies = [json.loads(line) for line in buf_out.getvalue().splitlines() if line.strip()]
            self.assertEqual(len(replies), 1)
            self.assertEqual(replies[0]["id"], 1)

    def test_sec07_pin_gateway_does_not_leak_remote_hosts_to_tool_egress(self) -> None:
        starter = _starter_unified_dict(
            GatewayPinResult(
                server_name="gh",
                transport="streamable-http",
                url="https://api.githubcopilot.com/mcp",
                oauth=OAuthClientConfig(
                    flow="client_credentials",
                    allowed_authorization_servers=("https://github.com/login/oauth",),
                    client_id="cid",
                    client_secret_env="GH_SECRET",  # noqa: S106
                    token_endpoint="https://idp.example.com/token",  # noqa: S106
                ),
                tools_sha256="0" * 64,
            )
        )
        self.assertEqual(starter["egress"]["allowed_domains"], [])

    def test_sec08_and_sec15_deep_json_raises_value_error_not_recursion_error(self) -> None:
        deep_frame = b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":' + b"[" * 1000 + b"]" * 1000 + b"}}"
        with self.assertRaises(StrictJsonError):
            if HAS_PYDANTIC:
                parse_jsonrpc_bytes(deep_frame)
            else:
                strict_json_loads(deep_frame)

        deep_obj: Any = "leaf"
        for _ in range(200):
            deep_obj = [deep_obj]
        with self.assertRaises(ValueError):
            canonical_json({"x": deep_obj})

    def test_sec09_oauth_cache_binding_includes_scopes_and_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache = root / "tok.json"
            cfg_wide = OAuthClientConfig(
                flow="client_credentials",
                allowed_authorization_servers=("https://auth.example.com",),
                client_id="cid",
                client_secret_env="OAUTH_SECRET",  # noqa: S106
                scopes=("repo", "admin"),
                token_cache_path=cache,
            )
            prov = OAuthTokenProvider(cfg_wide, resource_url="https://mcp.example.com")
            from mellyn.oauth_client import OAuthToken

            prov._save_cached_token(
                OAuthToken(access_token="tok_val", expires_at=time.time() + 3600)  # noqa: S106
            )
            cfg_narrow = OAuthClientConfig(
                flow="client_credentials",
                allowed_authorization_servers=("https://auth.example.com",),
                client_id="cid",
                client_secret_env="OAUTH_SECRET",  # noqa: S106
                scopes=("repo",),
                token_cache_path=cache,
            )
            prov2 = OAuthTokenProvider(cfg_narrow, resource_url="https://mcp.example.com")
            self.assertIsNone(prov2._token)

            # Corrupt/control-char cache rejected fail closed
            cache.write_text(
                json.dumps(
                    {
                        "binding": prov2._cache_binding(),
                        "access_token": "tok\r\nBad: 1",
                        "expires_at": 9999999999.0,
                    }
                ),
                encoding="utf-8",
            )
            self.assertIsNone(OAuthTokenProvider(cfg_narrow, resource_url="https://mcp.example.com")._token)

            # NaN expires_at rejected
            cache.write_text(
                f'{{"binding": {json.dumps(prov2._cache_binding())}, "access_token": "ok", "expires_at": NaN}}',
                encoding="utf-8",
            )
            self.assertIsNone(OAuthTokenProvider(cfg_narrow, resource_url="https://mcp.example.com")._token)

            # Symlink config load check (when OS allows symlinks)
            link = root / "link_tok.json"
            target = root / "real.json"
            target.write_text("{}", encoding="utf-8")
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                pass
            else:
                with self.assertRaises(PolicyLoadError):
                    parse_unified_dict(
                        {
                            "schema_version": 2,
                            "servers": [
                                {
                                    "name": "remote",
                                    "transport": "streamable-http",
                                    "url": "https://mcp.example.com/mcp",
                                    "oauth": {
                                        "flow": "bearer_env",
                                        "bearer_token_env": "TOK_ENV",
                                        "token_cache_path": str(link),
                                    },
                                }
                            ],
                        },
                        base_dir=root,
                        config_path=root / "mellyn.toml",
                    )

    def test_sec10_slow_drip_streams_abort_at_deadline(self) -> None:
        stream = _SlowChunkStream([b"a"] * 20, delay_s=0.03)
        with self.assertRaises(TimeoutError):
            read_bounded_bytes(stream, max_bytes=1024, deadline=time.monotonic() + 0.08)

        ds = StreamableHttpDownstream("remote", "https://mcp.example.com/mcp")
        sse_stream = _SlowChunkStream([b":"] + [b" "] * 20, delay_s=0.03)
        with self.assertRaises(TimeoutError):
            ds._read_sse_reply(sse_stream, req_id=1, deadline=time.monotonic() + 0.08)

    @unittest.skipUnless(HAS_PYDANTIC, "pydantic is not installed")
    def test_sec11_audit_redacts_field_path_for_split_secrets_and_canaries(self) -> None:
        secret_val = "sk-" + "proj-" + ("A9xQ7mL2pW4zK8rV" * 2)
        canary = "MELLYN_FIELD_CANARY_88"
        with tempfile.TemporaryDirectory() as tmp:
            p1 = Path(tmp) / "a.jsonl"
            sr = scan_payload({"https://alice:SecretPw99": {"@api.example.com": secret_val}})
            ledger = AuditLedger(p1)
            ledger.record(
                ZoneEvent(
                    event_id="e1",
                    timestamp_utc="2026-11-27T00:00:00Z",
                    zone="airlock",
                    action="tools/call",
                    verdict_allow=False,
                    severity="BLOCK",
                    rule_id="egress.secret",
                    reason="blocked",
                    artifact_sha256="0" * 64,
                    redactions=sr.findings,
                )
            )
            self.assertNotIn("SecretPw99", p1.read_text(encoding="utf-8"))

            p2 = Path(tmp) / "b.jsonl"
            sr2 = scan_payload({canary[:11]: {canary[11:]: secret_val}}, canary_tokens=(canary,))
            l2 = AuditLedger(p2, canary_tokens=(canary,))
            l2.record(
                ZoneEvent(
                    event_id="e2",
                    timestamp_utc="2026-11-27T00:00:00Z",
                    zone="airlock",
                    action="tools/call",
                    verdict_allow=False,
                    severity="AAD_FIRE",
                    rule_id="egress.canary",
                    reason="canary",
                    artifact_sha256="0" * 64,
                    redactions=sr2.findings,
                )
            )
            disk = p2.read_text(encoding="utf-8")
            self.assertIn("AAD_FIRE", disk)
            self.assertNotIn(canary, disk)

    def test_sec12_layered_secret_detection_catches_percent_fullwidth_and_decimal_prefix(self) -> None:
        aws_key = "AKIA" + ("W7X8Y9Z0" * 2)
        b64_aws = base64.b64encode(aws_key.encode()).decode()
        percent_broken = b64_aws[:14] + f"%{ord(b64_aws[14]):02X}" + b64_aws[15:]
        fullwidth_esc = "".join(f"\uff3cx{b:02x}" for b in aws_key.encode())
        dec_prefixed = "999 " + " ".join(str(b) for b in aws_key.encode())
        for vec in (percent_broken, fullwidth_esc, dec_prefixed):
            with self.subTest(vec=vec[:24]):
                if HAS_PYDANTIC:
                    self.assertFalse(scan_payload({"v": vec}).clean)
                self.assertFalse(scan_value({"v": vec}, ScannerConfig()).clean)
                self.assertIn("[REDACTED_SECRET]", redact_core_secrets(vec))

    def test_sec13_split_canary_detected_beyond_128kib_padding(self) -> None:
        canary = "MELLYN_SPLIT_128K_9944"
        b64 = base64.b64encode(canary.encode()).decode()
        payload = ["A" * 131_072, b64[:14], b64[14:]]
        self.assertTrue(scan_value(payload, ScannerConfig(canary_tokens=(canary,))).canary_matched)
        if HAS_PYDANTIC:
            self.assertTrue(scan_payload(payload, canary_tokens=(canary,)).canary_matched)

    def test_sec14_and_sec17_audit_and_sqlite_taint_scrub_canaries_before_truncation(self) -> None:
        canary = "MELLYN_AUDIT_CANARY_9944"
        with tempfile.TemporaryDirectory() as tmp:
            lp = Path(tmp) / "gw.jsonl"
            store = SqliteStateStore(Path(tmp) / "state.sqlite3")
            al_handle = None
            try:
                al, al_handle = AuditLogger.open_chained(lp, canary_tokens=(canary,))
                az = Authorizer(workspace_root=Path(tmp), audit_logger=al, state_store=store)
                sid = az.create_session()
                long_origin = "https://example.com/" + "a" * 210 + canary
                az.mark_tainted(sid, TaintSource("mcp", long_origin))
                al.record(
                    session_id=sid,
                    tool_name="workspace_read",
                    mcp_server=None,
                    arguments={},
                    decision=Decision.ALLOW,
                    risk_tier=RiskTier.LOW,
                    tainted=True,
                    taint_sources=(format_taint_entry(TaintSource("mcp", long_origin), canary_tokens=(canary,)),),
                    reasons=("x" * 490 + canary,),
                )
                raw_jsonl = lp.read_text(encoding="utf-8")
                self.assertNotIn(canary[:12], raw_jsonl)
                snap = store.get_session_snapshot(sid)
                if snap is None:
                    self.fail("Expected session snapshot to exist.")
                self.assertNotIn(canary[:12], snap.taint_sample[0].origin)
                self.assertNotIn(canary[:12], snap.taint_entries[0])
            finally:
                if al_handle is not None:
                    al_handle.close()
                store.close()

    def test_sec16_mcp_server_cannot_spoof_default_capabilities(self) -> None:
        with self.assertRaises(ValueError):
            PolicyConfig(
                allowed_mcp_servers=frozenset({"evil"}),
                tool_risk_tiers={"evil/git_status": RiskTier.LOW},
            )
        with tempfile.TemporaryDirectory() as tmp:
            az = Authorizer(
                workspace_root=Path(tmp),
                policy_config=PolicyConfig(allowed_mcp_servers=frozenset({"evil"})),
            )
            sid = az.create_session()
            az.issue_grant(
                session_id=sid,
                tool_name="git_status",
                mcp_server="evil",
                arguments={"path": "../../.ssh/id_rsa"},
                approved_by="approver@example.com",
            )
            res1 = az.authorize(ToolCallRequest(sid, "git_status", {"path": "../../.ssh/id_rsa"}, mcp_server="evil"))
            self.assertEqual(res1.decision, Decision.DENY)

            az.issue_grant(
                session_id=sid,
                tool_name="workspace_read",
                mcp_server="evil",
                arguments={"path": "AGENTS.md"},
                approved_by="approver@example.com",
            )
            res2 = az.authorize(ToolCallRequest(sid, "workspace_read", {"path": "AGENTS.md"}, mcp_server="evil"))
            self.assertEqual(res2.decision, Decision.DENY)


if __name__ == "__main__":
    unittest.main()
