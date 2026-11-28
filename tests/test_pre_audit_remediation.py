"""Regression tests for all 30 findings (Critical, High, Medium, Low) remediated in SEC-AUDIT-2026-001."""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import io
import json
import os
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

HAS_PYDANTIC = importlib.util.find_spec("pydantic") is not None

if HAS_PYDANTIC or os.environ.get("MELLYN_REQUIRE_API_TESTS") == "1":
    from mellyn.airlock.engine import evaluate_tool_call  # noqa: E402
    from mellyn.airlock.models import AirlockPolicy, JsonRpcRequest, parse_jsonrpc_bytes  # noqa: E402
    from mellyn.airlock.pin_cli import _write_atomic_text as pin_cli_write_atomic  # noqa: E402
    from mellyn.airlock.proxy import AirlockProxy, _hard_kill_subprocess  # noqa: E402
    from mellyn.core.audit import AuditLedger, _rotate_aside  # noqa: E402
    from mellyn.core.schemas import ZoneEvent  # noqa: E402
    from mellyn.egress.scanner import scan_payload  # noqa: E402
    from mellyn.ir_lab.verify_chain import read_and_verify_chain, verify_chain_bytes  # noqa: E402

from mellyn.audit import AuditLogger, format_taint_entry  # noqa: E402
from mellyn.authorizer import Authorizer  # noqa: E402
from mellyn.core.audit import (  # noqa: E402
    GENESIS_PREV_HASH,
    LedgerIntegrityError,
    read_regular_file_nofollow,
)
from mellyn.core.normalize import normalize_value  # noqa: E402
from mellyn.core.scan import ScannerConfig, redact_core_secrets, scan_value  # noqa: E402
from mellyn.core.strict_input import StrictJsonError, strict_json_loads  # noqa: E402
from mellyn.egress.guards import EgressValidator, WorkspacePathGuard  # noqa: E402
from mellyn.egress_proxy import generate_squid_config  # noqa: E402
from mellyn.http_downstream import StreamableHttpDownstream  # noqa: E402
from mellyn.init_cmd import (  # noqa: E402
    InitError,
    render_env_file,
    resolve_stack_config,
    run_up,
)
from mellyn.mcp_gateway import (  # noqa: E402
    AAD_EXIT_CODE,
    MCPGateway,
    check_privilege_separation,
    run_stdio_proxy,
)
from mellyn.models import Decision, RiskTier, TaintSource, ToolCallRequest, canonical_json  # noqa: E402
from mellyn.oauth_client import (  # noqa: E402
    OAuthClientConfig,
    OAuthError,
    OAuthTokenProvider,
    discover_authorization_server,
    discover_protected_resource,
    read_bounded_bytes,
)
from mellyn.pin_gateway import GatewayPinError, GatewayPinResult, _starter_unified_dict, _write_atomic  # noqa: E402
from mellyn.policy import PolicyConfig, ScopedRule, program_name  # noqa: E402
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


class TestMediumAndLowRemediations(unittest.TestCase):
    def test_sec18_workspace_path_guard_protects_lock_and_file_subtrees(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            guard = WorkspacePathGuard(ws, extra_protected_paths=("audit.jsonl.*",))
            for rel in ("audit.jsonl.lock", "audit.jsonl.lock/x", ".gitleaks.toml/x"):
                with self.subTest(rel=rel):
                    ok, _ = guard.validate_path(rel, is_write=True)
                    self.assertFalse(ok)

    def test_sec19_drive_relative_windows_path_denied(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            guard = WorkspacePathGuard(Path(tmp))
            self.assertFalse(guard.validate_path("C:secret.txt", is_write=False)[0])
            if HAS_PYDANTIC:
                policy = AirlockPolicy(allowed_tools=["read_file"], workspace_roots=[tmp])
                req = JsonRpcRequest(
                    jsonrpc="2.0",
                    id=1,
                    method="tools/call",
                    params={"name": "read_file", "arguments": {"path": "C:secret.txt"}},
                )
                verdict = evaluate_tool_call(req, policy)
                self.assertFalse(verdict.verdict_allow)
                self.assertEqual(verdict.rule_id, "airlock.path_boundary_violation")

    def test_sec20_program_name_strips_trailing_win32_dots_and_spaces(self) -> None:
        self.assertEqual(program_name("cmd.exe."), "cmd")
        self.assertEqual(program_name(r"C:\Windows\System32\powershell.EXE . "), "powershell")
        with tempfile.TemporaryDirectory() as tmp:
            cfg = PolicyConfig(
                scoped_rules=(ScopedRule("deny-rm", "shell_exec", Decision.DENY, programs=frozenset({"rm"})),)
            )
            az = Authorizer(workspace_root=Path(tmp), policy_config=cfg)
            sid = az.create_session()
            res_rm = az.authorize(ToolCallRequest(sid, "shell_exec", {"argv": ["rm.exe.", "-rf", "/"]}))
            res_py = az.authorize(ToolCallRequest(sid, "shell_exec", {"argv": ["python.exe.", "-c", "print(1)"]}))
            self.assertEqual(res_rm.decision, Decision.DENY)
            self.assertEqual(res_py.decision, Decision.DENY)

    @unittest.skipUnless(HAS_PYDANTIC, "pydantic is not installed")
    def test_sec21_airlock_rejects_file_uri_query_and_fragment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            target = ws / "note.txt"
            target.write_text("ok\n", encoding="utf-8")
            policy = AirlockPolicy(
                allowed_tools=["read_file"],
                allow_resources_read=True,
                workspace_roots=[str(ws)],
            )
            base_uri = target.as_uri()
            for bad_uri in (f"{base_uri}?raw=1", f"{base_uri}#frag"):
                req = JsonRpcRequest(
                    jsonrpc="2.0",
                    id=1,
                    method="tools/call",
                    params={"name": "read_file", "arguments": {"path": bad_uri}},
                )
                verdict = evaluate_tool_call(req, policy)
                self.assertFalse(verdict.verdict_allow)
                self.assertEqual(verdict.rule_id, "airlock.path_boundary_violation")

    @unittest.skipUnless(HAS_PYDANTIC, "pydantic is not installed")
    def test_sec22_airlock_fires_aad_on_name_notifications_unallowed_methods_and_cursor(self) -> None:
        canary = "MELLYN_SEC22_CANARY_42"
        with tempfile.TemporaryDirectory() as tmp:
            policy_enforce = AirlockPolicy(
                allowed_tools=["safe_tool"],
                canary_tokens=[canary],
                workspace_roots=[tmp],
            )
            req_name = JsonRpcRequest(
                jsonrpc="2.0",
                id=1,
                method="tools/call",
                params={"name": f"safe_{canary}", "arguments": {}},
            )
            v_name = evaluate_tool_call(req_name, policy_enforce)
            self.assertEqual(v_name.severity, "AAD_FIRE")

            req_split = JsonRpcRequest(
                jsonrpc="2.0",
                id=2,
                method="tools/call",
                params={"name": canary[:11], "arguments": {"x": canary[11:]}},
            )
            v_split = evaluate_tool_call(req_split, policy_enforce)
            self.assertEqual(v_split.severity, "AAD_FIRE")

            async def _exercise_proxy() -> None:
                from mellyn.airlock.models import JsonRpcNotification

                class _MemWriter:
                    def write(self, _b: bytes) -> None:
                        return None

                    async def drain(self) -> None:
                        return None

                def _make_proxy(mode: str, allow_obs: bool, name: str) -> tuple[AirlockProxy, Path]:
                    lp = Path(tmp) / f"{name}.jsonl"
                    ledger = AuditLedger(lp)
                    pol = AirlockPolicy(
                        allowed_tools=["safe_tool"],
                        canary_tokens=[canary],
                        workspace_roots=[tmp],
                        allow_resources_read=False,
                        allow_observe_mode=allow_obs,
                    )
                    proxy = AirlockProxy(
                        command=["python", "-c", "pass"],
                        policy=pol,
                        ledger=ledger,
                        client_reader=asyncio.StreamReader(),
                        client_writer=_MemWriter(),  # type: ignore[arg-type]
                        mode="observe" if mode == "observe" else "enforce",
                    )
                    return proxy, lp

                # Each enforce vector must trigger AAD_FIRE on its own proxy instance
                p1, lp1 = _make_proxy("enforce", False, "enf_0")
                await p1._handle_client_notification(
                    JsonRpcNotification(jsonrpc="2.0", method="notifications/evil", params={"x": canary}),
                    wire_bytes=b"{}\n",
                    wire_sha="0" * 64,
                )
                self.assertTrue(p1.aad_fired)
                self.assertIn("AAD_FIRE", [json.loads(ln)["event"]["severity"] for ln in lp1.read_text().splitlines()])

                for idx, req in enumerate(
                    (
                        JsonRpcRequest(jsonrpc="2.0", id=10, method="resources/read", params={"uri": canary}),
                        JsonRpcRequest(jsonrpc="2.0", id=11, method="tools/unlisted", params={"x": canary}),
                        JsonRpcRequest(jsonrpc="2.0", id=12, method="tools/list", params={"cursor": canary}),
                    ),
                    start=1,
                ):
                    p_enf, lp_enf = _make_proxy("enforce", False, f"enf_{idx}")
                    await p_enf._handle_client_request(req, wire_bytes=b"{}\n", wire_sha="0" * 64)
                    self.assertTrue(p_enf.aad_fired, f"Vector {idx} did not fire AAD")
                    sevs = [json.loads(ln)["event"]["severity"] for ln in lp_enf.read_text().splitlines()]
                    self.assertIn("AAD_FIRE", sevs)

                # In observe mode, none terminate the session, and all 4 still emit AAD_FIRE telemetry
                p_obs, lp_obs = _make_proxy("observe", True, "obs")
                await p_obs._handle_client_notification(
                    JsonRpcNotification(jsonrpc="2.0", method="notifications/evil", params={"x": canary}),
                    wire_bytes=b"{}\n",
                    wire_sha="0" * 64,
                )
                for req in (
                    JsonRpcRequest(jsonrpc="2.0", id=20, method="resources/read", params={"uri": canary}),
                    JsonRpcRequest(jsonrpc="2.0", id=21, method="tools/unlisted", params={"x": canary}),
                    JsonRpcRequest(jsonrpc="2.0", id=22, method="tools/list", params={"cursor": canary}),
                ):
                    await p_obs._handle_client_request(req, wire_bytes=b"{}\n", wire_sha="0" * 64)
                self.assertFalse(p_obs.aad_fired)
                obs_sevs = [json.loads(ln)["event"]["severity"] for ln in lp_obs.read_text().splitlines() if ln.strip()]
                self.assertEqual(obs_sevs.count("AAD_FIRE"), 4)

            asyncio.run(_exercise_proxy())

    @unittest.skipUnless(HAS_PYDANTIC, "pydantic is not installed")
    def test_sec23_hard_kill_posix_calls_killpg_even_if_leader_exited(self) -> None:
        class _ExitedProc:
            pid = 4242
            returncode = 0

            async def wait(self) -> int:
                return 0

            def kill(self) -> None:
                return None

        killpg_mock = mock.MagicMock()
        fake_os = types.SimpleNamespace(name="posix", killpg=killpg_mock)
        with (
            mock.patch("mellyn.airlock.proxy.os", fake_os),
            mock.patch("mellyn.airlock.proxy.signal.SIGKILL", 9, create=True),
        ):
            asyncio.run(_hard_kill_subprocess(_ExitedProc()))  # type: ignore[arg-type]
        killpg_mock.assert_called_once_with(4242, 9)

    def test_sec24_pin_atomic_writes_reject_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "out.toml"
            with mock.patch("mellyn.pin_gateway._is_link_or_junction", return_value=True):
                with self.assertRaises(GatewayPinError):
                    _write_atomic(target, "a = 1\n")
            _write_atomic(target, "a = 1\n")
            self.assertEqual(target.read_text(encoding="utf-8"), "a = 1\n")
            if HAS_PYDANTIC:
                cli_target = Path(tmp) / "pin.toml"
                with mock.patch("mellyn.airlock.pin_cli._is_link_or_junction", return_value=True):
                    with self.assertRaises(OSError):
                        pin_cli_write_atomic(cli_target, "x = 1\n")
                pin_cli_write_atomic(cli_target, "x = 1\n")
                self.assertEqual(cli_target.read_text(encoding="utf-8"), "x = 1\n")

    @unittest.skipUnless(HAS_PYDANTIC, "pydantic is not installed")
    def test_sec25_downstream_write_timeout_closes_stalled_stdin(self) -> None:
        class _StalledStdin:
            def __init__(self) -> None:
                self.closed = False

            def write(self, _b: bytes) -> None:
                return None

            async def drain(self) -> None:
                await asyncio.sleep(0.3)

            def close(self) -> None:
                self.closed = True

        class _Proc:
            def __init__(self) -> None:
                self.stdin = _StalledStdin()

        class _MemWriter:
            def write(self, _b: bytes) -> None:
                return None

            async def drain(self) -> None:
                return None

        with tempfile.TemporaryDirectory() as tmp:
            lp = Path(tmp) / "audit.jsonl"

            async def _run() -> tuple[bool, bool, bool]:
                pol = AirlockPolicy(allowed_tools=["echo"])
                proxy = AirlockProxy(
                    command=["python", "-c", "pass"],
                    policy=pol,
                    ledger=AuditLedger(lp),
                    client_reader=asyncio.StreamReader(),
                    client_writer=_MemWriter(),  # type: ignore[arg-type]
                )
                proxy._downstream_write_timeout = 0.04
                proc = _Proc()
                proxy._proc = proc  # type: ignore[assignment]
                ok = await proxy._write_downstream_bytes(b"{}\n")
                return ok, proxy._downstream_stdin_closed, proc.stdin.closed

            ok, closed_flag, stdin_closed = asyncio.run(_run())
        self.assertFalse(ok)
        self.assertTrue(closed_flag)
        self.assertTrue(stdin_closed)

    def test_sec26_mcp_gateway_list_all_handles_null_tools_safely(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            az = Authorizer(
                workspace_root=Path(tmp),
                policy_config=PolicyConfig(allowed_mcp_servers=frozenset({"srv"})),
            )
            srv = FakeDownstream("srv", ["ping"])
            srv.request = lambda _m, _p=None: {"jsonrpc": "2.0", "id": 1, "result": {"tools": None}}  # type: ignore[method-assign]
            gw = MCPGateway(authorizer=az, servers={"srv": srv})
            self.assertEqual(gw._list_all(srv, "tools/list", "tools"), [])

    def test_sec27_oauth_origin_pinning_enforced_with_allowed_domains(self) -> None:
        def _fake_json(payload: dict[str, Any]) -> Any:
            raw = json.dumps(payload).encode("utf-8")

            class _Resp:
                def __enter__(self) -> _Resp:
                    return self

                def __exit__(self, *_a: object) -> None:
                    return None

                def read(self, n: int = -1) -> bytes:
                    return raw if n < 0 else raw[:n]

            return _Resp()

        opener = mock.MagicMock()
        opener.open.side_effect = [
            _fake_json(
                {
                    "issuer": "https://auth.example.com",
                    "token_endpoint": "https://evil.example.com/token",
                }
            )
        ]
        with self.assertRaises(OAuthError):
            discover_protected_resource(
                "https://mcp.example.com/mcp",
                allowed_authorization_servers=("https://auth.example.com",),
                www_authenticate='Bearer resource_metadata="https://evil.example.com/prm"',
                allowed_domains=frozenset({"mcp.example.com", "evil.example.com", "auth.example.com"}),
                opener=opener,
            )
        with self.assertRaises(OAuthError):
            discover_authorization_server(
                "https://auth.example.com",
                allowed_domains=frozenset({"auth.example.com", "evil.example.com"}),
                opener=opener,
            )

    def test_sec28_normalize_depth_cap_and_ir_chain_nofollow(self) -> None:
        deep: Any = "leaf"
        for _ in range(150):
            deep = [deep]
        with self.assertRaises(ValueError):
            normalize_value(deep)

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "audit.jsonl"
            p.write_text("ok\n", encoding="utf-8")
            with mock.patch("mellyn.core.audit.is_link_or_junction", return_value=True):
                with self.assertRaises(OSError):
                    read_regular_file_nofollow(p)

            if HAS_PYDANTIC:
                bad_entry = {
                    "schema_version": 2,
                    "seq": 0,
                    "prev_hash": GENESIS_PREV_HASH,
                    "entry_hash": "0" * 64,
                    "source": "airlock",
                    "event": {"nested": deep},
                }
                report = verify_chain_bytes((json.dumps(bad_entry) + "\n").encode("utf-8"), ledger_path=str(p))
                self.assertFalse(report.valid)

                from datetime import UTC, datetime

                with mock.patch("mellyn.core.audit.is_link_or_junction", side_effect=lambda x: x.name != "audit.jsonl"):
                    with self.assertRaises(LedgerIntegrityError):
                        _rotate_aside(p, tag="v1", now_fn=lambda: datetime.now(UTC))

                with mock.patch("mellyn.ir_lab.verify_chain.is_link_or_junction", return_value=True):
                    rep, raw = read_and_verify_chain(p)
                    self.assertFalse(rep.valid)
                    self.assertIsNone(raw)

    def test_sec29_init_cmd_rejects_newline_env_and_nested_config_env(self) -> None:
        from mellyn.init_cmd import generate_credentials_bundle

        bundle = generate_credentials_bundle()
        with self.assertRaises(InitError):
            render_env_file(bundle, workspace_root=Path("ws\nMELLYN_EVIL=1"))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = root / "config"
            sub = cfg / "sub"
            sub.mkdir(parents=True)
            (cfg / "mellyn-policy.toml").write_text("[policy]\n", encoding="utf-8")
            (cfg / "mellyn-gateway.toml").write_text("servers = []\n", encoding="utf-8")
            compose = root / "compose.yaml"
            compose.write_text("services: {}\n", encoding="utf-8")
            nested_env = sub / ".env"
            nested_env.write_text(render_env_file(bundle, config_dir=cfg), encoding="utf-8")
            with self.assertRaises(InitError):
                run_up(compose_file=compose, squid_output=root / "squid.conf", env_file=nested_env, dry_run=True)

            with mock.patch(
                "mellyn.init_cmd._is_link_or_junction", side_effect=lambda p: p.name == "mellyn-policy.example.toml"
            ):
                with self.assertRaises(InitError):
                    resolve_stack_config(compose, {})

    def test_sec30_uid0_rejected_resource_http_egress_checked_and_jwt_redacted(self) -> None:
        with self.assertRaises(RuntimeError):
            check_privilege_separation(
                running_as_root=True,
                is_pid1=True,
                gateway_user="0",
                downstream_user="nobody",
            )
        with self.assertRaises(RuntimeError):
            check_privilege_separation(
                running_as_root=True,
                is_pid1=True,
                gateway_user="nobody",
                downstream_user="root",
            )

        with tempfile.TemporaryDirectory() as tmp:
            az = Authorizer(
                workspace_root=Path(tmp),
                policy_config=PolicyConfig(allowed_egress_domains=frozenset({"docs.python.org"})),
            )
            self.assertFalse(az._check_resource_uri("https://169.254.169.254/latest")[0])
            self.assertFalse(az._check_resource_uri("https://evil.example.com/exfil")[0])
            self.assertTrue(az._check_resource_uri("https://docs.python.org/3/library/")[0])

        fake_jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiJ1c2VyXzEyMzQ1NiIsInJvbGUiOiJhZG1pbiJ9"
            ".dGhpcy1pcy1hLXN5bnRoZXRpYy1oaWdoLWVudHJvcHktc2ln"
        )
        # Replace repetitive tail with mixed high-entropy characters cleanly assembled at runtime
        rng_sig = "aB9xK2mP7qL4zR8vT1wY6nC3jF5hD0sG"
        synth_jwt = fake_jwt.rsplit(".", 1)[0] + "." + rng_sig
        sr = scan_value({"auth": synth_jwt}, ScannerConfig(detect_high_entropy=True))
        self.assertFalse(sr.clean)
        self.assertTrue(sr.high_entropy_matched)


if __name__ == "__main__":
    unittest.main()
