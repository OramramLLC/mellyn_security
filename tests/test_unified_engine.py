"""Unit and integration tests for Pass 2 unified engine (scanner, hash chain, mellyn.toml, gateway AAD & observe)."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from typing import Any
from unittest import mock

# Make the module importable on its own, not only after another test file has put src/ on sys.path.
_REPO_ROOT = Path(__file__).resolve().parent.parent
for _import_dir in (_REPO_ROOT / "src",):
    if str(_import_dir) not in sys.path:
        sys.path.insert(0, str(_import_dir))

from mellyn import (  # noqa: E402
    AuditChainError,
    AuditLogger,
    Authorizer,
    PolicyConfig,
    PolicyLoadError,
    RiskTier,
    ScannerConfig,
    SqliteStateStore,
    TaintSource,
    ToolCapability,
    load_mellyn_config,
    load_unified_config,
    scan_value,
    verify_gateway_audit_file,
    verify_gateway_audit_lines,
)
from mellyn.audit import GENESIS_PREV_HASH, _is_legacy_unchained_log  # noqa: E402
from mellyn.cli import main as cli_main  # noqa: E402
from mellyn.egress_proxy import main as egress_main  # noqa: E402
from mellyn.init_cmd import init_workspace, run_up  # noqa: E402
from mellyn.mcp_gateway import (  # noqa: E402
    MELLYN_AAD_CONTAINED,
    MELLYN_POLICY_DENIED,
    MCPGateway,
)
from mellyn.mcp_gateway import (  # noqa: E402
    main as gateway_main,
)
from mellyn.unified_config import load_policy_any, render_unified_config  # noqa: E402


def _synth_canary() -> str:
    # Build via concatenation so static secret scanners never mistake a test canary for a live credential.
    return "".join(["MELLYN_", "SYNTH_", "CANARY_", "948271"])


def _synth_gh_cred() -> str:
    return "".join(["ghp", "_", "TestVal1234567890ABCDEFG"])


def _synth_ant_cred() -> str:
    return "".join(["sk", "-ant-", "api03-", "SynthTestValue_0123456789"])


def _synth_stripe_cred() -> str:
    return "".join(["sk", "_live_", "SynthTestValue01234567"])


class _FakeDownstream:
    """In-memory mock MCP downstream server recording forwarded calls and kill_now() invocations."""

    def __init__(
        self,
        name: str,
        *,
        tools: list[dict[str, Any]] | None = None,
        resources: list[dict[str, Any]] | None = None,
        tool_result: Any = None,
        resource_result: Any = None,
    ) -> None:
        self.name = name
        self.tools = (
            tools if tools is not None else [{"name": "echo", "description": "Safe test tool", "inputSchema": {}}]
        )
        self.resources = resources if resources is not None else []
        self.tool_result = tool_result if tool_result is not None else {"content": [{"type": "text", "text": "ok"}]}
        self.resource_result = (
            resource_result
            if resource_result is not None
            else {"contents": [{"uri": "file:///workspace/readme.txt", "text": "ok"}]}
        )
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.notifications: list[str] = []
        self.killed = False
        self.closed = False
        self._next_id = 1

    def request(self, method: str, params: dict[str, Any] | None = None, timeout: float = 1.0) -> dict[str, Any]:
        del timeout
        payload = dict(params or {})
        self.calls.append((method, payload))
        rid = self._next_id
        self._next_id += 1
        if method == "initialize":
            return {"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2025-06-18", "capabilities": {}}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": rid, "result": {"tools": list(self.tools)}}
        if method == "resources/list":
            return {"jsonrpc": "2.0", "id": rid, "result": {"resources": list(self.resources)}}
        if method == "tools/call":
            result = self.tool_result(payload) if callable(self.tool_result) else self.tool_result
            return {"jsonrpc": "2.0", "id": rid, "result": result}
        if method == "resources/read":
            result = self.resource_result(payload) if callable(self.resource_result) else self.resource_result
            return {"jsonrpc": "2.0", "id": rid, "result": result}
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "unknown method"}}

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        del params
        self.notifications.append(method)

    def kill_now(self) -> None:
        self.killed = True
        self.closed = True

    def close(self) -> None:
        self.closed = True


class TestGatewayHashChainedAudit(unittest.TestCase):
    """Tests for `AuditLogger.open_chained()`, pre-hash redaction, tamper detection, and CLI `mellyn verify`."""

    def test_open_chained_writes_sequential_hash_chain_and_resumes_across_restarts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.jsonl"

            logger1, handle1 = AuditLogger.open_chained(log_path, enforcement_mode="enforce")
            try:
                ev0 = logger1.record_taint(session_id="ses_1", taint_count=1, taint_sources=("src:test",))
                ev1 = logger1.record_containment(
                    session_id="ses_1",
                    tool_name="srv__tool",
                    mcp_server="srv",
                    decision="blocked_egress",
                    reasons=("Blocked sensitive string",),
                )
            finally:
                handle1.close()

            self.assertEqual(ev0.seq, 0)
            self.assertEqual(ev0.prev_hash, GENESIS_PREV_HASH)
            self.assertEqual(ev1.seq, 1)
            self.assertEqual(ev1.prev_hash, ev0.entry_hash)
            self.assertEqual(ev1.enforcement_mode, "enforce")

            # Resume same ledger across a gateway restart.
            logger2, handle2 = AuditLogger.open_chained(log_path, enforcement_mode="observe")
            try:
                ev2 = logger2.record_taint(session_id="ses_1", taint_count=2, taint_sources=("src:test2",))
            finally:
                handle2.close()

            self.assertEqual(ev2.seq, 2)
            self.assertEqual(ev2.prev_hash, ev1.entry_hash)
            self.assertEqual(ev2.enforcement_mode, "observe")

            res = verify_gateway_audit_file(log_path)
            self.assertTrue(res.valid, res.reason)
            self.assertEqual(res.entry_count, 3)
            self.assertEqual(res.last_seq, 2)
            self.assertEqual(res.last_hash, ev2.entry_hash)

            raw_lines = [line for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            lines_res = verify_gateway_audit_lines(raw_lines)
            self.assertTrue(lines_res.valid)
            self.assertEqual(lines_res.last_hash, ev2.entry_hash)

    def test_canary_and_secrets_scrubbed_before_hashing_and_disk_write(self) -> None:
        canary = _synth_canary()
        ant_cred = _synth_ant_cred()
        url_with_cred = "".join(["https://svc_acct:", "PassWord_9981", "@api.example.com/hook"])
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.jsonl"
            logger, handle = AuditLogger.open_chained(log_path, canary_tokens=(canary,))
            try:
                event = logger.record_containment(
                    session_id="ses_1",
                    tool_name="srv__send",
                    mcp_server="srv",
                    decision="aad_fire",
                    reasons=(f"leaked {canary} and {ant_cred} to {url_with_cred}",),
                )
            finally:
                handle.close()

            raw_disk = log_path.read_text(encoding="utf-8")
            self.assertNotIn(canary, raw_disk)
            self.assertNotIn(ant_cred, raw_disk)
            self.assertNotIn("PassWord_9981", raw_disk)
            self.assertIn("[REDACTED_CANARY]", event.reasons[0])
            self.assertIn("[REDACTED_SECRET]", event.reasons[0])
            self.assertTrue(verify_gateway_audit_file(log_path).valid)

    def test_tampering_corrupt_tail_and_symlink_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log_path = root / "audit.jsonl"
            logger, handle = AuditLogger.open_chained(log_path)
            try:
                for i in range(3):
                    logger.record_taint(session_id="ses_1", taint_count=i + 1, taint_sources=(f"s:{i}",))
            finally:
                handle.close()

            orig_lines = [line for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(len(orig_lines), 3)

            # 1) Field modification on line 2
            mod_lines = list(orig_lines)
            row1 = json.loads(mod_lines[1])
            row1["taint_count"] = 999
            mod_lines[1] = json.dumps(row1, sort_keys=True)
            mod_path = root / "mod.jsonl"
            mod_path.write_text("\n".join(mod_lines) + "\n", encoding="utf-8")
            res_mod = verify_gateway_audit_file(mod_path)
            self.assertFalse(res_mod.valid)
            self.assertEqual(res_mod.first_invalid_line, 2)

            # 2) Swapped lines
            swap_path = root / "swap.jsonl"
            swap_path.write_text("\n".join([orig_lines[0], orig_lines[2], orig_lines[1]]) + "\n", encoding="utf-8")
            res_swap = verify_gateway_audit_file(swap_path)
            self.assertFalse(res_swap.valid)
            self.assertEqual(res_swap.first_invalid_line, 2)

            # 3) Deleted middle line (seq gap)
            gap_path = root / "gap.jsonl"
            gap_path.write_text("\n".join([orig_lines[0], orig_lines[2]]) + "\n", encoding="utf-8")
            res_gap = verify_gateway_audit_file(gap_path)
            self.assertFalse(res_gap.valid)
            self.assertEqual(res_gap.first_invalid_line, 2)

            # 4) Truncated/corrupt tail rejected both by verifier and open_chained()
            corrupt_path = root / "corrupt.jsonl"
            corrupt_path.write_text("\n".join(orig_lines) + '\n{"truncated": ', encoding="utf-8")
            res_corrupt = verify_gateway_audit_file(corrupt_path)
            self.assertFalse(res_corrupt.valid)
            self.assertEqual(res_corrupt.first_invalid_line, 4)
            with self.assertRaises(AuditChainError):
                _, h = AuditLogger.open_chained(corrupt_path)
                h.close()

            # 5) Symlink rejected fail-closed
            with mock.patch.object(Path, "is_symlink", return_value=True):
                with self.assertRaises(AuditChainError):
                    verify_gateway_audit_file(log_path)
                with self.assertRaises(AuditChainError):
                    _, h = AuditLogger.open_chained(log_path)
                    h.close()

    @unittest.skipUnless(
        importlib.util.find_spec("pydantic") is not None or os.environ.get("MELLYN_REQUIRE_API_TESTS") == "1",
        "verifying an Airlock ledger needs mellyn.core.audit, which needs pydantic",
    )
    def test_cli_verify_routes_gateway_and_airlock_ledgers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gw_path = root / "gateway.jsonl"
            logger, handle = AuditLogger.open_chained(gw_path)
            try:
                logger.record_taint(session_id="ses_1", taint_count=1, taint_sources=("x:1",))
                logger.record_taint(session_id="ses_1", taint_count=2, taint_sources=("x:2",))
            finally:
                handle.close()

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main(["verify", str(gw_path), "--json"])
            self.assertEqual(rc, 0)
            report = json.loads(buf.getvalue())
            self.assertEqual(report["ledger_type"], "gateway")
            self.assertTrue(report["valid"])
            self.assertEqual(report["entry_count"], 2)

            tampered = root / "gateway-bad.jsonl"
            tampered.write_text(gw_path.read_text(encoding="utf-8") + "{bad json\n", encoding="utf-8")
            err_buf = io.StringIO()
            with contextlib.redirect_stderr(err_buf):
                rc_bad = cli_main(["verify", str(tampered)])
            self.assertEqual(rc_bad, 2)
            self.assertIn("INVALID", err_buf.getvalue())

            # Airlock-shaped JSON line (has `"event"` object) routes to Airlock forensic verifier, not Gateway.
            airlock_bad = root / "airlock.jsonl"
            airlock_bad.write_text(
                json.dumps(
                    {
                        "seq": 0,
                        "prev_hash": GENESIS_PREV_HASH,
                        "entry_hash": "1" * 64,
                        "event": {"zone": "AIRLOCK_INGRESS", "action": "ALLOW"},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            air_buf = io.StringIO()
            with contextlib.redirect_stdout(air_buf):
                rc_air = cli_main(["verify", str(airlock_bad), "--json"])
            self.assertEqual(rc_air, 2)
            air_report = json.loads(air_buf.getvalue())
            self.assertEqual(air_report["status"], "INTEGRITY_COMPROMISED")
            self.assertIn("verification", air_report)


class TestGatewayScanner(unittest.TestCase):
    """Tests for stdlib obfuscated canary, secret, and regex payload scanning (`mellyn.scanner`)."""

    def test_detects_raw_and_obfuscated_canary_variants(self) -> None:
        canary = _synth_canary()
        cfg = ScannerConfig(canary_tokens=(canary,), block_known_secrets=False, blocked_patterns=())
        canary_bytes = canary.encode("utf-8")

        variants: dict[str, Any] = {
            "raw": {"msg": f"prefix {canary} suffix"},
            "casefold_nfkc": canary.lower().replace("m", "\uff4d"),
            "invisible_unicode": f"{canary[:6]}\u200b{canary[6:14]}\ufeff{canary[14:]}",
            "percent_encoded": urllib.parse.quote(canary, safe=""),
            "double_percent_encoded": urllib.parse.quote(urllib.parse.quote(canary, safe=""), safe=""),
            "contiguous_hex": canary_bytes.hex(),
            "delimited_hex": ":".join(f"{b:02x}" for b in canary_bytes),
            "reversed": canary[::-1],
            "separator_skeleton": canary.replace("_", "---"),
            "b64_offset0": base64.b64encode(canary_bytes).decode("ascii"),
            "b64_offset1": base64.b64encode(b"x" + canary_bytes).decode("ascii"),
            "b64_offset2": base64.b64encode(b"xy" + canary_bytes).decode("ascii"),
            "split_across_fields": {
                "second_part": canary[len(canary) // 2 :],
                "nested": {"first_part": canary[: len(canary) // 2]},
            },
        }
        for label, payload in variants.items():
            with self.subTest(variant=label):
                res = scan_value(payload, cfg)
                self.assertFalse(res.clean, f"Expected canary detection for variant={label}")
                self.assertTrue(res.canary_matched, f"Expected canary_matched for variant={label}")

    def test_detects_synthetic_secrets_when_enabled(self) -> None:
        cfg = ScannerConfig(canary_tokens=(), block_known_secrets=True)
        for label, val in (
            ("gh", _synth_gh_cred()),
            ("ant", _synth_ant_cred()),
            ("stripe", _synth_stripe_cred()),
        ):
            with self.subTest(cred_kind=label):
                res = scan_value({"body": f"val={val}"}, cfg)
                self.assertFalse(res.clean)
                self.assertTrue(res.secret_matched)
                self.assertFalse(res.canary_matched)

    def test_custom_blocked_patterns_and_invalid_regex_rejected(self) -> None:
        cfg = ScannerConfig(block_known_secrets=False, blocked_patterns=(r"INTERNAL_PROJ-\d{4}",))
        matched = scan_value({"note": "Exporting INTERNAL_PROJ-4821 now"}, cfg)
        self.assertFalse(matched.clean)
        self.assertTrue(matched.blocked_pattern_matched)

        with self.assertRaises(ValueError):
            ScannerConfig(blocked_patterns=(r"[unclosed(",))

    def test_benign_payload_is_clean(self) -> None:
        cfg = ScannerConfig(
            canary_tokens=(_synth_canary(),),
            block_known_secrets=True,
            blocked_patterns=(r"INTERNAL_PROJ-\d{4}",),
        )
        res = scan_value({"query": "List open issues assigned to Alice", "limit": 10}, cfg)
        self.assertTrue(res.clean)
        self.assertEqual(res.findings, ())


class TestUnifiedConfig(unittest.TestCase):
    """Tests for unified `schema_version = 2` `mellyn.toml`, fail-closed checks, and `init --unified`."""

    def test_load_unified_config_compiles_presets_pins_egress_scanner_runtime_and_policy(self) -> None:
        canary = _synth_canary()
        pin = hashlib.sha256(b"[]").hexdigest()
        toml_text = f"""
schema_version = 2

[runtime]
mode = "enforce"
allow_observe_mode = false
state_db = "state/mellyn.sqlite3"
audit_log = "logs/mellyn-audit.jsonl"

[egress]
allowed_domains = ["api.custom-vendor.example"]
auto_sync_squid = true

[scanner]
canary_tokens = ["{canary}"]
block_known_secrets = true
aad_kill_on_leak = true
blocked_patterns = ["CONFIDENTIAL-[0-9]{{4}}"]

[policy]
protected_paths = ["secrets/**"]
deny_on_dlp_secret = true

[[servers]]
name = "github"
preset = "github"
command = ["npx", "-y", "@modelcontextprotocol/server-github"]
tools_sha256 = "{pin}"
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg_path = root / "mellyn.toml"
            cfg_path.write_text(toml_text, encoding="utf-8")

            loaded = load_unified_config(cfg_path)
            self.assertEqual(loaded.schema_version, 2)
            self.assertEqual(loaded.runtime.mode, "enforce")
            self.assertEqual(loaded.runtime.state_db, (root / "state/mellyn.sqlite3").resolve())
            self.assertEqual(loaded.runtime.audit_log, (root / "logs/mellyn-audit.jsonl").resolve())
            self.assertTrue(loaded.auto_sync_squid)
            self.assertEqual(loaded.scanner.canary_tokens, (canary,))
            self.assertEqual(loaded.scanner.blocked_patterns, ("CONFIDENTIAL-[0-9]{4}",))
            self.assertEqual(loaded.policy.allowed_mcp_servers, frozenset({"github"}))
            self.assertEqual(loaded.policy.pinned_tool_hashes, {"github": pin})
            self.assertIn("api.github.com", loaded.policy.allowed_egress_domains)
            self.assertIn("api.custom-vendor.example", loaded.policy.allowed_egress_domains)
            self.assertIn("github/get_issue", loaded.policy.tool_risk_tiers)

    def test_fail_closed_rejections_and_dual_opt_in_observe(self) -> None:
        base = render_unified_config(["mcp-filesystem"], canary_tokens=(_synth_canary(),))
        bad_cases = [
            ("unknown_section", base + "\n[unknown_sec]\nx = 1\n"),
            ("bad_scanner_regex", base.replace("blocked_patterns = []", 'blocked_patterns = ["[bad("]')),
            ("observe_without_opt_in", base.replace('mode = "enforce"', 'mode = "observe"')),
            (
                "bad_pin_digest",
                base.replace('preset = "mcp-filesystem"', 'preset = "mcp-filesystem"\ntools_sha256 = "not-a-sha"'),
            ),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for label, content in bad_cases:
                with self.subTest(case=label):
                    bad_path = root / f"{label}.toml"
                    bad_path.write_text(content, encoding="utf-8")
                    with self.assertRaises(PolicyLoadError):
                        load_unified_config(bad_path)

            good_observe = base.replace('mode = "enforce"', 'mode = "observe"').replace(
                "allow_observe_mode = false", "allow_observe_mode = true"
            )
            obs_path = root / "observe.toml"
            obs_path.write_text(good_observe, encoding="utf-8")
            loaded = load_unified_config(obs_path)
            self.assertEqual(loaded.runtime.mode, "observe")
            self.assertTrue(loaded.runtime.allow_observe_mode)

    def test_auto_detect_and_egress_proxy_from_unified_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            res = init_workspace(root, presets=("github",), extra_domains=("custom.api.example",), unified=True)
            unified_path = res.mellyn_config_path
            if unified_path is None:
                self.fail("Expected unified mellyn.toml path")

            auto_v2 = load_mellyn_config(unified_path)
            self.assertEqual(auto_v2.schema_version, 2)
            pol = load_policy_any(unified_path)
            self.assertIn("api.github.com", pol.allowed_egress_domains)
            self.assertIn("custom.api.example", pol.allowed_egress_domains)

            squid_path = root / "squid.conf"
            with contextlib.redirect_stdout(io.StringIO()):
                rc_egress = egress_main(["--policy", str(unified_path), "--output", str(squid_path)])
            self.assertEqual(rc_egress, 0)
            squid_text = squid_path.read_text(encoding="utf-8")
            self.assertIn(".api.github.com", squid_text)
            self.assertIn(".custom.api.example", squid_text)

            # Verify v1 split files still auto-detect cleanly.
            v1_dir = root / "v1"
            v1_res = init_workspace(v1_dir, presets=("mcp-filesystem",), unified=False)
            if v1_res.gateway_path is None:
                self.fail("Expected v1 gateway_path")
            auto_v1 = load_mellyn_config(v1_res.gateway_path)
            self.assertEqual(auto_v1.schema_version, 1)

    def test_init_unified_cli_and_dry_run_up(self) -> None:
        canary = _synth_canary()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Reject --canary without --unified
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli_main(["init", "--dir", str(root), "--canary", canary]), 2)

            with contextlib.redirect_stdout(io.StringIO()):
                rc = cli_main(
                    [
                        "init",
                        "--unified",
                        "--dir",
                        str(root),
                        "--preset",
                        "mcp-filesystem",
                        "--preset",
                        "github",
                        "--canary",
                        canary,
                        "--quiet-keys",
                    ]
                )
            self.assertEqual(rc, 0)
            env_text = (root / ".env").read_text(encoding="utf-8")
            self.assertIn("MELLYN_POLICY_FILE=mellyn.toml", env_text)
            self.assertIn("MELLYN_GATEWAY_CONFIG_FILE=mellyn.toml", env_text)
            self.assertTrue((root / "config" / "mellyn.toml").is_file())
            self.assertFalse((root / "config" / "mellyn-policy.toml").exists())
            self.assertFalse((root / "config" / "mellyn-gateway.toml").exists())

            compose_path = root / "deploy" / "docker-compose.yml"
            compose_path.parent.mkdir(parents=True, exist_ok=True)
            compose_path.write_text("services: {}\n", encoding="utf-8")
            dry_rc, argv = run_up(
                compose_file=compose_path,
                squid_output=root / "deploy" / "egress" / "squid.conf",
                env_file=root / ".env",
                dry_run=True,
            )
            self.assertEqual(dry_rc, 0)
            self.assertIn("compose", argv)


class TestUnifiedGatewayContainmentAndObserve(unittest.TestCase):
    """Tests for gateway AAD containment, quarantine, dual-opt-in observe mode, and viewer verification."""

    def _build_gateway(
        self,
        tmp_dir: Path,
        *,
        servers: dict[str, _FakeDownstream],
        trusted: tuple[str, ...] = ("fs",),
        tool_risk_tiers: dict[str, RiskTier] | None = None,
        scanner: ScannerConfig | None = None,
        mode: str = "enforce",
        allow_observe_mode: bool = False,
        state_db: Path | None = None,
    ) -> tuple[MCPGateway, Path, Any, Any]:
        tiers = tool_risk_tiers or {}
        policy = PolicyConfig(
            allowed_mcp_servers=tuple(servers.keys()),
            trusted_mcp_servers=trusted,
            tool_risk_tiers=tiers,
            tool_capabilities={k: ToolCapability(pure=True) for k, tier in tiers.items() if tier != RiskTier.HIGH},
        )
        audit_path = tmp_dir / "gw-audit.jsonl"
        canary_tokens = scanner.canary_tokens if scanner is not None else ()
        audit_logger, audit_handle = AuditLogger.open_chained(
            audit_path, canary_tokens=canary_tokens, enforcement_mode=mode
        )
        state_store = SqliteStateStore(state_db) if state_db is not None else None
        try:
            authorizer = Authorizer(
                workspace_root=tmp_dir,
                policy_config=policy,
                audit_logger=audit_logger,
                session_ttl_seconds=None,
                state_store=state_store,
            )
            gw = MCPGateway(
                authorizer=authorizer,
                servers=servers,
                scanner_config=scanner,
                mode=mode,  # type: ignore[arg-type]
                allow_observe_mode=allow_observe_mode,
            )
        except Exception:
            if state_store is not None:
                state_store.close()
            audit_handle.close()
            raise
        return gw, audit_path, audit_handle, state_store

    def test_request_canary_aad_containment_and_quarantine(self) -> None:
        canary = _synth_canary()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            srv_tools = _FakeDownstream("fs", resources=[{"uri": "file:///workspace/a.txt", "name": "a"}])
            srv_res = _FakeDownstream(
                "docs",
                resources=[{"uri": f"https://docs.example/{canary}", "name": "trap"}],
            )
            scanner = ScannerConfig(canary_tokens=(canary,), block_known_secrets=True, aad_kill_on_leak=True)
            gw, audit_path, audit_handle, store = self._build_gateway(
                root,
                servers={"fs": srv_tools, "docs": srv_res},
                trusted=("fs", "docs"),
                tool_risk_tiers={"fs/echo": RiskTier.LOW},
                scanner=scanner,
                state_db=root / "state.sqlite3",
            )
            try:
                # 1) Canary in tools/call request arguments -> AAD kill + quarantine before downstream call
                reply = gw.handle_message(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": "fs__echo", "arguments": {"text": canary}},
                    }
                )
                if reply is None:
                    self.fail("Expected JSON-RPC reply for request canary")
                self.assertEqual(reply["error"]["code"], MELLYN_AAD_CONTAINED)
                self.assertTrue(srv_tools.killed)
                self.assertEqual(srv_tools.calls, [])
                self.assertIn("fs", gw._quarantined_servers)
                # Containment severs the whole session, as the Airlock does: every server is stopped.
                self.assertTrue(srv_res.killed)
                self.assertEqual(gw._quarantined_servers, {"fs", "docs"})

                # Subsequent clean call on quarantined server still fails closed with AAD code
                reply2 = gw.handle_message(
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": "fs__echo", "arguments": {"text": "benign"}},
                    }
                )
                if reply2 is None:
                    self.fail("Expected JSON-RPC reply on quarantined server")
                self.assertEqual(reply2["error"]["code"], MELLYN_AAD_CONTAINED)
                self.assertEqual(srv_tools.calls, [])

                # 2) The second server is unreachable too: listing and reading are refused without forwarding.
                listing = gw.handle_message({"jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": {}})
                self.assertEqual((listing or {}).get("error", {}).get("code"), MELLYN_AAD_CONTAINED)
                reply3 = gw.handle_message(
                    {
                        "jsonrpc": "2.0",
                        "id": 4,
                        "method": "resources/read",
                        "params": {"uri": f"https://docs.example/{canary}"},
                    }
                )
                if reply3 is None:
                    self.fail("Expected JSON-RPC reply for resources/read canary")
                self.assertEqual(reply3["error"]["code"], MELLYN_AAD_CONTAINED)
                self.assertTrue(srv_res.killed)
                self.assertEqual(srv_res.calls, [])
            finally:
                if store is not None:
                    store.close()
                audit_handle.close()

            raw_disk = audit_path.read_text(encoding="utf-8")
            self.assertNotIn(canary, raw_disk)
            self.assertTrue(verify_gateway_audit_file(audit_path).valid)
            events = [json.loads(line) for line in raw_disk.splitlines() if line.strip()]
            containment = [ev for ev in events if ev.get("event_type") == "containment"]
            # One trigger: once the session is severed, later calls are refused before they are even scanned.
            self.assertEqual(len(containment), 1)
            self.assertTrue(all(ev["decision"] == "aad_fire" for ev in containment))

    def test_response_canary_and_secret_interception(self) -> None:
        canary = _synth_canary()
        gh_cred = _synth_gh_cred()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            leaky_tool_srv = _FakeDownstream(
                "alpha",
                tool_result={"content": [{"type": "text", "text": f"Found secret {canary}"}]},
            )
            doc_uri = (root / "report.txt").as_uri()
            leaky_res_srv = _FakeDownstream(
                "beta",
                resources=[{"uri": doc_uri, "name": "report"}],
                resource_result={"contents": [{"uri": doc_uri, "text": canary}]},
            )
            cred_srv = _FakeDownstream(
                "gamma",
                tool_result={"content": [{"type": "text", "text": f"token={gh_cred}"}]},
            )
            scanner = ScannerConfig(canary_tokens=(canary,), block_known_secrets=True, aad_kill_on_leak=True)
            gw, audit_path, audit_handle, _ = self._build_gateway(
                root,
                servers={"alpha": leaky_tool_srv, "beta": leaky_res_srv, "gamma": cred_srv},
                trusted=("alpha", "beta", "gamma"),
                tool_risk_tiers={
                    "alpha/echo": RiskTier.LOW,
                    "beta/resources/read": RiskTier.LOW,
                    "gamma/echo": RiskTier.LOW,
                },
                scanner=scanner,
            )
            try:
                # 1) Response canary from tools/call triggers AAD before reaching agent
                r1 = gw.handle_message(
                    {
                        "jsonrpc": "2.0",
                        "id": 10,
                        "method": "tools/call",
                        "params": {"name": "alpha__echo", "arguments": {"text": "read"}},
                    }
                )
                if r1 is None:
                    self.fail("Expected JSON-RPC reply for response canary")
                self.assertEqual(r1["error"]["code"], MELLYN_AAD_CONTAINED)
                self.assertTrue(leaky_tool_srv.killed)
                self.assertEqual(len(leaky_tool_srv.calls), 1)

                # 2) Response canary from resources/read triggers AAD before reaching agent
                gw.handle_message({"jsonrpc": "2.0", "id": 11, "method": "resources/list", "params": {}})
                r2 = gw.handle_message(
                    {
                        "jsonrpc": "2.0",
                        "id": 12,
                        "method": "resources/read",
                        "params": {"uri": doc_uri},
                    }
                )
                if r2 is None:
                    self.fail("Expected JSON-RPC reply for resources/read response canary")
                self.assertEqual(r2["error"]["code"], MELLYN_AAD_CONTAINED)
                self.assertTrue(leaky_res_srv.killed)
            finally:
                audit_handle.close()

            # 3) Response synthetic secret (non-canary) blocks with POLICY_DENIED without AAD kill. A separate
            # gateway: the canary above already severed that session, so nothing there reaches gamma.
            secret_root = root / "secret-case"
            secret_root.mkdir()
            self.assertTrue(cred_srv.killed)  # stopped with the rest of the first session
            cred_srv = _FakeDownstream(
                "gamma",
                tool_result={"content": [{"type": "text", "text": f"token={gh_cred}"}]},
            )
            gw, audit_path_2, audit_handle, _ = self._build_gateway(
                secret_root,
                servers={"gamma": cred_srv},
                trusted=("gamma",),
                tool_risk_tiers={"gamma/echo": RiskTier.LOW},
                scanner=scanner,
            )
            try:
                r3 = gw.handle_message(
                    {
                        "jsonrpc": "2.0",
                        "id": 13,
                        "method": "tools/call",
                        "params": {"name": "gamma__echo", "arguments": {"text": "get cred"}},
                    }
                )
                if r3 is None:
                    self.fail("Expected JSON-RPC reply for secret interception")
                self.assertEqual(r3["error"]["code"], MELLYN_POLICY_DENIED)
                self.assertFalse(cred_srv.killed)
                self.assertNotIn("gamma", gw._quarantined_servers)
            finally:
                audit_handle.close()

            for ledger in (audit_path, audit_path_2):
                self.assertTrue(verify_gateway_audit_file(ledger).valid)
                raw_disk = ledger.read_text(encoding="utf-8")
                self.assertNotIn(canary, raw_disk)
                self.assertNotIn(gh_cred, raw_disk)

            def containment_decisions(ledger: Path) -> list[str]:
                return [
                    json.loads(line)["decision"]
                    for line in ledger.read_text(encoding="utf-8").splitlines()
                    if line.strip() and json.loads(line).get("event_type") == "containment"
                ]

            # First session: one AAD trigger; the resources/read after it is refused before it is scanned.
            self.assertEqual(containment_decisions(audit_path), ["aad_fire"])
            self.assertEqual(containment_decisions(audit_path_2), ["blocked_egress"])

    def test_dual_opt_in_observe_mode_logs_and_forwards_without_killing(self) -> None:
        canary = _synth_canary()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            srv = _FakeDownstream(
                "untrusted",
                tool_result={"content": [{"type": "text", "text": f"saw {canary}"}]},
            )
            scanner = ScannerConfig(canary_tokens=(canary,), block_known_secrets=True, aad_kill_on_leak=True)

            # Constructor refuses observe mode without allow_observe_mode=True.
            with self.assertRaises(ValueError):
                self._build_gateway(root, servers={"untrusted": srv}, scanner=scanner, mode="observe")

            # CLI refuses --mode observe when config sets allow_observe_mode = false.
            cfg_path = root / "mellyn.toml"
            cfg_path.write_text(render_unified_config(["mcp-filesystem"]), encoding="utf-8")
            err_buf = io.StringIO()
            with contextlib.redirect_stderr(err_buf):
                cli_rc = gateway_main(
                    [
                        "--config",
                        str(cfg_path),
                        "--workspace",
                        str(root),
                        "--audit-log",
                        str(root / "denied.jsonl"),
                        "--mode",
                        "observe",
                    ]
                )
            self.assertEqual(cli_rc, 2)
            self.assertIn("allow_observe_mode", err_buf.getvalue())

            # Dual opt-in: HIGH-risk call from untrusted server (normally denied/held) AND canary leak are
            # both logged with their real verdict under enforcement_mode="observe", forwarded without kill.
            gw, audit_path, audit_handle, _ = self._build_gateway(
                root,
                servers={"untrusted": srv},
                trusted=(),
                tool_risk_tiers={"untrusted/echo": RiskTier.HIGH},
                scanner=scanner,
                mode="observe",
                allow_observe_mode=True,
            )
            try:
                gw.authorizer.mark_tainted(gw.session_id, TaintSource(source_type="test_taint", origin="seed"))
                reply = gw.handle_message(
                    {
                        "jsonrpc": "2.0",
                        "id": 99,
                        "method": "tools/call",
                        "params": {"name": "untrusted__echo", "arguments": {"msg": "ok"}},
                    }
                )
                if reply is None:
                    self.fail("Expected JSON-RPC reply in observe mode")
                self.assertIn("result", reply)
                self.assertFalse(srv.killed)
                self.assertEqual(gw._quarantined_servers, set())
            finally:
                audit_handle.close()

            self.assertTrue(verify_gateway_audit_file(audit_path).valid)
            raw_disk = audit_path.read_text(encoding="utf-8")
            self.assertNotIn(canary, raw_disk)
            events = [json.loads(line) for line in raw_disk.splitlines() if line.strip()]
            self.assertTrue(all(ev["enforcement_mode"] == "observe" for ev in events))
            self.assertTrue(
                any(ev["event_type"] == "authorization" and ev["decision"] == "require_approval" for ev in events)
            )
            self.assertTrue(
                any(ev["event_type"] == "containment" and ev["decision"] == "observed_aad" for ev in events)
            )

    def test_gateway_audit_verifier_detects_valid_tampered_and_legacy_ledgers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            chained_path = root / "chained.jsonl"
            logger, handle = AuditLogger.open_chained(chained_path)
            try:
                logger.record_taint(session_id="ses_1", taint_count=1, taint_sources=("src:1",))
            finally:
                handle.close()

            valid_res = verify_gateway_audit_file(chained_path)
            self.assertTrue(valid_res.valid)
            self.assertIsNone(valid_res.reason)

            tampered_path = root / "tampered.jsonl"
            row = json.loads(chained_path.read_text(encoding="utf-8").strip())
            row["taint_count"] = 777
            tampered_path.write_text(json.dumps(row) + "\n", encoding="utf-8")
            tampered_res = verify_gateway_audit_file(tampered_path)
            self.assertFalse(tampered_res.valid)
            self.assertIsInstance(tampered_res.reason, str)

            legacy_path = root / "legacy.jsonl"
            legacy_path.write_text(json.dumps({"audit_id": "aud_legacy", "decision": "allow"}) + "\n", encoding="utf-8")
            legacy_res = verify_gateway_audit_file(legacy_path)
            self.assertFalse(legacy_res.valid)
            self.assertTrue(_is_legacy_unchained_log(legacy_path))


if __name__ == "__main__":
    unittest.main()
