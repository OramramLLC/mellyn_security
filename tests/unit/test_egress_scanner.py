"""Deterministic unit tests for `mellyn.egress.scanner` and `mellyn.egress.guards`."""

from __future__ import annotations

import base64
import tempfile
import unittest
from pathlib import Path

from mellyn.airlock.engine import evaluate_tool_call
from mellyn.airlock.models import AirlockPolicy, JsonRpcRequest
from mellyn.audit import redact_text as gateway_redact_text
from mellyn.core.normalize import JsonObject, sha256_exact
from mellyn.core.scan import KNOWN_SECRET_RULES, redact_core_secrets
from mellyn.egress.guards import EgressValidator, WorkspacePathGuard
from mellyn.egress.scanner import scan_payload, scan_text, shannon_entropy
from mellyn.scanner import ScannerConfig, scan_value


class TestEgressScanner(unittest.TestCase):
    def test_detects_plain_and_obfuscated_canary_tokens_without_raw_leakage(self) -> None:
        canary = "MELLYN_CANARY_TOKEN_4242"
        payloads: list[tuple[str, JsonObject]] = [
            ("plain", {"out": f"hello {canary} world"}),
            ("zero_width_split", {"out": "hello MELLYN_\u200bCANARY_\u200dTOKEN_4242"}),
            ("unicode_tag_split", {"out": "MELLYN_\U000e0043CANARY_\U000e0041TOKEN_4242"}),
            ("fullwidth_nfkc", {"out": "ＭＥＬＬＹＮ＿ＣＡＮＡＲＹ＿ＴＯＫＥＮ＿４２４２"}),
            ("canary_in_key", {"MELLYN_CANARY_TOKEN_4242": "val"}),
        ]
        for label, payload in payloads:
            with self.subTest(label=label):
                res = scan_payload(payload, canary_tokens=(canary,))
                self.assertFalse(res.clean)
                self.assertTrue(res.canary_matched)
                self.assertEqual(res.artifact_sha256, sha256_exact(payload))
                self.assertNotIn(canary, str(res.redacted_payload))
                self.assertNotIn(canary, str([f.model_dump() for f in res.findings]))
                self.assertTrue(any(f.kind == "canary" for f in res.findings))

    def test_detects_known_secrets_and_obfuscated_api_keys(self) -> None:
        samples = (
            "sk-proj-" + ("Z" * 24),
            "sk-ant-api03-" + ("A" * 20),
            "AIza" + ("B" * 35),
            "hf_" + ("C" * 30),
            "ghp_" + ("D" * 30),
            "AKIA" + ("1234ABCD" * 2),
            "https://alice:top_secret_pw_99@api.example.com/v1",
            "sk-\u200bproj-" + ("Q" * 24),
        )
        for secret in samples:
            with self.subTest(prefix=secret[:10]):
                res = scan_text(f"payload={secret}")
                self.assertFalse(res.clean)
                self.assertTrue(res.secret_matched)
                self.assertNotIn(secret, str(res.redacted_payload))
                self.assertIn("[REDACTED_SECRET]", str(res.redacted_payload))

    def test_detects_high_entropy_secrets_without_flagging_clean_text_or_hashes(self) -> None:
        high_ent = "token=" + "aZ9$kL2mP8qR4vW7xN3bY5cQ"
        self.assertGreaterEqual(shannon_entropy("aZ9$kL2mP8qR4vW7xN3bY5cQ"), 4.0)
        hit = scan_text(high_ent, entropy_threshold=4.0, min_entropy_length=20)
        self.assertFalse(hit.clean)
        self.assertTrue(hit.high_entropy_matched)
        self.assertNotIn("aZ9$kL2mP8qR4vW7xN3bY5cQ", str(hit.redacted_payload))
        self.assertIn("[REDACTED_HIGH_ENTROPY]", str(hit.redacted_payload))

        clean_samples = (
            "Summarize the quarterly architecture notes in docs/ARCHITECTURE.md.",
            "550e8400-e29b-41d4-a716-446655440000",  # UUID
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA-256 hex digest
        )
        for text in clean_samples:
            with self.subTest(text=text[:24]):
                res = scan_text(text)
                self.assertTrue(res.clean)
                self.assertEqual(res.findings, [])

    def test_detects_blocked_patterns_even_under_unicode_tags(self) -> None:
        obfuscated = "DO_\u200bNOT_EXFIL\U000e0041TRATE"
        res = scan_text(obfuscated, blocked_patterns=(r"DO_NOT_EXFILTRATE",))
        self.assertFalse(res.clean)
        self.assertTrue(res.blocked_pattern_matched)
        self.assertIn("[REDACTED_BLOCKED]", str(res.redacted_payload))
        self.assertTrue(any(f.kind == "blocked_pattern" for f in res.findings))

    def test_detects_encoded_reversed_and_interleaved_canaries_without_false_positives(self) -> None:
        canary = "MELLYN_CANARY_TOKEN_4242"
        raw = canary.encode("utf-8")
        hex_lower = raw.hex()
        variants: list[tuple[str, str]] = [
            ("hex_lower", hex_lower),
            ("hex_upper", hex_lower.upper()),
            ("hex_colon", ":".join(f"{b:02x}" for b in raw)),
            ("hex_hyphen", "-".join(f"{b:02X}" for b in raw)),
            ("b64_offset_0", base64.b64encode(raw).decode("ascii")),
            ("b64_offset_1", base64.b64encode(b"a" + raw + b"z").decode("ascii")),
            ("b64_offset_2", base64.b64encode(b"ab" + raw + b"yz").decode("ascii")),
            ("b64_urlsafe", base64.urlsafe_b64encode(b"x" + raw).decode("ascii")),
            ("b64_lowercase_canary", base64.b64encode(canary.lower().encode("utf-8")).decode("ascii")),
            ("b64_percent_canary", base64.b64encode(canary.replace("_", "%5F").encode("ascii")).decode("ascii")),
            ("reversed", canary[::-1]),
            ("double_percent", canary.replace("_", "%255F")),
            ("dot_interleaved", ".".join(canary)),
            ("hyphen_interleaved", "-".join(canary)),
        ]
        for label, sample in variants:
            with self.subTest(variant=label):
                res = scan_payload({"out": f"prefix {sample} suffix"}, canary_tokens=(canary,))
                self.assertFalse(res.clean, label)
                self.assertTrue(res.canary_matched, label)
                self.assertEqual(res.redacted_payload, {"out": "[REDACTED_CANARY]"})
                self.assertNotIn(sample, str(res.redacted_payload))
                self.assertNotIn(canary, str(res.redacted_payload))

        clean_controls = (
            "Summarize the quarterly architecture notes in docs/ARCHITECTURE.md for review.",
            "550e8400-e29b-41d4-a716-446655440000",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "https://docs.python.org/3/library/asyncio.html",
        )
        for text in clean_controls:
            with self.subTest(control=text[:24]):
                res = scan_payload({"msg": text}, canary_tokens=(canary,))
                self.assertTrue(res.clean)
                self.assertFalse(res.canary_matched)
                self.assertEqual(res.findings, [])

    def test_list_and_nested_dict_regex_rules(self) -> None:
        policy = AirlockPolicy(
            allowed_tools=["query"],
            tool_rules={
                "query": {
                    "name": "query",
                    "arg_regex_rules": {"tags": "^[a-z_]{2,12}$"},
                    "arg_deny_regex_rules": {"filters": r"(?i)\bDROP\b|--"},
                }
            },
        )
        ok_req = JsonRpcRequest(
            jsonrpc="2.0",
            id=1,
            method="tools/call",
            params={
                "name": "query",
                "arguments": {"tags": ["alpha", "beta_two"], "filters": {"where": ["safe_col", {"eq": "ok"}]}},
            },
        )
        self.assertTrue(evaluate_tool_call(ok_req, policy).verdict_allow)

        for bad_label, args in (
            ("empty_list", {"tags": []}),
            ("non_str_elem", {"tags": ["alpha", 123]}),
            ("non_nfkc_elem", {"tags": ["ａｌｐｈａ"]}),
            ("list_regex_mismatch", {"tags": ["alpha", "BAD!"]}),
            ("nested_list_deny", {"tags": ["alpha"], "filters": ["ok", "val -- comment"]}),
            ("nested_dict_deny_value", {"tags": ["alpha"], "filters": {"nested": {"stmt": "DROP TABLE"}}}),
            ("nested_dict_deny_key", {"tags": ["alpha"], "filters": {"nested": {"DROP": "x"}}}),
        ):
            with self.subTest(case=bad_label):
                bad_req = JsonRpcRequest(
                    jsonrpc="2.0",
                    id=2,
                    method="tools/call",
                    params={"name": "query", "arguments": args},
                )
                verdict = evaluate_tool_call(bad_req, policy)
                self.assertFalse(verdict.verdict_allow)
                self.assertEqual(verdict.rule_id, "airlock.arg_regex_violation")

    def test_shared_core_rules_depth_and_wrappers_stay_in_step(self) -> None:
        self.assertEqual(len(KNOWN_SECRET_RULES), 13)
        canary_a = "MELLYN_CANARY_" + "ALPHA_4242"
        canary_b = "MELLYN_CANARY_" + "BETA_7373"
        aws_key = "AKIA" + ("1234ABCD" * 2)
        gh_key = "gh" + "p_" + ("X" * 24)
        url_secret = "https://" + "alice:top_secret_pw_99@api.example.com/v1"
        pem_secret = (
            "-----BEGIN RSA "
            + "PRIVATE KEY-----\n"
            + ("MIIEowIBAAKCAQEAt0FakeTestBodyOnly1234567890\n" * 2)
            + "-----END RSA "
            + "PRIVATE KEY-----"
        )
        all_13_samples = (
            url_secret,
            "sk-" + "proj-" + ("Z" * 24),
            "sk-" + "ant-api03-" + ("A" * 20),
            "AIza" + ("B" * 35),
            "hf_" + ("C" * 30),
            "lsv2_pt_" + ("a" * 32) + "_" + ("b" * 10),
            gh_key,
            "github_pat_" + ("D" * 30),
            aws_key,
            "xoxb-" + ("1" * 24),
            "sk_live_" + ("Z" * 24),
            pem_secret,
            "Bearer " + ("Y" * 24),
        )
        gw_cfg = ScannerConfig(canary_tokens=(canary_a, canary_b))
        for sample in all_13_samples:
            with self.subTest(sample_prefix=sample[:12]):
                air = scan_payload({"v": sample}, canary_tokens=(canary_a, canary_b))
                gw = scan_value({"v": sample}, gw_cfg)
                self.assertTrue(air.secret_matched)
                self.assertTrue(gw.secret_matched)
                redacted = redact_core_secrets(f"x={sample}")
                self.assertIn("[REDACTED_SECRET]", redacted)
                self.assertEqual(gateway_redact_text(f"x={sample}"), redacted)

        # No early break: multiple secrets + multiple canaries all report findings in both wrappers.
        multi = {"secrets": f"{aws_key} {gh_key} {url_secret}", "canaries": f"{canary_a} {canary_b}"}
        air_multi = scan_payload(multi, canary_tokens=(canary_a, canary_b))
        gw_multi = scan_value(multi, gw_cfg)
        self.assertEqual(
            {f.rule_id for f in air_multi.findings if f.kind == "secret"},
            {"aws-access-key", "github-token", "url-userinfo-password"},
        )
        self.assertEqual(
            {f.rule_id for f in gw_multi.findings if f.kind == "secret"},
            {"aws-access-key", "github-token", "url-userinfo-password"},
        )
        self.assertEqual(
            {f.rule_id for f in air_multi.findings if f.kind == "canary"},
            {"canary-0", "canary-1"},
        )
        self.assertEqual(
            {f.rule_id for f in gw_multi.findings if f.kind == "canary"},
            {"canary-0", "canary-1"},
        )

        # Punctuation skeleton + deep nesting > 64 + canary at depth 70 both caught through both wrappers.
        skel = ";".join(canary_a.split("_"))
        self.assertTrue(scan_payload({"s": skel}, canary_tokens=(canary_a,)).canary_matched)
        self.assertTrue(scan_value({"s": skel}, gw_cfg).canary_matched)
        self.assertTrue(scan_value((canary_a[:8], "gap", canary_a[8:]), gw_cfg).canary_matched)

        deep_benign: JsonObject = {"leaf": "ok"}
        deep_canary: JsonObject = {"leaf": canary_a}
        for _ in range(70):
            deep_benign = {"n": deep_benign}
            deep_canary = {"n": deep_canary}
        air_deep = scan_payload(deep_benign, canary_tokens=(canary_a,))
        gw_deep = scan_value(deep_benign, gw_cfg)
        self.assertFalse(air_deep.clean)
        self.assertFalse(gw_deep.clean)
        self.assertIn("nesting-too-deep", {f.rule_id for f in air_deep.findings})
        self.assertIn("nesting-too-deep", {f.rule_id for f in gw_deep.findings})

        air_deep_c = scan_payload(deep_canary, canary_tokens=(canary_a,))
        gw_deep_c = scan_value(deep_canary, gw_cfg)
        self.assertTrue(air_deep_c.canary_matched)
        self.assertTrue(gw_deep_c.canary_matched)
        self.assertIn("nesting-too-deep", {f.rule_id for f in air_deep_c.findings})
        self.assertIn("nesting-too-deep", {f.rule_id for f in gw_deep_c.findings})

        # High entropy stays off for gateway default & ledger redaction, and matches when enabled.
        high_ent = "token=" + "aZ9$kL2mP8qR4vW7xN3bY5cQ"
        self.assertTrue(scan_value({"v": high_ent}, gw_cfg).clean)
        self.assertFalse(scan_value({"v": high_ent}, ScannerConfig(detect_high_entropy=True)).clean)
        self.assertEqual(redact_core_secrets(high_ent), high_ent)
        self.assertEqual(gateway_redact_text(high_ent), high_ent)


class TestMigratedEgressAndWorkspaceGuards(unittest.TestCase):
    def test_egress_validator_and_workspace_path_guard(self) -> None:
        ev = EgressValidator(frozenset({"docs.python.org"}))
        self.assertTrue(ev.validate_url("https://docs.python.org/3/")[0])
        self.assertTrue(ev.validate_url("https://api.docs.python.org/")[0])
        for bad_url in (
            "http://docs.python.org/",
            "https://169.254.169.254/latest/meta-data/",
            "https://localhost/admin",
            "https://user:pass@docs.python.org/",
            "https://evil-docs.python.org/",
        ):
            with self.subTest(bad_url=bad_url):
                self.assertFalse(ev.validate_url(bad_url)[0])

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "notes.txt").write_text("safe\n", encoding="utf-8")
            (ws / ".env").write_text("SECRET=1\n", encoding="utf-8")
            guard = WorkspacePathGuard(ws)
            self.assertTrue(guard.validate_path("notes.txt", is_write=False)[0])
            self.assertFalse(guard.validate_path("../../etc/passwd", is_write=False)[0])
            self.assertFalse(guard.validate_path(".env", is_write=False)[0])
            self.assertFalse(guard.validate_path(".git/hooks/pre-commit", is_write=True)[0])
            matches = guard.search_content("safe")
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0].path, "notes.txt")


if __name__ == "__main__":
    unittest.main()
