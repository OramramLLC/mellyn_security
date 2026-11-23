"""Deterministic unit tests for `mcp_airlock.egress.scanner` and `mcp_airlock.egress.guards`."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_airlock.core.normalize import JsonObject, sha256_exact
from mcp_airlock.egress.guards import EgressValidator, WorkspacePathGuard
from mcp_airlock.egress.scanner import scan_payload, scan_text, shannon_entropy


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
