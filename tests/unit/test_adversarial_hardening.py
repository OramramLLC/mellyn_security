"""Regression unit tests for adversarial hardening (NTFS ADS paths, encoded/split canaries, encoded secrets)."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import re
import secrets
import sys
import tempfile
import time
import unicodedata
import unittest
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

if importlib.util.find_spec("pydantic") is None and os.environ.get("MELLYN_REQUIRE_API_TESTS") != "1":
    raise unittest.SkipTest("pydantic is not installed; adversarial hardening tests skipped")

from mellyn.airlock.engine import evaluate_tool_call  # noqa: E402
from mellyn.airlock.models import AirlockPolicy, JsonRpcRequest, ToolPolicyRule  # noqa: E402
from mellyn.core.audit import (  # noqa: E402
    AuditLedger,
    _split_fragments_cover_canary,
    canary_present,
    canary_present_in_json,
    redact_core_secrets,
    split_fragment_length,
)
from mellyn.core.normalize import is_invisible_codepoint, normalize_str  # noqa: E402
from mellyn.core.schemas import ZoneEvent  # noqa: E402
from mellyn.egress.guards import WorkspacePathGuard  # noqa: E402
from mellyn.egress.scanner import scan_payload, scan_text  # noqa: E402

CANARY = "MELLYN_CANARY_ALPHA_9472"
# Documentation-style sample credentials, assembled at runtime so no secret-shaped literal sits in the source.
SAMPLE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"
SAMPLE_AWS_PCT = SAMPLE_AWS[:4] + "%49" + SAMPLE_AWS[5:]
SAMPLE_OPENAI = "sk-" + "proj-" + "exampleDummy1234567890"


class TestNtfsAdsAndPathGuard(unittest.TestCase):
    def test_airlock_gateway_and_authorizer_share_one_path_and_url_guard(self) -> None:
        """
        The Airlock and the authorizer once had separate path guards, and this test compared them. Since the
        namespace merge there is one: a second copy appearing again (and drifting) must fail here.
        """
        import mellyn.authorizer
        import mellyn.egress
        import mellyn.egress.guards

        for name in ("WorkspacePathGuard", "EgressValidator", "check_workspace_root"):
            with self.subTest(name=name):
                self.assertIs(getattr(mellyn.egress, name), getattr(mellyn.egress.guards, name))
        self.assertIs(mellyn.authorizer.WorkspacePathGuard, mellyn.egress.guards.WorkspacePathGuard)
        self.assertIs(mellyn.authorizer.EgressValidator, mellyn.egress.guards.EgressValidator)
        defining = sorted(
            path.relative_to(REPO_ROOT).as_posix()
            for path in (REPO_ROOT / "src" / "mellyn").rglob("*.py")
            if re.search(r"^class (WorkspacePathGuard|EgressValidator)\b", path.read_text(encoding="utf-8"), re.M)
        )
        self.assertEqual(defining, ["src/mellyn/egress/guards.py"])

    def test_ads_and_trailing_dot_denied_while_benign_windows_paths_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp).resolve()
            (ws / "notes.txt").write_text("ok", encoding="utf-8")
            guard = WorkspacePathGuard(ws)
            pol = AirlockPolicy(
                allowed_tools=["read_file"],
                workspace_roots=[str(ws)],
                tool_rules={"read_file": ToolPolicyRule(name="read_file", allowed=True, path_arg_names=["path"])},
            )

            for bad_path in (".env::$DATA", "secret.key::$DATA", ".env:stream", ".env.", "sub/foo:bar/notes.txt"):
                with self.subTest(bad_path=bad_path):
                    self.assertFalse(guard.validate_path(bad_path, is_write=False)[0])
                    req = JsonRpcRequest(
                        jsonrpc="2.0",
                        id=1,
                        method="tools/call",
                        params={"name": "read_file", "arguments": {"path": bad_path}},
                    )
                    verdict = evaluate_tool_call(req, pol)
                    self.assertFalse(verdict.verdict_allow)

            for good_path in ("notes.txt", str(ws / "notes.txt")):
                with self.subTest(good_path=good_path):
                    self.assertTrue(guard.validate_path(good_path, is_write=False)[0])


class TestEncodedAndSplitCanaryHardening(unittest.TestCase):
    def test_encoded_chunked_reversed_base32_and_split_canaries_detected(self) -> None:
        raw = CANARY.encode("utf-8")
        b64 = base64.b64encode(raw).decode("ascii")
        hx = raw.hex()
        variants = {
            "newline_b64": "\n".join(b64[i : i + 8] for i in range(0, len(b64), 8)),
            "spaced_b64": " ".join(b64[i : i + 8] for i in range(0, len(b64), 8)),
            "pct_hex": f"{hx[:4]}%{ord(hx[4]):02X}{hx[5:]}",
            "pct_b64": f"{b64[:4]}%{ord(b64[4]):02X}{b64[5:]}",
            "ox_hex": " ".join(f"0x{b:02x}" for b in raw),
            "rev_hex": hx[::-1],
            "rev_b64": b64[::-1],
            "base32": base64.b32encode(raw).decode("ascii"),
        }
        for label, text in variants.items():
            with self.subTest(variant=label):
                self.assertTrue(canary_present(text, CANARY))
                res = scan_payload(text, canary_tokens=(CANARY,))
                self.assertTrue(res.canary_matched)
                self.assertFalse(res.clean)
                self.assertFalse(canary_present(json.dumps(res.redacted_payload), CANARY))

        half = len(CANARY) // 2
        split_cases = (
            [CANARY[:half], CANARY[half:]],
            {"p1": CANARY[:half], "p2": CANARY[half:]},
            {CANARY[:half]: CANARY[half:]},
        )
        for container in split_cases:
            self.assertTrue(canary_present_in_json(container, CANARY))
            res = scan_payload(container, canary_tokens=(CANARY,))
            self.assertTrue(res.canary_matched)
            self.assertEqual(res.redacted_payload, "[REDACTED_CANARY]")

    def test_short_token_does_not_split_match_benign_container(self) -> None:
        self.assertFalse(canary_present_in_json(["foo", "bar"], "foobar"))

    def test_audit_ledger_redacts_encoded_and_split_canaries_before_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            ledger = AuditLedger(path, canary_tokens=(CANARY,))
            b64 = base64.b64encode(CANARY.encode("utf-8")).decode("ascii")
            chunked_b64 = " ".join(b64[i : i + 8] for i in range(0, len(b64), 8))
            ox_hex = " ".join(f"0x{b:02x}" for b in CANARY.encode("utf-8"))
            half = len(CANARY) // 2
            ts = datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC).isoformat().replace("+00:00", "Z")

            ledger.record(
                ZoneEvent(
                    event_id="evt-1",
                    timestamp_utc=ts,
                    zone="egress",
                    action="tools/call",
                    verdict_allow=False,
                    severity="AAD_FIRE",
                    rule_id="egress.canary_exfiltration",
                    reason="encoded canary test",
                    artifact_sha256="a" * 64,
                    metadata={
                        "session_id": "s1",
                        "chunked": chunked_b64,
                        "ox": ox_hex,
                        "split": [CANARY[:half], CANARY[half:]],
                    },
                )
            )
            disk_text = path.read_text(encoding="utf-8")
            self.assertNotIn(CANARY, disk_text)
            self.assertNotIn(chunked_b64, disk_text)
            self.assertNotIn(ox_hex, disk_text)
            self.assertNotIn(CANARY[:half], disk_text)


class TestEncodedSecretDetectionAndZeroFalsePositives(unittest.TestCase):
    def test_percent_and_hex_secrets_caught_and_benign_inputs_clean(self) -> None:
        res_pct = scan_text(f"key={SAMPLE_AWS_PCT}")
        self.assertTrue(res_pct.secret_matched)
        self.assertFalse(res_pct.clean)
        self.assertNotIn(SAMPLE_AWS, str(res_pct.redacted_payload))

        for raw_secret in (SAMPLE_AWS, SAMPLE_OPENAI):
            hx = raw_secret.encode("utf-8").hex()
            res_hex = scan_text(hx)
            self.assertTrue(res_hex.secret_matched)
            self.assertFalse(res_hex.clean)
            self.assertEqual(res_hex.redacted_payload, "[REDACTED_SECRET]")

        sha256_digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        for benign in (
            sha256_digest,
            "550e8400-e29b-41d4-a716-446655440000",
            "normal documentation status text",
            "100% pass rate on local regression checks",
        ):
            with self.subTest(benign=benign):
                res = scan_text(benign, canary_tokens=(CANARY,))
                self.assertTrue(res.clean)

        benign_b64 = base64.b64encode(b"normal documentation status text").decode("ascii")
        res_b64 = scan_text(benign_b64, canary_tokens=(CANARY,))
        self.assertFalse(res_b64.secret_matched)
        self.assertFalse(res_b64.canary_matched)

    def test_large_benign_hex_and_base64_scan_stays_linear(self) -> None:
        large_hex = "abcd1234" * 12_500
        start = time.perf_counter()
        res = scan_text(large_hex, canary_tokens=(CANARY,))
        elapsed = time.perf_counter() - start
        self.assertTrue(res.clean)
        self.assertLess(elapsed, 2.0)


def _event(metadata: dict[str, Any], *, tool_name: str | None = None, event_id: str = "evt") -> ZoneEvent:
    return ZoneEvent(
        event_id=event_id,
        timestamp_utc="2026-11-24T12:00:00Z",
        zone="egress",
        action="tools/call",
        verdict_allow=False,
        severity="BLOCK",
        rule_id="egress.review_fix",
        reason="review fix probe",
        artifact_sha256="a" * 64,
        tool_name=tool_name,
        metadata=metadata,
    )


class TestSplitCanaryOrderAndGapTolerance(unittest.TestCase):
    def test_pieces_found_interleaved_reordered_padded_and_in_keys(self) -> None:
        third = len(CANARY) // 3
        a, b, c = CANARY[:third], CANARY[third : 2 * third], CANARY[2 * third :]
        cases: dict[str, Any] = {
            "interleaved": {"p1": a, "note": "unrelated", "p2": b, "n": 3, "p3": c},
            "reordered": [c, a, b],
            "padded": ["x" * 200_000, a, b, c],
            "keys_with_values_between": {a: 1, "k": 2, b: 3, c: 4},
            "nested": {"outer": [{"deep": [a]}, "filler"], "z": {"q": c, "r": b}},
        }
        for label, payload in cases.items():
            with self.subTest(case=label):
                self.assertTrue(canary_present_in_json(payload, CANARY))
                res = scan_payload(payload, canary_tokens=(CANARY,))
                self.assertTrue(res.canary_matched)
                self.assertEqual(res.redacted_payload, "[REDACTED_CANARY]")

    def test_random_canaries_not_found_in_large_unrelated_payloads(self) -> None:
        payloads = {
            "hex": [os.urandom(512).hex() for _ in range(512)],
            "base64": [base64.b64encode(os.urandom(768)).decode("ascii") for _ in range(512)],
        }
        makers = {"token_hex": lambda: secrets.token_hex(16), "token_urlsafe": lambda: secrets.token_urlsafe(16)}
        for label, payload in payloads.items():
            for kind, make in makers.items():
                for _ in range(10):
                    with self.subTest(payload=label, canary_kind=kind):
                        # The order-free check is the new false-positive risk, so it is tested directly.
                        self.assertFalse(_split_fragments_cover_canary(payload, make()))

    def test_order_free_check_needs_a_long_canary_and_long_enough_pieces(self) -> None:
        short = "ABCDEFGH12345"  # under 16 characters: only adjacent pieces count
        self.assertFalse(canary_present_in_json({"a": short[:6], "x": "gap", "b": short[6:]}, short))
        self.assertTrue(canary_present_in_json([short[:6], short[6:]], short))
        # Pieces shorter than the fragment length, scattered among other data, are a documented limit.
        self.assertEqual(split_fragment_length(CANARY), 5)
        self.assertEqual(split_fragment_length(secrets.token_hex(16)), 7)


class TestLedgerSplitRedactionCostAndScope(unittest.TestCase):
    def test_record_time_does_not_grow_with_nesting_depth(self) -> None:
        def nested(depth: int) -> Any:
            node: Any = "x" * 14_000
            for _ in range(depth):
                node = [node]
            return node

        with tempfile.TemporaryDirectory() as tmp:
            ledger = AuditLedger(Path(tmp) / "audit.jsonl", canary_tokens=(CANARY,))
            ledger.record(_event({"session_id": "s", "blob": nested(1)}, event_id="warm"))
            timings: dict[int, float] = {}
            for depth in (1, 90):
                start = time.perf_counter()
                ledger.record(_event({"session_id": "s", "blob": nested(depth)}, event_id=f"d{depth}"))
                timings[depth] = time.perf_counter() - start
        # Before the fix every nesting level rescanned its whole subtree (about 50x slower at this depth).
        self.assertLess(timings[90], timings[1] * 4 + 0.25, timings)

    def test_split_pieces_redacted_without_losing_unrelated_forensic_fields(self) -> None:
        half = len(CANARY) // 2
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            AuditLedger(path, canary_tokens=(CANARY,)).record(
                _event(
                    {
                        "session_id": "s1",
                        "trigger_event_id": "evt-123",
                        "args": {"a": CANARY[:half], "gap": "x", "b": CANARY[half:]},
                    }
                )
            )
            meta = json.loads(path.read_text(encoding="utf-8"))["event"]["metadata"]
        self.assertEqual(meta["args"], "[REDACTED_CANARY]")
        self.assertEqual(meta["trigger_event_id"], "evt-123")
        self.assertEqual(meta["session_id"], "s1")

    def test_split_between_tool_name_and_metadata_is_redacted_not_a_failed_write(self) -> None:
        third = len(CANARY) // 3
        a, b, c = CANARY[:third], CANARY[third : 2 * third], CANARY[2 * third :]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            # Without the peer-field step this raised "Audit redaction invariant violated" and nothing was written.
            AuditLedger(path, canary_tokens=(CANARY,)).record(
                _event({"session_id": "s1", "x": b, "y": "gap", "z": c}, tool_name=a)
            )
            disk = path.read_text(encoding="utf-8")
        for piece in (a, b, c):
            self.assertNotIn(piece, disk)


class TestTrailingDotOrSpaceSegments(unittest.TestCase):
    def test_absent_protected_files_cannot_be_created_with_a_trailing_dot_or_space(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp).resolve()
            guard = WorkspacePathGuard(ws)
            for target in (
                ".gitleaks.toml.",
                ".mellyn-allowlist.toml ",
                ".claude./settings.json",
                ".github./workflows/x.yml",
                "docs/notes.txt.",
            ):
                with self.subTest(denied=target):
                    self.assertFalse(guard.validate_path(target, is_write=True)[0])
            for target in ("notes.txt", "docs/guide.md", ".env.example"):
                with self.subTest(allowed=target):
                    self.assertTrue(guard.validate_path(target, is_write=True)[0])


class TestEscapedNestedAndEncodedSecrets(unittest.TestCase):
    def test_escaped_decimal_and_nested_canaries_detected(self) -> None:
        raw = CANARY.encode("utf-8")
        b64 = base64.b64encode(raw).decode("ascii")
        variants = {
            "x_escapes": "".join(f"\\x{b:02x}" for b in raw),
            "u_escapes": "".join(f"\\u{b:04x}" for b in raw),
            "u_brace_escapes": "".join(f"\\u{{{b:x}}}" for b in raw),
            "decimal": ", ".join(str(b) for b in raw),
            "double_b64": base64.b64encode(b64.encode("ascii")).decode("ascii"),
            "b64_of_hex": base64.b64encode(raw.hex().encode("ascii")).decode("ascii"),
        }
        for label, text in variants.items():
            with self.subTest(variant=label):
                self.assertTrue(canary_present(text, CANARY))
                self.assertTrue(scan_text(text, canary_tokens=(CANARY,)).canary_matched)

    def test_encoded_secrets_detected_and_redacted_in_scanner_and_ledger(self) -> None:
        raw = SAMPLE_AWS.encode("utf-8")
        variants = {
            "b64": base64.b64encode(raw).decode("ascii"),
            "b64url_offset": base64.urlsafe_b64encode(b"x=" + raw).decode("ascii"),
            "spaced_hex": " ".join(f"{b:02x}" for b in raw),
            "colon_hex": ":".join(f"{b:02X}" for b in raw),
            "0x_hex": ", ".join(f"0x{b:02x}" for b in raw),
            "decimal": ",".join(str(b) for b in raw),
            "u_escapes": "".join(f"\\u{b:04x}" for b in raw),
        }
        for label, text in variants.items():
            with self.subTest(variant=label):
                res = scan_text(f"cfg={text}")
                self.assertTrue(res.secret_matched)
                self.assertNotIn(text, str(res.redacted_payload))
                self.assertNotIn(text, redact_core_secrets(f"cfg={text}"))

    def test_ordinary_encoded_data_stays_clean(self) -> None:
        jwt_parts = (b'{"alg":"HS256","typ":"JWT"}', b'{"sub":"user-1","iat":1700000000}')
        benign = {
            "jwt_like": ".".join(base64.urlsafe_b64encode(p).decode("ascii").rstrip("=") for p in jwt_parts),
            "b64_prose": base64.b64encode(b"Quarterly report: revenue grew in every region." * 4).decode("ascii"),
            "number_list": ", ".join(str(n) for n in range(40)),
            "mac_addresses": " ".join(f"00:1a:2b:3c:4d:{n:02x}" for n in range(6)),
            "escaped_json_text": "line one\\nline two \\u00e9t\\u00e9",
        }
        for label, text in benign.items():
            with self.subTest(benign=label):
                res = scan_text(text, canary_tokens=(CANARY,))
                self.assertFalse(res.secret_matched)
                self.assertFalse(res.canary_matched)


class TestAsciiNormalizationFastPath(unittest.TestCase):
    def test_fast_path_matches_the_full_normalization_for_every_ascii_character(self) -> None:
        for code in range(128):
            ch = chr(code)
            self.assertFalse(is_invisible_codepoint(ch))
            self.assertEqual(unicodedata.normalize("NFKC", ch), ch)
            self.assertEqual(normalize_str(f"a{ch}b"), f"a{ch}b")
        self.assertEqual(normalize_str("x​yﬁ"), "xyfi")
