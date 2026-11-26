"""Regression tests for review fixes to the shared scanner core (Phase 2, Pass 2B).

- Invisible-character stripping is fast on non-ASCII text and removes exactly the same characters as before.
- The gateway's hidden-text check covers every `Cf` character, as the CHANGELOG now states.
- `mellyn-bench` reports large-payload latency, which the small accuracy corpus could not show.
- The rule IDs gateway audit reasons carry are pinned to the ones the CHANGELOG lists.
"""

from __future__ import annotations

import base64
import importlib.util
import sys
import time
import unicodedata
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from mellyn.core import normalize  # noqa: E402
from mellyn.scanner import ScannerConfig, invisible_unicode_tools, scan_value  # noqa: E402

HAS_PYDANTIC = importlib.util.find_spec("pydantic") is not None
ALL_CODEPOINTS = "".join(chr(cp) for cp in range(sys.maxunicode + 1) if not 0xD800 <= cp <= 0xDFFF)


def _reference_strip(text: str) -> str:
    """The per-character definition the fast path must match exactly."""
    return "".join(ch for ch in text if not normalize.is_invisible_codepoint(ch))


class TestInvisibleStrippingIsFastAndExact(unittest.TestCase):
    def test_strip_matches_the_per_character_definition_for_every_codepoint(self) -> None:
        self.assertEqual(normalize.strip_invisible(ALL_CODEPOINTS), _reference_strip(ALL_CODEPOINTS))

    def test_no_invisible_codepoint_lies_outside_the_scanned_planes(self) -> None:
        # The compiled class is built from these planes only; a Unicode update adding a Cf elsewhere must fail here.
        outside = [
            hex(cp)
            for cp in range(sys.maxunicode + 1)
            if not any(cp in span for span in normalize._INVISIBLE_SCAN_RANGES)
            and normalize.is_invisible_codepoint(chr(cp))
        ]
        self.assertEqual(outside, [], f"Unicode {unicodedata.unidata_version}")

    def test_has_invisible_unicode_agrees_with_the_definition(self) -> None:
        for cp in (0x00AD, 0x061C, 0x200D, 0xFE0F, 0xFEFF, 0xFFF9, 0x1D173, 0xE0041, 0xE0100, 0x3164):
            with self.subTest(cp=hex(cp)):
                self.assertTrue(normalize.has_invisible_unicode({"k": [f"a{chr(cp)}b"]}))
        self.assertFalse(normalize.has_invisible_unicode({"k": ["café 日本語 🙂"]}))

    def test_stripping_large_non_ascii_text_is_not_per_character_python(self) -> None:
        text = "Résumé café 日本語 🙂 naïve​ " * 160_000  # ~4.5 MB of UTF-8, with invisible characters
        normalize.strip_invisible("é")  # build the class outside the timed region
        start = time.perf_counter()
        stripped = normalize.strip_invisible(text)
        elapsed = time.perf_counter() - start
        self.assertNotIn("​", stripped)
        # The per-character check took 1-2 s on this input; the compiled class takes a few hundredths.
        self.assertLess(elapsed, 0.5)


class TestGatewayHiddenTextCoversEveryFormatCharacter(unittest.TestCase):
    def test_every_cf_character_blocks_a_listing(self) -> None:
        missed = [
            hex(cp)
            for cp in range(sys.maxunicode + 1)
            if unicodedata.category(chr(cp)) == "Cf"
            and not invisible_unicode_tools([{"name": "t", "description": "Reads" + chr(cp) + " a file."}])
        ]
        # Before 2B, 46 Cf characters (soft hyphen, U+FFF9-FFFB interlinear annotation, ...) passed.
        self.assertEqual(missed, [])


class TestGatewayRuleIds(unittest.TestCase):
    """Audit containment reasons carry `kind:rule_id`; these are the IDs the CHANGELOG documents."""

    def test_split_canaries_and_blocked_patterns_use_the_documented_ids(self) -> None:
        canary = "MELLYN-" + "canary-" + "Zq7Rk2Lm9Vx4"
        cfg = ScannerConfig(canary_tokens=(canary,), blocked_patterns=(r"DROP\s+TABLE",))
        split = scan_value([canary[:12], canary[12:]], cfg)
        self.assertIn(("canary", "canary-0", "$[split]"), {(f.kind, f.rule_id, f.field_path) for f in split.findings})
        self.assertNotIn("canary-0-split", {f.rule_id for f in split.findings})
        blocked = scan_value("please DROP TABLE users", cfg)
        self.assertEqual({(f.kind, f.rule_id) for f in blocked.findings}, {("blocked_pattern", "blocked-pattern-0")})


@unittest.skipUnless(HAS_PYDANTIC, "mellyn-bench needs pydantic")
class TestBenchReportsLargePayloadLatency(unittest.TestCase):
    def test_large_payloads_are_timed_and_reported(self) -> None:
        from mellyn.egress import bench

        payloads = bench.build_large_latency_payloads()
        self.assertEqual(len(payloads), 2)
        for payload in payloads:
            self.assertGreaterEqual(len(payload.encode("utf-8")), 100 * 1024)
        self.assertFalse(payloads[0].isascii())  # exercises the non-ASCII normalization path
        base64.b64decode(payloads[1].replace("\n", ""), validate=True)  # real MIME-style Base64

        report = bench.run_benchmark(iterations=1, surface="gateway")
        self.assertGreater(report.large_payload_us_per_kb, 0.0)
        self.assertIn("Large payloads", bench.render_benchmark_markdown(report))


if __name__ == "__main__":
    unittest.main()
