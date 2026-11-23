"""Deterministic unit tests for `mcp_airlock.core.audit` tamper-evident JSONL ledger."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mcp_airlock.core.audit import AuditLedger, verify_ledger
from mcp_airlock.core.normalize import JsonObject, sha256_exact
from mcp_airlock.core.schemas import GENESIS_PREV_HASH, ZoneEvent


def _make_event(
    seq_idx: int,
    *,
    reason: str = "permitted",
    metadata: JsonObject | None = None,
    tool_name: str = "read_note",
    verdict_allow: bool = True,
    severity: str = "ALLOW",
) -> ZoneEvent:
    sev_lit = "ALLOW" if verdict_allow else ("AAD_FIRE" if severity == "AAD_FIRE" else "BLOCK")
    return ZoneEvent(
        event_id=f"evt-{seq_idx}",
        timestamp_utc=f"2026-11-23T15:00:0{seq_idx}Z",
        zone="airlock",
        action="tools/call",
        verdict_allow=verdict_allow,
        severity=sev_lit,
        rule_id=f"rule-{seq_idx}",
        reason=reason,
        artifact_sha256="0" * 64,
        tool_name=tool_name,
        request_id=seq_idx,
        metadata=metadata or {},
    )


class TestAuditLedgerChainAndVerification(unittest.TestCase):
    def test_append_verify_and_resume_across_instances(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.jsonl"
            ledger = AuditLedger(log_path)
            self.assertEqual(verify_ledger(log_path).valid, False)  # non-existent file

            e0 = ledger.record(_make_event(0), raw_artifact={"step": 0})
            e1 = ledger.record(_make_event(1), raw_artifact={"step": 1})
            e2 = ledger.record(_make_event(2), raw_artifact={"step": 2})

            self.assertEqual(e0.seq, 0)
            self.assertEqual(e0.prev_hash, GENESIS_PREV_HASH)
            self.assertEqual(e1.seq, 1)
            self.assertEqual(e1.prev_hash, e0.entry_hash)
            self.assertEqual(e2.seq, 2)
            self.assertEqual(e2.prev_hash, e1.entry_hash)

            res = verify_ledger(log_path)
            self.assertTrue(res.valid)
            self.assertEqual(res.entry_count, 3)
            self.assertEqual(res.last_seq, 2)
            self.assertEqual(res.last_hash, e2.entry_hash)

            # Reopen ledger on existing file and append two more entries
            reopened = AuditLedger(log_path)
            e3 = reopened.record(_make_event(3), raw_artifact={"step": 3})
            e4 = reopened.record(_make_event(4), raw_artifact={"step": 4})
            self.assertEqual(e3.seq, 3)
            self.assertEqual(e3.prev_hash, e2.entry_hash)
            self.assertEqual(e4.seq, 4)

            res2 = verify_ledger(log_path)
            self.assertTrue(res2.valid)
            self.assertEqual(res2.entry_count, 5)
            self.assertEqual(res2.last_hash, e4.entry_hash)

    def test_mid_log_single_byte_tamper_deletion_reorder_and_injection_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base_path = Path(tmp) / "audit.jsonl"
            ledger = AuditLedger(base_path)
            for idx in range(5):
                ledger.record(_make_event(idx, reason=f"clean-event-{idx}"), raw_artifact={"idx": idx})

            orig_lines = base_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(orig_lines), 5)

            # 1. Flip a single character inside line 2 (`clean-event-2` -> `clean-evfnt-2`)
            tampered_byte = Path(tmp) / "tamper_byte.jsonl"
            mod_lines = list(orig_lines)
            self.assertIn("clean-event-2", mod_lines[2])
            mod_lines[2] = mod_lines[2].replace("clean-event-2", "clean-evfnt-2", 1)
            tampered_byte.write_text("\n".join(mod_lines) + "\n", encoding="utf-8", newline="\n")

            check_byte = verify_ledger(tampered_byte)
            self.assertFalse(check_byte.valid)
            self.assertEqual(check_byte.first_invalid_seq, 2)
            with self.assertRaises(ValueError):
                AuditLedger(tampered_byte)  # refuses to append to tampered ledger

            # 2. Mid-log invisible Unicode character injection on line 2
            tag_tampered = Path(tmp) / "tamper_tag.jsonl"
            tag_lines = list(orig_lines)
            tag_lines[2] = tag_lines[2].replace("clean-event-2", "clean\U000e0041-event-2", 1)
            tag_tampered.write_text("\n".join(tag_lines) + "\n", encoding="utf-8", newline="\n")
            check_tag = verify_ledger(tag_tampered)
            self.assertFalse(check_tag.valid)
            self.assertEqual(check_tag.first_invalid_seq, 2)

            # 3. Entry deletion (drop line 1 -> seq gap at index 1)
            deleted_line = Path(tmp) / "deleted.jsonl"
            deleted_line.write_text("\n".join([orig_lines[0], *orig_lines[2:]]) + "\n", encoding="utf-8", newline="\n")
            check_del = verify_ledger(deleted_line)
            self.assertFalse(check_del.valid)
            self.assertEqual(check_del.first_invalid_seq, 1)

            # 4. Extra JSON field appended to line 3
            extra_field = Path(tmp) / "extra.jsonl"
            extra_lines = list(orig_lines)
            row = json.loads(extra_lines[3])
            row["forged"] = True
            extra_lines[3] = json.dumps(row, sort_keys=True, separators=(",", ":"))
            extra_field.write_text("\n".join(extra_lines) + "\n", encoding="utf-8", newline="\n")
            check_extra = verify_ledger(extra_field)
            self.assertFalse(check_extra.valid)
            self.assertEqual(check_extra.first_invalid_seq, 3)

            # 5. Truncated trailing line without newline
            truncated = Path(tmp) / "truncated.jsonl"
            truncated.write_bytes(base_path.read_bytes()[:-1])
            self.assertFalse(verify_ledger(truncated).valid)


class TestRedactBeforeDisk(unittest.TestCase):
    def test_computes_raw_artifact_sha256_before_redacting_secrets_and_canaries(self) -> None:
        canary = "MEL_CANARY_9981_SECRET"
        tagged_canary = "MEL_\u200bCANARY_\U000e00419981_SECRET"
        fullwidth_canary = "ＭＥＬ＿ＣＡＮＡＲＹ＿９９８１＿ＳＥＣＲＥＴ"
        openai_secret = "sk-proj-" + ("A" * 24)
        aws_secret = "AKIA" + ("1234ABCD" * 2)
        bearer_token = "Bearer " + "super_sample_bearer_value_9911"

        raw_artifact: JsonObject = {
            "tool": "http_post",
            "payload": f"{canary} / {openai_secret} / {aws_secret} / {bearer_token}",
        }
        expected_raw_hash = sha256_exact(raw_artifact)

        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.jsonl"
            ledger = AuditLedger(log_path, canary_tokens=(canary,))

            event = _make_event(
                0,
                verdict_allow=False,
                severity="AAD_FIRE",
                reason=f"Blocked exfil {tagged_canary} & {openai_secret}",
                metadata={
                    "fullwidth": fullwidth_canary,
                    "aws": aws_secret,
                    "auth": bearer_token,
                },
            )
            entry = ledger.record(event, raw_artifact=raw_artifact)
            self.assertEqual(entry.event.artifact_sha256, expected_raw_hash)

            disk_text = log_path.read_text(encoding="utf-8")
            for raw_sensitive in (canary, openai_secret, aws_secret, "super_sample_bearer_value_9911"):
                self.assertNotIn(raw_sensitive, disk_text)
            self.assertIn("[REDACTED_CANARY]", disk_text)
            self.assertIn("[REDACTED_SECRET]", disk_text)
            self.assertTrue(verify_ledger(log_path).valid)


if __name__ == "__main__":
    unittest.main()
