"""
Cryptographic ledger verifier for `audit.jsonl` inside `mcp_airlock.ir_lab`.

Strict DAG invariant: imports ONLY from `mcp_airlock.core` (+ stdlib / pydantic).
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from mcp_airlock.core.audit import LedgerAnchor, verify_ledger_bytes


class ChainVerificationReport(BaseModel):
    """Structured cryptographic verification report pinning invalid `seq` and 1-based line numbers."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    valid: bool
    ledger_path: str
    entry_count: int = Field(ge=0)
    last_seq: int | None = None
    last_hash: str | None = None
    first_invalid_seq: int | None = None
    first_invalid_line: int | None = None
    reason: str | None = None
    # False when no external anchor was supplied: entries deleted from the END of the ledger (or a ledger rewritten
    # from genesis) still verify as a valid chain, so a "valid" result does not rule those out.
    anchored: bool = False


def verify_chain_bytes(
    raw_bytes: bytes, *, ledger_path: str, anchor: LedgerAnchor | None = None
) -> ChainVerificationReport:
    """Verify ledger bytes already read into memory (see `verify_chain`)."""
    check = verify_ledger_bytes(raw_bytes, anchor=anchor)
    first_invalid_line = (
        check.first_invalid_seq + 1 if (not check.valid and check.first_invalid_seq is not None) else None
    )
    return ChainVerificationReport(
        valid=check.valid,
        ledger_path=ledger_path,
        entry_count=check.entry_count,
        last_seq=check.last_seq,
        last_hash=check.last_hash,
        first_invalid_seq=check.first_invalid_seq,
        first_invalid_line=first_invalid_line,
        reason=check.reason,
        anchored=anchor is not None,
    )


def read_and_verify_chain(
    path: Path, *, anchor: LedgerAnchor | None = None
) -> tuple[ChainVerificationReport, bytes | None]:
    """
    Read `path` ONCE and verify those bytes. Returns the report and the verified bytes (None if unreadable), so a
    caller that goes on to parse the ledger reports on exactly the content that was verified, even if the file is
    being appended to or edited at the same time.
    """
    if not path.is_file():
        return (
            ChainVerificationReport(
                valid=False,
                ledger_path=str(path),
                entry_count=0,
                first_invalid_seq=0,
                reason="Audit ledger does not exist.",
                anchored=anchor is not None,
            ),
            None,
        )
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        return (
            ChainVerificationReport(
                valid=False,
                ledger_path=str(path),
                entry_count=0,
                first_invalid_seq=0,
                reason=f"Could not read audit ledger: {exc}",
                anchored=anchor is not None,
            ),
            None,
        )
    return verify_chain_bytes(raw_bytes, ledger_path=str(path), anchor=anchor), raw_bytes


def verify_chain(path: Path, *, anchor: LedgerAnchor | None = None) -> ChainVerificationReport:
    """
    Verify an `audit.jsonl` ledger from genesis (`seq == 0`, `prev_hash == "0" * 64`) using `core.audit`.

    Returns a strict `ChainVerificationReport` pinpointing both `first_invalid_seq` and 1-based `first_invalid_line`
    on tamper or truncation.
    """
    report, _ = read_and_verify_chain(path, anchor=anchor)
    return report


__all__ = ["ChainVerificationReport", "read_and_verify_chain", "verify_chain", "verify_chain_bytes"]
