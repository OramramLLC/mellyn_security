"""
Cryptographic ledger verifier for `audit.jsonl` inside `mellyn.ir_lab`.

Strict DAG invariant: imports ONLY from `mellyn.core` (+ stdlib / pydantic).
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from mellyn.core.audit import LedgerAnchor, is_link_or_junction, read_regular_file_nofollow, verify_ledger_bytes_core
from mellyn.core.schemas import LedgerFormat


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
    ledger_format: LedgerFormat | None = None


def verify_chain_bytes(
    raw_bytes: bytes, *, ledger_path: str, anchor: LedgerAnchor | None = None
) -> ChainVerificationReport:
    """Verify ledger bytes already read into memory (via the unified `mellyn.core.audit` verifier)."""
    check = verify_ledger_bytes_core(raw_bytes, anchor=anchor)
    first_invalid_line = (
        check.first_invalid_line
        if check.first_invalid_line is not None
        else (check.first_invalid_seq + 1 if (not check.valid and check.first_invalid_seq is not None) else None)
    )
    fmt: LedgerFormat | None = (
        check.ledger_format
        if check.ledger_format
        in {  # type: ignore[assignment]
            "empty",
            "v2",
            "v1_airlock",
            "v1_gateway",
            "pre_chain",
        }
        else None
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
        ledger_format=fmt,
    )


def read_and_verify_chain(
    path: Path, *, anchor: LedgerAnchor | None = None
) -> tuple[ChainVerificationReport, bytes | None]:
    """
    Read `path` ONCE via `O_NOFOLLOW` and verify those bytes. Refuses symlink/junction ledger paths
    fail-closed and returns the report plus exact verified bytes.
    """
    if is_link_or_junction(path) or is_link_or_junction(path.parent):
        return (
            ChainVerificationReport(
                valid=False,
                ledger_path=str(path),
                entry_count=0,
                first_invalid_seq=0,
                first_invalid_line=1,
                reason=f"Refusing symlink audit ledger path '{path}'.",
                anchored=anchor is not None,
            ),
            None,
        )
    if not path.is_file():
        return (
            ChainVerificationReport(
                valid=False,
                ledger_path=str(path),
                entry_count=0,
                first_invalid_seq=0,
                first_invalid_line=1,
                reason="Audit ledger does not exist.",
                anchored=anchor is not None,
            ),
            None,
        )
    try:
        raw_bytes = read_regular_file_nofollow(path)
    except OSError as exc:
        return (
            ChainVerificationReport(
                valid=False,
                ledger_path=str(path),
                entry_count=0,
                first_invalid_seq=0,
                first_invalid_line=1,
                reason=f"Could not read audit ledger: {exc}",
                anchored=anchor is not None,
            ),
            None,
        )
    return verify_chain_bytes(raw_bytes, ledger_path=str(path), anchor=anchor), raw_bytes


def verify_chain(path: Path, *, anchor: LedgerAnchor | None = None) -> ChainVerificationReport:
    """Verify an `audit.jsonl` ledger from genesis (`v2`, `v1_airlock`, `v1_gateway`) via `core.audit`."""
    report, _ = read_and_verify_chain(path, anchor=anchor)
    return report


__all__ = ["ChainVerificationReport", "read_and_verify_chain", "verify_chain", "verify_chain_bytes"]
