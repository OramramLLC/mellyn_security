"""
Tamper-evident append-only JSONL flight recorder and standalone ledger verifier.

Invariants enforced (per AGENTS.md):
  - Redact Before Disk: compute `artifact_sha256` from the unredacted artifact first,
    redact all secret patterns and planted canary tokens in `ZoneEvent`, assert no
    canary survives, then hash-chain and flush + fsync.
  - Canonical Hashing: `entry_hash` is computed over canonicalized `{seq, prev_hash, event}`.
  - Strict DAG: `core.audit` imports nothing from `egress`, `airlock`, or `ir_lab`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import cast

from pydantic import ValidationError

from mellyn.core.normalize import (
    JsonObject,
    JsonValue,
    canonical_json_bytes,
    has_invisible_unicode,
    normalize_str,
    sha256_canonical,
    sha256_exact,
)
from mellyn.core.scan import (
    SPLIT_COVERAGE_MIN_CANARY_CHARS as SPLIT_COVERAGE_MIN_CANARY_CHARS,
)
from mellyn.core.scan import (
    _iter_json_strings as _iter_json_strings,
)
from mellyn.core.scan import (
    _split_fragments_cover_canary as _split_fragments_cover_canary,
)
from mellyn.core.scan import (
    canary_present as canary_present,
)
from mellyn.core.scan import (
    canary_present_in_json as canary_present_in_json,
)
from mellyn.core.scan import (
    extract_split_canary_views as extract_split_canary_views,
)
from mellyn.core.scan import (
    redact_canary_in_text as redact_canary_in_text,
)
from mellyn.core.scan import (
    redact_core_secrets as redact_core_secrets,
)
from mellyn.core.scan import (
    redact_encoded_secret_tokens as redact_encoded_secret_tokens,
)
from mellyn.core.scan import (
    split_fragment_length as split_fragment_length,
)
from mellyn.core.scan import (
    unescape_text as unescape_text,
)
from mellyn.core.schemas import (
    GENESIS_PREV_HASH,
    AuditLedgerEntry,
    LedgerVerification,
    ZoneEvent,
)


def _redact_dict(
    value: JsonObject,
    *,
    canary_tokens: tuple[str, ...],
    extra_redactor: Callable[[str], str] | None,
) -> JsonObject:
    redacted_dict: dict[str, JsonValue] = {}
    for k, v in value.items():
        safe_k = redact_core_secrets(k, canary_tokens=canary_tokens, extra_redactor=extra_redactor)
        safe_v = _redact_json_value(v, canary_tokens=canary_tokens, extra_redactor=extra_redactor)
        redacted_dict[safe_k] = safe_v
    return redacted_dict


def _redact_json_value(
    value: JsonValue,
    *,
    canary_tokens: tuple[str, ...],
    extra_redactor: Callable[[str], str] | None,
) -> JsonValue:
    if isinstance(value, str):
        return redact_core_secrets(value, canary_tokens=canary_tokens, extra_redactor=extra_redactor)
    # Split canaries are handled once per event in `_redact_split_canaries`; checking here, at every nesting level,
    # rescanned each subtree once per level of depth.
    if isinstance(value, list):
        return [_redact_json_value(item, canary_tokens=canary_tokens, extra_redactor=extra_redactor) for item in value]
    if isinstance(value, dict):
        return _redact_dict(value, canary_tokens=canary_tokens, extra_redactor=extra_redactor)
    return value


def _split_canary_in(value: JsonValue, canary_tokens: tuple[str, ...]) -> bool:
    return any(canary_present_in_json(value, canary) for canary in canary_tokens)


def _carries_canary_piece(value: JsonValue, canary_tokens: tuple[str, ...]) -> bool:
    """True when some string in `value` holds a canary fragment the split check counts, or a split of its own."""
    if isinstance(value, list | dict) and _split_canary_in(value, canary_tokens):
        return True
    for canary in canary_tokens:
        norm = normalize_str(canary)
        if len(norm) < 8:
            continue
        folded = norm.casefold()
        k = min(split_fragment_length(norm), len(folded))
        windows = {folded[i : i + k] for i in range(len(folded) - k + 1)}
        if any(any(w in normalize_str(s).casefold() for w in windows) for s in _iter_json_strings(value)):
            return True
    return False


def _sanitize_event(
    event: ZoneEvent,
    *,
    artifact_sha256: str,
    canary_tokens: tuple[str, ...],
    extra_redactor: Callable[[str], str] | None,
) -> ZoneEvent:
    safe_meta = _redact_dict(event.metadata, canary_tokens=canary_tokens, extra_redactor=extra_redactor)
    safe_req_id: int | str | None = (
        redact_core_secrets(event.request_id, canary_tokens=canary_tokens, extra_redactor=extra_redactor)
        if isinstance(event.request_id, str)
        else event.request_id
    )
    safe_tool = (
        redact_core_secrets(event.tool_name, canary_tokens=canary_tokens, extra_redactor=extra_redactor)
        if event.tool_name is not None
        else None
    )
    safe_action = redact_core_secrets(event.action, canary_tokens=canary_tokens, extra_redactor=extra_redactor)
    safe_reason = redact_core_secrets(event.reason, canary_tokens=canary_tokens, extra_redactor=extra_redactor)

    # Split canaries: one scan over metadata plus the top-level fields a peer can influence (the JSON-RPC method,
    # tool name, string request id, and reason text). Only on a hit is metadata narrowed, then those fields
    # redacted, then metadata dropped, so the on-disk invariant in `record()` only fires for something this missed.
    def _peer_view() -> JsonObject:
        view: JsonObject = {"action": safe_action, "reason": safe_reason, "metadata": safe_meta}
        if safe_tool is not None:
            view["tool_name"] = safe_tool
        if isinstance(safe_req_id, str):
            view["request_id"] = safe_req_id
        return view

    if canary_tokens and _split_canary_in(_peer_view(), canary_tokens):
        # Redact every field holding a piece, not just enough to stop the check firing: removing one piece would
        # otherwise leave the rest of the canary on disk. Unrelated fields (e.g. `trigger_event_id`) survive.
        def _scrub(text: str) -> str:
            return "[REDACTED_CANARY]" if _carries_canary_piece(text, canary_tokens) else text

        safe_meta = {
            k: ("[REDACTED_CANARY]" if _carries_canary_piece(v, canary_tokens) else v) for k, v in safe_meta.items()
        }
        safe_action, safe_reason = _scrub(safe_action), _scrub(safe_reason)
        safe_tool = _scrub(safe_tool) if safe_tool is not None else None
        safe_req_id = _scrub(safe_req_id) if isinstance(safe_req_id, str) else safe_req_id
        if _split_canary_in(_peer_view(), canary_tokens):
            # Pieces too small to count as fragments, sitting side by side: drop everything a peer could shape.
            safe_action = safe_reason = "[REDACTED_CANARY]"
            safe_tool = "[REDACTED_CANARY]" if safe_tool is not None else None
            safe_req_id = "[REDACTED_CANARY]" if isinstance(safe_req_id, str) else safe_req_id
            sid = safe_meta.get("session_id")
            keep_sid = isinstance(sid, str) and not any(canary_present(sid, c) for c in canary_tokens)
            safe_meta = (
                {"session_id": sid, "redacted": "[REDACTED_CANARY]"} if keep_sid else {"redacted": "[REDACTED_CANARY]"}
            )

    return ZoneEvent(
        event_id=redact_core_secrets(event.event_id, canary_tokens=canary_tokens, extra_redactor=extra_redactor),
        timestamp_utc=event.timestamp_utc,
        zone=event.zone,
        action=safe_action,
        verdict_allow=event.verdict_allow,
        severity=event.severity,
        rule_id=redact_core_secrets(event.rule_id, canary_tokens=canary_tokens, extra_redactor=extra_redactor),
        reason=safe_reason,
        artifact_sha256=artifact_sha256,
        tool_name=safe_tool,
        request_id=safe_req_id,
        redactions=event.redactions,
        metadata=safe_meta,
    )


def _entry_chain_payload(seq: int, prev_hash: str, event: ZoneEvent) -> JsonObject:
    raw_dump = cast(JsonObject, event.model_dump(mode="json"))
    return {
        "seq": seq,
        "prev_hash": prev_hash,
        "event": raw_dump,
    }


type LedgerAnchor = tuple[int, str]
"""`(seq, entry_hash)` of an entry recorded OUTSIDE the ledger file (e.g. shipped to a log server)."""


def verify_ledger(path: Path, *, anchor: LedgerAnchor | None = None) -> LedgerVerification:
    """
    Verify an append-only hash-chained `audit.jsonl` ledger from genesis (`seq == 0`) to tail.

    Checks:
      - Strictly contiguous sequence numbers (`0, 1, 2, ...`).
      - Valid `AuditLedgerEntry` strict schemas (no extra keys or type coercion).
      - Genesis `prev_hash == "0" * 64` and `entry.prev_hash == prev.entry_hash` thereafter.
      - Exact `entry_hash == sha256_canonical({seq, prev_hash, event})` and canonical disk encoding.
      - With `anchor`: the entry at `anchor[0]` exists and has hash `anchor[1]`.

    The chain alone cannot detect entries deleted from the END, or a whole ledger rewritten from genesis: both
    still form a valid chain. Only an anchor kept outside the file (the last `(last_seq, last_hash)` you saw)
    detects those.
    """
    if anchor is not None and (anchor[0] < 0 or not re.fullmatch(r"[0-9a-f]{64}", anchor[1])):
        return LedgerVerification(valid=False, entry_count=0, first_invalid_seq=0, reason="Ledger anchor is malformed.")

    if not path.is_file():
        return LedgerVerification(
            valid=False,
            entry_count=0,
            first_invalid_seq=0,
            reason="Audit ledger does not exist.",
        )

    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        return LedgerVerification(
            valid=False, entry_count=0, first_invalid_seq=0, reason=f"Could not read audit ledger: {exc}"
        )
    return verify_ledger_bytes(raw_bytes, anchor=anchor)


def verify_ledger_bytes(raw_bytes: bytes, *, anchor: LedgerAnchor | None = None) -> LedgerVerification:
    """
    Verify ledger content already read into memory (same checks as `verify_ledger`). Use this when the caller goes
    on to parse the content, so what it reports on is exactly what was verified (no second read of a live file).
    """
    if anchor is not None and (anchor[0] < 0 or not re.fullmatch(r"[0-9a-f]{64}", anchor[1])):
        return LedgerVerification(valid=False, entry_count=0, first_invalid_seq=0, reason="Ledger anchor is malformed.")

    if not raw_bytes:
        if anchor is not None:
            return LedgerVerification(
                valid=False,
                entry_count=0,
                first_invalid_seq=0,
                reason=f"Audit ledger is empty but anchor expects seq {anchor[0]} (truncated).",
            )
        return LedgerVerification(valid=True, entry_count=0, last_seq=None, last_hash=None)

    lines = raw_bytes.split(b"\n")
    if lines and lines[-1] == b"":
        lines = lines[:-1]
    elif raw_bytes and not raw_bytes.endswith(b"\n"):
        return LedgerVerification(
            valid=False,
            entry_count=0,
            first_invalid_seq=0,
            reason="Audit ledger is truncated (missing trailing newline).",
        )

    expected_prev = GENESIS_PREV_HASH
    last_hash: str | None = None
    count = 0

    for expected_seq, line_bytes in enumerate(lines):
        if not line_bytes:
            return LedgerVerification(
                valid=False,
                entry_count=count,
                first_invalid_seq=expected_seq,
                reason=f"Blank line encountered at seq {expected_seq}.",
            )
        try:
            decoded_text = line_bytes.decode("utf-8")
            parsed_obj = json.loads(decoded_text)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return LedgerVerification(
                valid=False,
                entry_count=count,
                first_invalid_seq=expected_seq,
                reason=f"Malformed JSON at seq {expected_seq}: {exc}",
            )

        if not isinstance(parsed_obj, dict) or has_invisible_unicode(parsed_obj):
            return LedgerVerification(
                valid=False,
                entry_count=count,
                first_invalid_seq=expected_seq,
                reason=f"Invalid entry structure or invisible Unicode detected at seq {expected_seq}.",
            )

        try:
            entry = AuditLedgerEntry.model_validate(parsed_obj)
        except ValidationError as exc:
            return LedgerVerification(
                valid=False,
                entry_count=count,
                first_invalid_seq=expected_seq,
                reason=f"Schema validation failed at seq {expected_seq}: {exc.error_count()} error(s).",
            )

        if entry.seq != expected_seq:
            return LedgerVerification(
                valid=False,
                entry_count=count,
                first_invalid_seq=expected_seq,
                reason=f"Sequence mismatch at index {expected_seq}: found seq {entry.seq}.",
            )

        if entry.prev_hash != expected_prev:
            return LedgerVerification(
                valid=False,
                entry_count=count,
                first_invalid_seq=expected_seq,
                reason=f"Hash chain break at seq {expected_seq}: prev_hash does not match prior entry_hash.",
            )

        expected_entry_hash = sha256_canonical(_entry_chain_payload(entry.seq, entry.prev_hash, entry.event))
        if entry.entry_hash != expected_entry_hash:
            return LedgerVerification(
                valid=False,
                entry_count=count,
                first_invalid_seq=expected_seq,
                reason=f"Tampered entry content at seq {expected_seq}: entry_hash mismatch.",
            )

        canonical_disk_line = canonical_json_bytes(cast(JsonObject, entry.model_dump(mode="json")))
        if line_bytes != canonical_disk_line:
            return LedgerVerification(
                valid=False,
                entry_count=count,
                first_invalid_seq=expected_seq,
                reason=f"Non-canonical encoding / mid-log byte tampering at seq {expected_seq}.",
            )

        if anchor is not None and entry.seq == anchor[0] and entry.entry_hash != anchor[1]:
            return LedgerVerification(
                valid=False,
                entry_count=count,
                first_invalid_seq=expected_seq,
                reason=f"Entry at anchored seq {expected_seq} does not match the anchor hash (ledger rewritten).",
            )

        expected_prev = entry.entry_hash
        last_hash = entry.entry_hash
        count += 1

    if anchor is not None and count <= anchor[0]:
        return LedgerVerification(
            valid=False,
            entry_count=count,
            first_invalid_seq=count,
            reason=f"Audit ledger ends at {count} entries but anchor expects seq {anchor[0]} (truncated).",
        )

    return LedgerVerification(
        valid=True,
        entry_count=count,
        last_seq=count - 1,
        last_hash=last_hash,
    )


@contextmanager
def _exclusive_lock(lock_path: Path) -> Iterator[None]:
    """Hold an exclusive OS lock on `lock_path` (a sidecar file) so concurrent writers cannot fork the chain."""
    with lock_path.open("a+b") as fh:
        if sys.platform == "win32":
            import msvcrt

            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)  # retries ~10s, then raises OSError (fail closed)
            try:
                yield
            finally:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


class AuditLedger:
    """
    Append-only, redacted, hash-chained JSONL ledger (`audit.jsonl`).

    Verifies existing ledger integrity on open (fail-closed) and resumes chaining from the last verified entry.
    Appends hold an exclusive lock on `<ledger>.lock`. Before each append the writer checks, in constant time, that
    the file size and the last line it wrote are unchanged; if not (another writer appended, or the file was
    truncated or edited near the tail), the whole ledger is re-verified, including that our own last entry is still
    present, before chaining onto the new tail. A same-size edit to an OLDER entry is not re-checked on every write
    (that would mean hashing the whole file each time); it is caught by `verify_ledger`, on the next open, or by an
    external anchor.

    Pass `anchor` (a `(seq, entry_hash)` stored outside the file, e.g. the `head` from the previous run) to detect
    tail truncation or a full rewrite, which the hash chain alone cannot see.
    """

    def __init__(
        self,
        path: Path,
        *,
        canary_tokens: tuple[str, ...] = (),
        redactor: Callable[[str], str] | None = None,
        anchor: LedgerAnchor | None = None,
    ) -> None:
        self.path = path
        self.canary_tokens = tuple(t for t in canary_tokens if t)
        self._extra_redactor = redactor
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_path = self.path.with_name(self.path.name + ".lock")
        self._next_seq = 0
        self._prev_hash = GENESIS_PREV_HASH
        self._known_size = 0
        self._known_tail = b""

        with _exclusive_lock(self._lock_path):
            raw = self.path.read_bytes() if self.path.exists() else b""
            if raw or anchor is not None:
                self._adopt_verified_tail(anchor=anchor)
            self._known_size = len(raw)
            self._known_tail = raw[raw.rfind(b"\n", 0, len(raw) - 1) + 1 :] if raw else b""

    def _file_unchanged_since_last_write(self) -> bool:
        """Constant-time check: same size, and the last line we know of is still at the end of the file."""
        size = self.path.stat().st_size if self.path.exists() else 0
        if size != self._known_size:
            return False
        if not self._known_tail:
            return True
        with self.path.open("rb") as fh:
            fh.seek(size - len(self._known_tail))
            return fh.read(len(self._known_tail)) == self._known_tail

    @property
    def next_seq(self) -> int:
        return self._next_seq

    @property
    def prev_hash(self) -> str:
        return self._prev_hash

    @property
    def head(self) -> LedgerAnchor | None:
        """`(seq, entry_hash)` of the last entry this instance knows of; persist it outside the file as an anchor."""
        return None if self._next_seq == 0 else (self._next_seq - 1, self._prev_hash)

    def _adopt_verified_tail(self, *, anchor: LedgerAnchor | None) -> None:
        check = verify_ledger(self.path, anchor=anchor)
        if not check.valid:
            raise ValueError(f"Refusing to append to tampered audit ledger '{self.path}': {check.reason}")
        self._next_seq = check.entry_count
        self._prev_hash = check.last_hash if check.last_hash is not None else GENESIS_PREV_HASH

    def record(
        self,
        event: ZoneEvent,
        *,
        raw_artifact: JsonValue | bytes | None = None,
    ) -> AuditLedgerEntry:
        """
        Compute `artifact_sha256` from `raw_artifact` (if supplied), redact all secrets and
        canaries in `event`, hash-chain, verify zero canary leakage, append to disk, and flush+fsync.
        """
        if raw_artifact is None:
            computed_artifact_sha = event.artifact_sha256
        elif isinstance(raw_artifact, bytes):
            computed_artifact_sha = hashlib.sha256(raw_artifact).hexdigest()
        else:
            computed_artifact_sha = sha256_exact(raw_artifact)

        safe_event = _sanitize_event(
            event,
            artifact_sha256=computed_artifact_sha,
            canary_tokens=self.canary_tokens,
            extra_redactor=self._extra_redactor,
        )

        # Canonicalize normalized event before chaining so stored entry_hash equals disk representation.
        canonical_event_obj = json.loads(
            canonical_json_bytes(cast(JsonObject, safe_event.model_dump(mode="json"))).decode("utf-8")
        )
        canonical_event = ZoneEvent.model_validate(canonical_event_obj)

        with _exclusive_lock(self._lock_path):
            if not self._file_unchanged_since_last_write():
                # Another writer appended (or someone edited the file) since our last write: re-verify, require
                # our own last entry to still be there, and chain onto the verified tail.
                self._adopt_verified_tail(anchor=self.head)
            size_before = self.path.stat().st_size if self.path.exists() else 0

            seq = self._next_seq
            prev_hash = self._prev_hash
            entry_hash = sha256_canonical(_entry_chain_payload(seq, prev_hash, canonical_event))
            entry = AuditLedgerEntry(
                seq=seq,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
                event=canonical_event,
            )
            entry_dump = cast(JsonObject, entry.model_dump(mode="json"))
            line_bytes = canonical_json_bytes(entry_dump)
            line_text = line_bytes.decode("utf-8")

            # Hard defense-in-depth invariant: refuse to flush if any canary form survived sanitization.
            for canary in self.canary_tokens:
                if (
                    canary in line_text
                    or canary_present(line_text, canary)
                    or canary_present_in_json(entry_dump, canary)
                ):
                    raise RuntimeError("Audit redaction invariant violated: canary value survived sanitization.")

            payload_line = line_bytes + b"\n"
            with self.path.open("ab") as fh:
                fh.write(payload_line)
                fh.flush()
                os.fsync(fh.fileno())
            self._known_size = size_before + len(payload_line)
            self._known_tail = payload_line
            self._next_seq = seq + 1
            self._prev_hash = entry_hash

        return entry
