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

import base64
import binascii
import functools
import hashlib
import json
import os
import re
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from urllib.parse import unquote

from pydantic import ValidationError

from mcp_airlock.core.normalize import (
    JsonObject,
    JsonValue,
    canonical_json_bytes,
    has_invisible_unicode,
    normalize_str,
    sha256_canonical,
    sha256_exact,
)
from mcp_airlock.core.schemas import (
    GENESIS_PREV_HASH,
    AuditLedgerEntry,
    LedgerVerification,
    ZoneEvent,
)

# Defense-in-depth secret regexes owned by core so audit.py never persists raw secrets even standalone.
CORE_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-(?:proj|svcacct|None)-[A-Za-z0-9_-]{10,}"),
    re.compile(r"sk-[A-Za-z0-9]{48}"),
    re.compile(r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{10,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{20,}"),
    re.compile(r"hf_[A-Za-z0-9]{20,}"),
    re.compile(r"lsv2_(?:pt|sk)_[a-f0-9]{16,}_[a-f0-9]{6,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"xox[baprs]-[0-9A-Za-z-]{16,}"),
    re.compile(r"(?:sk|rk)_live_[0-9A-Za-z]{16,}"),
    re.compile(r"(?i)(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}"),
    # The body may not cross another BEGIN header, so many unterminated headers stay linear to scan.
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:(?!-----BEGIN )[\s\S])*?-----END [A-Z0-9 ]*PRIVATE KEY-----"),
)

# The lookbehind makes a scheme start only at a token boundary, keeping the scan linear on long words.
_URL_USERINFO_SECRET_RE = re.compile(r"(?<![A-Za-z0-9+.-])([A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+(@)")
_CANARY_SEP_RE = re.compile(r"[\s._:/\\|-]+")
_HEX_CANDIDATE_RE = re.compile(r"[0-9A-Fa-f]{16,}")
_DELIMITED_HEX_CANDIDATE_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:\-\s]+){7,}[0-9A-Fa-f]{2}")
_B64_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")


def _compile_obfuscated_canary_regex(token: str) -> re.Pattern[str]:
    """Match `token` even if invisible Unicode format/tag characters are interleaved between characters."""
    norm_token = normalize_str(token)
    if not norm_token:
        return re.compile(re.escape(token))
    gap = (
        r"[\u034f\u115f\u1160\u17b4\u17b5\u180b-\u180e\u200b-\u200f\u2060\u2800"
        r"\u3164\ufeff\uffa0\ufe00-\ufe0f\U000e0000-\U000e007f\U000e0100-\U000e01ef]*"
    )
    escaped_chars = [re.escape(ch) for ch in norm_token]
    return re.compile(gap.join(escaped_chars), re.IGNORECASE)


@dataclass(frozen=True)
class _CanarySignature:
    norm_canary: str
    folded: str
    obfuscated_re: re.Pattern[str]
    reversed_folded: str | None
    hex_lower: str | None
    delimited_hex_re: re.Pattern[str] | None
    b64_slices: tuple[str, ...]
    skeleton: str | None


@functools.lru_cache(maxsize=256)
def _canary_signature(norm_canary: str) -> _CanarySignature:
    folded = norm_canary.casefold()
    raw_bytes = norm_canary.encode("utf-8")
    hex_lower = raw_bytes.hex() if len(raw_bytes) >= 6 else None
    delimited_hex_re = (
        re.compile(r"[:\-\s]+".join(f"{b:02x}" for b in raw_bytes), re.IGNORECASE) if len(norm_canary) >= 8 else None
    )
    slices: list[str] = []
    seen_slices: set[str] = set()
    for enc_fn in (base64.b64encode, base64.urlsafe_b64encode):
        for offset in (0, 1, 2):
            padded = (b"\x00" * offset) + raw_bytes
            unpadded = enc_fn(padded).decode("ascii").rstrip("=")
            lead = 0 if offset == 0 else (2 if offset == 1 else 3)
            trail = 0 if (len(padded) % 3 == 0) else 1
            end = len(unpadded) - trail if trail else len(unpadded)
            inv = unpadded[lead:end]
            if len(inv) >= 12 and inv not in seen_slices:
                seen_slices.add(inv)
                slices.append(inv)
    skel = _CANARY_SEP_RE.sub("", norm_canary).casefold()
    skeleton = skel if (len(norm_canary) >= 8 and len(skel) >= 8) else None
    return _CanarySignature(
        norm_canary=norm_canary,
        folded=folded,
        obfuscated_re=_compile_obfuscated_canary_regex(norm_canary),
        reversed_folded=norm_canary[::-1].casefold() if len(norm_canary) >= 8 else None,
        hex_lower=hex_lower,
        delimited_hex_re=delimited_hex_re,
        b64_slices=tuple(slices),
        skeleton=skeleton,
    )


def _match_plain_forms(norm: str, sig: _CanarySignature) -> bool:
    norm_folded = norm.casefold()
    if sig.folded in norm_folded:
        return True
    if sig.reversed_folded is not None and sig.reversed_folded in norm_folded:
        return True
    if sig.skeleton is not None and sig.skeleton in _CANARY_SEP_RE.sub("", norm).casefold():
        return True
    return False


def _canary_present_plain(text: str, sig: _CanarySignature) -> bool:
    """Plaintext, reversed, separator-stripped, and single/double percent-decoded match without candidate decoding."""
    norm = normalize_str(text)
    if _match_plain_forms(norm, sig):
        return True
    if "%" in norm:
        u1 = normalize_str(unquote(norm))
        if _match_plain_forms(u1, sig):
            return True
        if "%" in u1:
            u2 = normalize_str(unquote(u1))
            if _match_plain_forms(u2, sig):
                return True
    return False


def canary_present(text: str, canary: str) -> bool:
    """
    Deterministic check for raw, NFKC/invisible-obfuscated, percent-encoded (1x/2x), reversed,
    punctuation/whitespace-interleaved, hex (contiguous/delimited), and Base64/Base64url (all 3 byte
    alignments) canary forms inside `text`.
    """
    norm_canary = normalize_str(canary)
    if not norm_canary:
        return False
    sig = _canary_signature(norm_canary)
    norm = normalize_str(text)
    if _canary_present_plain(norm, sig):
        return True
    norm_folded = norm.casefold()
    if sig.hex_lower is not None and sig.hex_lower in norm_folded:
        return True
    if sig.delimited_hex_re is not None and sig.delimited_hex_re.search(norm) is not None:
        return True
    if any(sl in norm for sl in sig.b64_slices):
        return True

    for m in _HEX_CANDIDATE_RE.finditer(norm):
        tok = m.group(0)
        candidates = (tok,) if len(tok) % 2 == 0 else (tok[:-1], tok[1:])
        for cand in candidates:
            try:
                decoded = bytes.fromhex(cand).decode("utf-8", errors="ignore")
            except ValueError:
                continue
            if decoded and _canary_present_plain(decoded, sig):
                return True

    for m in _DELIMITED_HEX_CANDIDATE_RE.finditer(norm):
        compact = re.sub(r"[:\-\s]+", "", m.group(0))
        if len(compact) % 2 != 0:
            compact = compact[:-1]
        try:
            decoded = bytes.fromhex(compact).decode("utf-8", errors="ignore")
        except ValueError:
            continue
        if decoded and _canary_present_plain(decoded, sig):
            return True

    for m in _B64_CANDIDATE_RE.finditer(norm):
        core = m.group(0).rstrip("=").replace("-", "+").replace("_", "/")
        for offset in (0, 1, 2, 3):
            shifted = core[offset:]
            if len(shifted) < 12:
                continue
            rem = len(shifted) % 4
            if rem == 1:
                shifted = shifted[:-1]
            elif rem:
                shifted = shifted + ("=" * (4 - rem))
            try:
                decoded = base64.b64decode(shifted, validate=False).decode("utf-8", errors="ignore")
            except (binascii.Error, ValueError):
                continue
            if decoded and _canary_present_plain(decoded, sig):
                return True

    return False


def redact_canary_in_text(text: str, canary: str) -> tuple[str, bool]:
    """
    Detect and redact any plain, obfuscated, reversed, interleaved, percent-encoded, hex, or Base64
    representation of `canary` inside `text`. Returns `(sanitized, matched)`.
    """
    if not canary:
        return text, False
    norm_canary = normalize_str(canary)
    matched = (canary in text) or (bool(norm_canary) and canary_present(text, canary))
    if not matched:
        return text, False
    sanitized = text.replace(canary, "[REDACTED_CANARY]")
    if norm_canary:
        sanitized = _canary_signature(norm_canary).obfuscated_re.sub("[REDACTED_CANARY]", sanitized)
        if canary in sanitized or canary_present(sanitized, canary):
            # Encoded, homoglyphed, reversed, or interleaved residue cannot be excised cleanly in place.
            sanitized = "[REDACTED_CANARY]"
    return sanitized, True


def redact_core_secrets(
    text: str,
    *,
    canary_tokens: tuple[str, ...] = (),
    extra_redactor: Callable[[str], str] | None = None,
) -> str:
    """
    Redact canary tokens (raw, tag-obfuscated, NFKC, percent-encoded, hex, Base64, reversed, interleaved),
    URL passwords, and known credential patterns.
    """
    sanitized = text
    for canary in canary_tokens:
        sanitized, _ = redact_canary_in_text(sanitized, canary)

    sanitized = _URL_USERINFO_SECRET_RE.sub(r"\1[REDACTED_SECRET]\2", sanitized)
    for pattern in CORE_SECRET_PATTERNS:
        sanitized = pattern.sub("[REDACTED_SECRET]", sanitized)
    norm_after = normalize_str(sanitized)
    if norm_after != sanitized:
        norm_checked = _URL_USERINFO_SECRET_RE.sub(r"\1[REDACTED_SECRET]\2", norm_after)
        changed = norm_checked != norm_after
        for pattern in CORE_SECRET_PATTERNS:
            replaced = pattern.sub("[REDACTED_SECRET]", norm_checked)
            if replaced != norm_checked:
                changed = True
                norm_checked = replaced
        if changed:
            sanitized = norm_checked
    if extra_redactor is not None:
        sanitized = extra_redactor(sanitized)
    return sanitized


def _redact_json_value(
    value: JsonValue,
    *,
    canary_tokens: tuple[str, ...],
    extra_redactor: Callable[[str], str] | None,
) -> JsonValue:
    if isinstance(value, str):
        return redact_core_secrets(value, canary_tokens=canary_tokens, extra_redactor=extra_redactor)
    if isinstance(value, list):
        return [_redact_json_value(item, canary_tokens=canary_tokens, extra_redactor=extra_redactor) for item in value]
    if isinstance(value, dict):
        redacted_dict: dict[str, JsonValue] = {}
        for k, v in value.items():
            safe_k = redact_core_secrets(k, canary_tokens=canary_tokens, extra_redactor=extra_redactor)
            safe_v = _redact_json_value(v, canary_tokens=canary_tokens, extra_redactor=extra_redactor)
            redacted_dict[safe_k] = safe_v
        return redacted_dict
    return value


def _sanitize_event(
    event: ZoneEvent,
    *,
    artifact_sha256: str,
    canary_tokens: tuple[str, ...],
    extra_redactor: Callable[[str], str] | None,
) -> ZoneEvent:
    safe_meta = cast(
        JsonObject,
        _redact_json_value(event.metadata, canary_tokens=canary_tokens, extra_redactor=extra_redactor),
    )
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
    return ZoneEvent(
        event_id=redact_core_secrets(event.event_id, canary_tokens=canary_tokens, extra_redactor=extra_redactor),
        timestamp_utc=event.timestamp_utc,
        zone=event.zone,
        action=redact_core_secrets(event.action, canary_tokens=canary_tokens, extra_redactor=extra_redactor),
        verdict_allow=event.verdict_allow,
        severity=event.severity,
        rule_id=redact_core_secrets(event.rule_id, canary_tokens=canary_tokens, extra_redactor=extra_redactor),
        reason=redact_core_secrets(event.reason, canary_tokens=canary_tokens, extra_redactor=extra_redactor),
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
            line_bytes = canonical_json_bytes(cast(JsonObject, entry.model_dump(mode="json")))
            line_text = line_bytes.decode("utf-8")

            # Hard defense-in-depth invariant: refuse to flush if any canary form survived sanitization.
            for canary in self.canary_tokens:
                if canary in line_text or canary_present(line_text, canary):
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
