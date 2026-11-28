"""
Tamper-evident append-only JSONL flight recorder (`schema_version = 2`) and universal ledger verifier.

Invariants enforced (per AGENTS.md):
  - Redact Before Disk: compute `artifact_sha256` from the unredacted artifact first,
    redact all secret patterns and planted canary tokens in events, assert no canary survives
    on serialized bytes/JSON, then hash-chain and flush + fsync.
  - Unified v2 Envelope: `{schema_version: 2, seq, prev_hash, entry_hash, source, event}`, with
    canonical hashing over `{schema_version, seq, prev_hash, source, event}` and U+0085/U+2028/U+2029
    escaped on disk (`\\u0085`, `\\u2028`, `\\u2029`).
  - Read-Only Legacy Support & Fail-Closed Migration: `verify_ledger*` verifies v2, v1 Airlock,
    and v1 gateway ledgers auto-detected (rejecting mixed or unchained logs). On open, writers move
    entirely-v1 ledgers aside to `<name>.v1-<UTC>` and unchained pre-1.1 logs aside to
    `<name>.pre-chain-<UTC>`, writing a v2 `ledger_rotated` genesis record. Mixed, symlinked, or
    tampered ledgers refuse startup fail closed.
  - Bare-Stdlib Compatibility & Strict DAG: top-level imports use only the Python standard library
    and `mellyn.core.normalize` / `mellyn.core.scan`. `pydantic` and `mellyn.core.schemas` are imported
    lazily inside the `AuditLedger` / `verify_ledger` Pydantic facades.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sys
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, TextIO, cast

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

if TYPE_CHECKING:
    from mellyn.core.schemas import AuditLedgerEntry, LedgerFormat, LedgerVerification, ZoneEvent

GENESIS_PREV_HASH = "0" * 64
LEDGER_SCHEMA_VERSION: Literal[2] = 2
LEDGER_SOURCES: frozenset[str] = frozenset({"airlock", "gateway", "authorizer"})
EMPTY_JSON_OBJECT_SHA256 = hashlib.sha256(b"{}").hexdigest()

type LedgerAnchor = tuple[int, str]
"""`(seq, entry_hash)` of an entry recorded OUTSIDE the ledger file (e.g. shipped to a log server)."""

_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
# Characters Python's str.splitlines() treats as line breaks but json.dumps(ensure_ascii=False) leaves raw.
# Escaping them on write ensures records never split across lines while preserving exact parsed string values.
_LINE_BREAK_ESCAPES = str.maketrans({"\u0085": "\\u0085", "\u2028": "\\u2028", "\u2029": "\\u2029"})
_V1_CHAIN_FIELDS = ("seq", "prev_hash", "entry_hash")
_V2_KEYS = frozenset({"schema_version", "seq", "prev_hash", "entry_hash", "source", "event"})
_V1_AIRLOCK_KEYS = frozenset({"seq", "prev_hash", "entry_hash", "event"})

_ZONE_EVENT_REQUIRED = frozenset(
    {
        "event_id",
        "timestamp_utc",
        "zone",
        "action",
        "verdict_allow",
        "severity",
        "rule_id",
        "reason",
        "artifact_sha256",
    }
)
_ZONE_EVENT_ALL = _ZONE_EVENT_REQUIRED | {"tool_name", "request_id", "redactions", "metadata"}
_REDACTION_RECORD_KEYS = frozenset({"kind", "rule_id", "field_path", "match_sha256"})
_REDACTION_KINDS = frozenset({"canary", "secret", "high_entropy", "blocked_pattern", "structure"})
_SEVERITIES = frozenset({"ALLOW", "INFO", "WARN", "BLOCK", "AAD_FIRE"})
_ZONES = frozenset({"core", "egress", "airlock", "ir_lab", "gateway", "authorizer"})
_WIN_LOCK_TIMEOUT_SECONDS = 15.0


class LedgerIntegrityError(ValueError):
    """Raised fail-closed when an audit ledger fails symlink safety, verification, or schema checks."""


@dataclass(frozen=True)
class CoreLedgerEntry:
    """Stdlib representation of one hash-chained `schema_version = 2` audit entry."""

    schema_version: int
    seq: int
    prev_hash: str
    entry_hash: str
    source: str
    event: JsonObject


@dataclass(frozen=True)
class CoreLedgerVerification:
    """Result of verifying any supported audit ledger (`v2`, `v1_airlock`, `v1_gateway`, or `empty`)."""

    valid: bool
    entry_count: int
    last_seq: int | None = None
    last_hash: str | None = None
    first_invalid_seq: int | None = None
    first_invalid_line: int | None = None
    reason: str | None = None
    ledger_format: str | None = None
    sources: tuple[str, ...] = ()


def split_audit_lines(text: str) -> list[str]:
    """Split a ledger into records on `"\\n"` only (escaping U+0085/U+2028/U+2029 prevents spurious breaks)."""
    return text.split("\n")


def encode_ledger_line(entry_obj: JsonObject) -> bytes:
    """Serialize a canonical JSON ledger line with U+0085/U+2028/U+2029 escaped for single-line integrity."""
    canonical_text = canonical_json_bytes(entry_obj).decode("utf-8")
    return canonical_text.translate(_LINE_BREAK_ESCAPES).encode("utf-8")


def _strict_json_loads(raw_line: str) -> Any:
    def _reject_dup_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in pairs:
            if k in out:
                raise ValueError(f"Duplicate JSON key '{k}' in audit entry.")
            out[k] = v
        return out

    def _reject_constant(token: str) -> Any:
        raise ValueError(f"Non-standard JSON constant is forbidden in audit entry: {token!r}.")

    return json.loads(raw_line, object_pairs_hook=_reject_dup_keys, parse_constant=_reject_constant)


def _reject_symlink_path(path: Path) -> None:
    if path.is_symlink() or path.parent.is_symlink():
        raise LedgerIntegrityError(f"Refusing symlink audit ledger path '{path}'.")


def _open_private_fd(path: Path, flags: int) -> int:
    open_flags = flags | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, open_flags, 0o600)
    try:
        if os.name == "posix" and hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
    except Exception:
        os.close(fd)
        raise
    return fd


def _check_json_finite(value: object) -> bool:
    stack: list[object] = [value]
    while stack:
        node = stack.pop()
        if node is None or isinstance(node, bool | int | str):
            continue
        if isinstance(node, float):
            if not math.isfinite(node):
                return False
            continue
        if isinstance(node, list):
            stack.extend(node)
            continue
        if isinstance(node, dict):
            for k, v in node.items():
                if not isinstance(k, str):
                    return False
                stack.append(v)
            continue
        return False
    return True


def _validate_zone_event_dict(event: dict[str, Any]) -> str | None:
    """Validate strict `ZoneEvent` structure in stdlib without requiring Pydantic."""
    keys = event.keys()
    if not (_ZONE_EVENT_REQUIRED <= keys):
        return "ZoneEvent is missing required field(s)."
    extra = keys - _ZONE_EVENT_ALL
    if extra:
        return f"ZoneEvent contains unexpected field(s): {', '.join(sorted(extra))}."

    for req_str in ("event_id", "timestamp_utc", "action", "rule_id", "reason"):
        val = event[req_str]
        if not isinstance(val, str) or not val:
            return f"ZoneEvent field '{req_str}' must be a non-empty string."

    if event["zone"] not in _ZONES:
        return f"Invalid ZoneEvent zone: {event['zone']!r}."
    if not isinstance(event["verdict_allow"], bool):
        return "ZoneEvent verdict_allow must be a strict boolean."
    if event["severity"] not in _SEVERITIES:
        return f"Invalid ZoneEvent severity: {event['severity']!r}."
    if event["severity"] in ("BLOCK", "AAD_FIRE") and event["verdict_allow"]:
        return f"Severity {event['severity']!r} cannot coexist with verdict_allow=True."

    art_sha = event["artifact_sha256"]
    if not isinstance(art_sha, str) or _SHA256_HEX_RE.fullmatch(art_sha) is None:
        return "ZoneEvent artifact_sha256 must be a 64-character lowercase hex digest."

    tool_name = event.get("tool_name")
    if "tool_name" in event and tool_name is not None and not isinstance(tool_name, str):
        return "ZoneEvent tool_name must be a string or null."

    req_id = event.get("request_id")
    if "request_id" in event and req_id is not None:
        if isinstance(req_id, bool) or not isinstance(req_id, int | str):
            return "ZoneEvent request_id must be int, str, or null."

    if "redactions" in event:
        redactions = event["redactions"]
        if not isinstance(redactions, list):
            return "ZoneEvent redactions must be a list."
        for item in redactions:
            if not isinstance(item, dict) or item.keys() != _REDACTION_RECORD_KEYS:
                return "ZoneEvent redaction entry has invalid schema."
            if item["kind"] not in _REDACTION_KINDS:
                return f"ZoneEvent redaction kind invalid: {item['kind']!r}."
            if not isinstance(item["rule_id"], str) or not item["rule_id"]:
                return "ZoneEvent redaction rule_id must be a non-empty string."
            if not isinstance(item["field_path"], str) or not item["field_path"]:
                return "ZoneEvent redaction field_path must be a non-empty string."
            match_sha = item["match_sha256"]
            if not isinstance(match_sha, str) or _SHA256_HEX_RE.fullmatch(match_sha) is None:
                return "ZoneEvent redaction match_sha256 must be a 64-char lowercase hex digest."

    if "metadata" in event:
        meta = event["metadata"]
        if not isinstance(meta, dict) or not _check_json_finite(meta):
            return "ZoneEvent metadata must be a strict finite JSON object."

    return None


def _is_valid_anchor(anchor: LedgerAnchor) -> bool:
    return (
        isinstance(anchor, tuple)
        and len(anchor) == 2
        and not isinstance(anchor[0], bool)
        and isinstance(anchor[0], int)
        and anchor[0] >= 0
        and isinstance(anchor[1], str)
        and _SHA256_HEX_RE.fullmatch(anchor[1]) is not None
    )


def _fail_verification(
    *,
    entry_count: int,
    last_seq: int | None,
    last_hash: str | None,
    first_invalid_seq: int | None,
    first_invalid_line: int | None,
    reason: str,
    ledger_format: str | None = None,
) -> CoreLedgerVerification:
    return CoreLedgerVerification(
        valid=False,
        entry_count=entry_count,
        last_seq=last_seq,
        last_hash=last_hash,
        first_invalid_seq=first_invalid_seq,
        first_invalid_line=first_invalid_line,
        reason=reason,
        ledger_format=ledger_format,
    )


def _classify_line_format(obj: dict[str, Any]) -> tuple[str | None, str | None]:
    if "schema_version" in obj:
        sv = obj["schema_version"]
        if isinstance(sv, bool) or sv != LEDGER_SCHEMA_VERSION:
            return None, f"Unsupported ledger schema_version: {sv!r}."
        return "v2", None
    if "event" in obj:
        return "v1_airlock", None
    if any(field in obj for field in _V1_CHAIN_FIELDS):
        return "v1_gateway", None
    return "pre_chain", None


def _verify_v2_entry(
    obj: dict[str, Any],
    line_bytes: bytes,
    *,
    seq: int,
    prev_hash: str,
    entry_hash: str,
) -> tuple[str | None, str | None]:
    if obj.keys() != _V2_KEYS:
        return None, f"Schema validation failed at seq {seq}: invalid v2 envelope fields."
    if has_invisible_unicode(obj):
        return None, f"Invalid entry structure or invisible Unicode detected at seq {seq}."
    source = obj["source"]
    if not isinstance(source, str) or source not in LEDGER_SOURCES:
        return None, f"Invalid v2 ledger source at seq {seq}: {source!r}."
    event = obj["event"]
    if not isinstance(event, dict) or not _check_json_finite(event):
        return None, f"Invalid v2 event payload at seq {seq}."
    if source == "airlock":
        err = _validate_zone_event_dict(event)
        if err is not None:
            return None, f"Schema validation failed at seq {seq}: {err}"

    expected_hash = sha256_canonical(
        {
            "schema_version": LEDGER_SCHEMA_VERSION,
            "seq": seq,
            "prev_hash": prev_hash,
            "source": source,
            "event": event,
        }
    )
    if not hmac.compare_digest(entry_hash, expected_hash):
        return None, f"Tampered entry content at seq {seq}: entry_hash mismatch."
    if line_bytes != encode_ledger_line(obj):
        return None, f"Non-canonical encoding / mid-log byte tampering at seq {seq}."
    return source, None


def _verify_v1_airlock_entry(
    obj: dict[str, Any],
    line_bytes: bytes,
    *,
    seq: int,
    prev_hash: str,
    entry_hash: str,
) -> str | None:
    if obj.keys() != _V1_AIRLOCK_KEYS:
        return f"Schema validation failed at seq {seq}: invalid v1 Airlock envelope fields."
    if has_invisible_unicode(obj):
        return f"Invalid entry structure or invisible Unicode detected at seq {seq}."
    event = obj["event"]
    if not isinstance(event, dict):
        return f"Schema validation failed at seq {seq}: v1 Airlock event must be a JSON object."
    err = _validate_zone_event_dict(event)
    if err is not None:
        return f"Schema validation failed at seq {seq}: {err}"

    expected_hash = sha256_canonical({"seq": seq, "prev_hash": prev_hash, "event": event})
    if not hmac.compare_digest(entry_hash, expected_hash):
        return f"Tampered entry content at seq {seq}: entry_hash mismatch."
    if line_bytes != canonical_json_bytes(obj):
        return f"Non-canonical encoding / mid-log byte tampering at seq {seq}."
    return None


def _verify_v1_gateway_entry(obj: dict[str, Any], *, line_no: int, entry_hash: str) -> str | None:
    body = {k: v for k, v in obj.items() if k != "entry_hash"}
    if not _check_json_finite(body):
        return f"Non-finite number in v1 gateway audit entry on line {line_no}."
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode(
        "utf-8"
    )
    expected_hash = hashlib.sha256(encoded).hexdigest()
    if not hmac.compare_digest(entry_hash, expected_hash):
        return f"Entry digest mismatch on line {line_no} (tampered record)."
    return None


def verify_ledger_bytes_core(raw_bytes: bytes, *, anchor: LedgerAnchor | None = None) -> CoreLedgerVerification:
    """
    Universal single verifier over raw ledger bytes for `v2`, `v1_airlock`, `v1_gateway`, and empty logs.

    Rejects mixed formats, unchained pre-1.1 logs, blank lines, missing trailing newlines, duplicate JSON keys,
    non-finite constants, invisible Unicode (for v1 Airlock and v2), and anchor mismatches.
    """
    if anchor is not None and not _is_valid_anchor(anchor):
        return _fail_verification(
            entry_count=0,
            last_seq=None,
            last_hash=None,
            first_invalid_seq=0,
            first_invalid_line=1,
            reason="Ledger anchor is malformed.",
        )

    if not raw_bytes:
        if anchor is not None:
            return _fail_verification(
                entry_count=0,
                last_seq=None,
                last_hash=None,
                first_invalid_seq=0,
                first_invalid_line=1,
                reason=f"Audit ledger is empty but anchor expects seq {anchor[0]} (truncated).",
                ledger_format="empty",
            )
        return CoreLedgerVerification(valid=True, entry_count=0, last_seq=None, last_hash=None, ledger_format="empty")

    has_trailing_nl = raw_bytes.endswith(b"\n")
    lines = raw_bytes[:-1].split(b"\n") if has_trailing_nl else raw_bytes.split(b"\n")

    expected_prev = GENESIS_PREV_HASH
    last_hash: str | None = None
    detected_format: str | None = None
    seen_sources: set[str] = set()
    count = 0

    for expected_seq, line_bytes in enumerate(lines):
        line_no = expected_seq + 1
        last_seq_so_far = expected_seq - 1 if count else None

        if not line_bytes or line_bytes == b"\r":
            return _fail_verification(
                entry_count=count,
                last_seq=last_seq_so_far,
                last_hash=last_hash,
                first_invalid_seq=expected_seq,
                first_invalid_line=line_no,
                reason=f"Blank line encountered at seq {expected_seq}.",
                ledger_format=detected_format,
            )

        parse_bytes = line_bytes[:-1] if line_bytes.endswith(b"\r") else line_bytes
        try:
            decoded_text = parse_bytes.decode("utf-8")
            parsed_obj = _strict_json_loads(decoded_text)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            return _fail_verification(
                entry_count=count,
                last_seq=last_seq_so_far,
                last_hash=last_hash,
                first_invalid_seq=expected_seq,
                first_invalid_line=line_no,
                reason=f"Malformed JSON or duplicate key at line {line_no} (seq {expected_seq}): {exc}",
                ledger_format=detected_format,
            )

        if not isinstance(parsed_obj, dict):
            return _fail_verification(
                entry_count=count,
                last_seq=last_seq_so_far,
                last_hash=last_hash,
                first_invalid_seq=expected_seq,
                first_invalid_line=line_no,
                reason=f"Audit entry on line {line_no} (seq {expected_seq}) is not a JSON object.",
                ledger_format=detected_format,
            )

        line_format, fmt_err = _classify_line_format(parsed_obj)
        if fmt_err is not None or line_format is None:
            return _fail_verification(
                entry_count=count,
                last_seq=last_seq_so_far,
                last_hash=last_hash,
                first_invalid_seq=expected_seq,
                first_invalid_line=line_no,
                reason=fmt_err or f"Unrecognized ledger format at seq {expected_seq}.",
                ledger_format=detected_format,
            )

        if line_format == "pre_chain":
            return _fail_verification(
                entry_count=count,
                last_seq=last_seq_so_far,
                last_hash=last_hash,
                first_invalid_seq=expected_seq,
                first_invalid_line=line_no,
                reason=f"Unchained pre-1.1 audit record encountered at line {line_no} (seq {expected_seq}).",
                ledger_format="pre_chain" if detected_format is None else detected_format,
            )

        if detected_format is None:
            detected_format = line_format
        elif line_format != detected_format:
            return _fail_verification(
                entry_count=count,
                last_seq=last_seq_so_far,
                last_hash=last_hash,
                first_invalid_seq=expected_seq,
                first_invalid_line=line_no,
                reason=(
                    f"Mixed ledger formats at line {line_no} (seq {expected_seq}): "
                    f"expected {detected_format!r}, found {line_format!r}."
                ),
                ledger_format=detected_format,
            )

        seq = parsed_obj.get("seq")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq != expected_seq:
            return _fail_verification(
                entry_count=count,
                last_seq=last_seq_so_far,
                last_hash=last_hash,
                first_invalid_seq=expected_seq,
                first_invalid_line=line_no,
                reason=f"Sequence mismatch at line {line_no} (index {expected_seq}): found seq {seq!r}.",
                ledger_format=detected_format,
            )

        prev_hash = parsed_obj.get("prev_hash")
        if (
            not isinstance(prev_hash, str)
            or _SHA256_HEX_RE.fullmatch(prev_hash) is None
            or not hmac.compare_digest(prev_hash, expected_prev)
        ):
            return _fail_verification(
                entry_count=count,
                last_seq=last_seq_so_far,
                last_hash=last_hash,
                first_invalid_seq=expected_seq,
                first_invalid_line=line_no,
                reason=f"Hash chain break at line {line_no} (seq {expected_seq}): prev_hash mismatch.",
                ledger_format=detected_format,
            )

        entry_hash = parsed_obj.get("entry_hash")
        if not isinstance(entry_hash, str) or _SHA256_HEX_RE.fullmatch(entry_hash) is None:
            return _fail_verification(
                entry_count=count,
                last_seq=last_seq_so_far,
                last_hash=last_hash,
                first_invalid_seq=expected_seq,
                first_invalid_line=line_no,
                reason=f"Malformed entry_hash at line {line_no} (seq {expected_seq}).",
                ledger_format=detected_format,
            )

        if line_format == "v2":
            entry_source, verify_err = _verify_v2_entry(
                parsed_obj,
                parse_bytes,
                seq=seq,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
            )
            if verify_err is not None or entry_source is None:
                return _fail_verification(
                    entry_count=count,
                    last_seq=last_seq_so_far,
                    last_hash=last_hash,
                    first_invalid_seq=expected_seq,
                    first_invalid_line=line_no,
                    reason=verify_err or f"Invalid v2 entry at seq {expected_seq}.",
                    ledger_format=detected_format,
                )
            seen_sources.add(entry_source)
        elif line_format == "v1_airlock":
            verify_err = _verify_v1_airlock_entry(
                parsed_obj,
                parse_bytes,
                seq=seq,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
            )
            if verify_err is not None:
                return _fail_verification(
                    entry_count=count,
                    last_seq=last_seq_so_far,
                    last_hash=last_hash,
                    first_invalid_seq=expected_seq,
                    first_invalid_line=line_no,
                    reason=verify_err,
                    ledger_format=detected_format,
                )
            seen_sources.add("airlock")
        else:
            verify_err = _verify_v1_gateway_entry(parsed_obj, line_no=line_no, entry_hash=entry_hash)
            if verify_err is not None:
                return _fail_verification(
                    entry_count=count,
                    last_seq=last_seq_so_far,
                    last_hash=last_hash,
                    first_invalid_seq=expected_seq,
                    first_invalid_line=line_no,
                    reason=verify_err,
                    ledger_format=detected_format,
                )
            seen_sources.add("gateway")

        if anchor is not None and seq == anchor[0] and not hmac.compare_digest(entry_hash, anchor[1]):
            return _fail_verification(
                entry_count=count,
                last_seq=last_seq_so_far,
                last_hash=last_hash,
                first_invalid_seq=expected_seq,
                first_invalid_line=line_no,
                reason=f"Entry at anchored seq {expected_seq} does not match the anchor hash (ledger rewritten).",
                ledger_format=detected_format,
            )

        expected_prev = entry_hash
        last_hash = entry_hash
        count += 1

    if not has_trailing_nl:
        return _fail_verification(
            entry_count=count,
            last_seq=count - 1 if count else None,
            last_hash=last_hash,
            first_invalid_seq=max(0, count - 1),
            first_invalid_line=max(1, count),
            reason="Audit ledger is truncated (missing trailing newline).",
            ledger_format=detected_format,
        )

    if anchor is not None and count <= anchor[0]:
        return _fail_verification(
            entry_count=count,
            last_seq=count - 1 if count else None,
            last_hash=last_hash,
            first_invalid_seq=count,
            first_invalid_line=count + 1,
            reason=f"Audit ledger ends at {count} entries but anchor expects seq {anchor[0]} (truncated).",
            ledger_format=detected_format,
        )

    return CoreLedgerVerification(
        valid=True,
        entry_count=count,
        last_seq=count - 1,
        last_hash=last_hash,
        first_invalid_seq=None,
        first_invalid_line=None,
        reason=None,
        ledger_format=detected_format,
        sources=tuple(sorted(seen_sources)),
    )


def verify_ledger_file_core(path: Path, *, anchor: LedgerAnchor | None = None) -> CoreLedgerVerification:
    """Verify an audit ledger on disk, refusing symlinks and missing files fail-closed."""
    if anchor is not None and not _is_valid_anchor(anchor):
        return _fail_verification(
            entry_count=0,
            last_seq=None,
            last_hash=None,
            first_invalid_seq=0,
            first_invalid_line=1,
            reason="Ledger anchor is malformed.",
        )

    if path.is_symlink() or path.parent.is_symlink():
        return _fail_verification(
            entry_count=0,
            last_seq=None,
            last_hash=None,
            first_invalid_seq=0,
            first_invalid_line=1,
            reason=f"Refusing symlink audit ledger path '{path}'.",
        )

    if not path.is_file():
        return _fail_verification(
            entry_count=0,
            last_seq=None,
            last_hash=None,
            first_invalid_seq=0,
            first_invalid_line=1,
            reason="Audit ledger does not exist.",
        )

    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        return _fail_verification(
            entry_count=0,
            last_seq=None,
            last_hash=None,
            first_invalid_seq=0,
            first_invalid_line=1,
            reason=f"Could not read audit ledger: {exc}",
        )
    return verify_ledger_bytes_core(raw_bytes, anchor=anchor)


def verify_ledger_lines_core(lines: Sequence[str], *, anchor: LedgerAnchor | None = None) -> CoreLedgerVerification:
    """Verify pre-split JSONL ledger lines using the single universal verifier."""
    trimmed = list(lines)
    while trimmed and not trimmed[-1].strip():
        trimmed.pop()
    if not trimmed:
        return verify_ledger_bytes_core(b"", anchor=anchor)
    try:
        raw_bytes = ("\n".join(trimmed) + "\n").encode("utf-8")
    except UnicodeEncodeError as exc:
        return _fail_verification(
            entry_count=0,
            last_seq=None,
            last_hash=None,
            first_invalid_seq=0,
            first_invalid_line=1,
            reason=f"Invalid UTF-8 surrogate in audit line: {exc}",
        )
    return verify_ledger_bytes_core(raw_bytes, anchor=anchor)


def is_legacy_unchained_bytes(raw_bytes: bytes) -> bool:
    """
    True only for a non-empty log written before hash chaining existed: every non-blank line is a valid
    strict JSON object with none of `schema_version`, `seq`, `prev_hash`, `entry_hash`, or `event`.
    """
    if not raw_bytes:
        return False
    try:
        lines = split_audit_lines(raw_bytes.decode("utf-8"))
    except UnicodeDecodeError:
        return False
    records = 0
    forbidden = (*_V1_CHAIN_FIELDS, "schema_version", "event")
    for raw in lines:
        stripped = raw.strip()
        if not stripped:
            continue
        try:
            obj = _strict_json_loads(stripped)
        except (ValueError, json.JSONDecodeError):
            return False
        if not isinstance(obj, dict) or any(field in obj for field in forbidden):
            return False
        records += 1
    return records > 0


def verify_ledger_bytes(raw_bytes: bytes, *, anchor: LedgerAnchor | None = None) -> LedgerVerification:
    """
    Verify ledger content already read into memory (`v2`, `v1_airlock`, `v1_gateway`, or `empty`).
    """
    from mellyn.core.schemas import LedgerVerification

    res = verify_ledger_bytes_core(raw_bytes, anchor=anchor)
    return LedgerVerification(
        valid=res.valid,
        entry_count=res.entry_count,
        last_seq=res.last_seq,
        last_hash=res.last_hash,
        first_invalid_seq=res.first_invalid_seq,
        reason=res.reason,
        ledger_format=cast("LedgerFormat | None", res.ledger_format),
    )


def verify_ledger(path: Path, *, anchor: LedgerAnchor | None = None) -> LedgerVerification:
    """
    Verify an append-only hash-chained `audit.jsonl` ledger (`v2`, `v1_airlock`, `v1_gateway`) from genesis.
    """
    from mellyn.core.schemas import LedgerVerification

    res = verify_ledger_file_core(path, anchor=anchor)
    return LedgerVerification(
        valid=res.valid,
        entry_count=res.entry_count,
        last_seq=res.last_seq,
        last_hash=res.last_hash,
        first_invalid_seq=res.first_invalid_seq,
        reason=res.reason,
        ledger_format=cast("LedgerFormat | None", res.ledger_format),
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


_SAFE_GATEWAY_STRUCTURAL_FIELDS = frozenset(
    {
        "audit_id",
        "timestamp",
        "decision",
        "risk_tier",
        "tainted",
        "args_sha256",
        "policy_id",
        "grant_id",
        "event_type",
        "taint_count",
        "enforcement_mode",
    }
)


def _sanitize_json_event(
    event: JsonObject,
    *,
    canary_tokens: tuple[str, ...],
    extra_redactor: Callable[[str], str] | None,
) -> JsonObject:
    safe_event = _redact_dict(event, canary_tokens=canary_tokens, extra_redactor=extra_redactor)
    if not canary_tokens or not _split_canary_in(safe_event, canary_tokens):
        return safe_event

    scrubbed: dict[str, JsonValue] = {}
    for k, v in safe_event.items():
        if k in _SAFE_GATEWAY_STRUCTURAL_FIELDS:
            scrubbed[k] = v
        elif isinstance(v, list):
            scrubbed[k] = ["[REDACTED_CANARY]" if _carries_canary_piece(item, canary_tokens) else item for item in v]
        elif _carries_canary_piece(v, canary_tokens):
            scrubbed[k] = "[REDACTED_CANARY]" if not isinstance(v, dict) else {"redacted": "[REDACTED_CANARY]"}
        else:
            scrubbed[k] = v

    if _split_canary_in(scrubbed, canary_tokens):
        for field in ("reasons", "taint_sources"):
            if isinstance(scrubbed.get(field), list):
                scrubbed[field] = ["[REDACTED_CANARY]"]
        for field in ("tool_name", "mcp_server", "action", "reason", "request_id"):
            if scrubbed.get(field) is not None:
                scrubbed[field] = "[REDACTED_CANARY]"
        sid = scrubbed.get("session_id")
        if isinstance(sid, str) and any(canary_present(sid, c) for c in canary_tokens):
            scrubbed["session_id"] = "[REDACTED_CANARY]"
        if isinstance(scrubbed.get("metadata"), dict):
            scrubbed["metadata"] = {"redacted": "[REDACTED_CANARY]"}
        if _split_canary_in(scrubbed, canary_tokens):
            for k in list(scrubbed):
                if k in _SAFE_GATEWAY_STRUCTURAL_FIELDS:
                    continue
                val = scrubbed[k]
                if isinstance(val, str):
                    scrubbed[k] = "[REDACTED_CANARY]"
                elif isinstance(val, list):
                    scrubbed[k] = ["[REDACTED_CANARY]"]
                elif isinstance(val, dict):
                    scrubbed[k] = {"redacted": "[REDACTED_CANARY]"}
    return scrubbed


def _sanitize_event(
    event: ZoneEvent,
    *,
    artifact_sha256: str,
    canary_tokens: tuple[str, ...],
    extra_redactor: Callable[[str], str] | None,
) -> ZoneEvent:
    from mellyn.core.schemas import RedactionRecord, ZoneEvent

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
    safe_redactions = [
        RedactionRecord(
            kind=rec.kind,
            rule_id=rec.rule_id,
            field_path=redact_core_secrets(rec.field_path, canary_tokens=canary_tokens, extra_redactor=extra_redactor),
            match_sha256=rec.match_sha256,
        )
        for rec in event.redactions
    ]

    def _peer_view() -> JsonObject:
        view: JsonObject = {"action": safe_action, "reason": safe_reason, "metadata": safe_meta}
        if safe_tool is not None:
            view["tool_name"] = safe_tool
        if isinstance(safe_req_id, str):
            view["request_id"] = safe_req_id
        if safe_redactions:
            view["redactions"] = [rec.field_path for rec in safe_redactions]
        return view

    if canary_tokens and _split_canary_in(_peer_view(), canary_tokens):

        def _scrub(text: str) -> str:
            return "[REDACTED_CANARY]" if _carries_canary_piece(text, canary_tokens) else text

        safe_meta = {
            k: ("[REDACTED_CANARY]" if _carries_canary_piece(v, canary_tokens) else v) for k, v in safe_meta.items()
        }
        safe_action, safe_reason = _scrub(safe_action), _scrub(safe_reason)
        safe_tool = _scrub(safe_tool) if safe_tool is not None else None
        safe_req_id = _scrub(safe_req_id) if isinstance(safe_req_id, str) else safe_req_id
        safe_redactions = [
            RedactionRecord(
                kind=rec.kind,
                rule_id=rec.rule_id,
                field_path="$[redacted]" if _carries_canary_piece(rec.field_path, canary_tokens) else rec.field_path,
                match_sha256=rec.match_sha256,
            )
            for rec in safe_redactions
        ]
        if _split_canary_in(_peer_view(), canary_tokens):
            safe_action = safe_reason = "[REDACTED_CANARY]"
            safe_tool = "[REDACTED_CANARY]" if safe_tool is not None else None
            safe_req_id = "[REDACTED_CANARY]" if isinstance(safe_req_id, str) else safe_req_id
            safe_redactions = [
                RedactionRecord(
                    kind=rec.kind,
                    rule_id=rec.rule_id,
                    field_path="$[redacted]",
                    match_sha256=rec.match_sha256,
                )
                for rec in safe_redactions
            ]
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
        redactions=safe_redactions,
        metadata=safe_meta,
    )


@contextmanager
def _locked_fd(fd: int) -> Iterator[None]:
    """Hold an exclusive OS lock on the open lock file `fd` so concurrent processes cannot fork the chain."""
    if sys.platform == "win32":
        import msvcrt

        deadline = time.monotonic() + _WIN_LOCK_TIMEOUT_SECONDS
        while True:
            os.lseek(fd, 0, os.SEEK_SET)
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.005)
        try:
            yield
        finally:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)


@contextmanager
def _exclusive_lock(lock_path: Path) -> Iterator[None]:
    """Open `lock_path` (refusing symlinks) and hold an exclusive OS lock on it."""
    _reject_symlink_path(lock_path)
    fd = _open_private_fd(lock_path, os.O_RDWR | os.O_CREAT)
    try:
        with _locked_fd(fd):
            yield
    finally:
        os.close(fd)


def _file_identity(path: Path) -> tuple[int, int] | None:
    """`(st_dev, st_ino)` of the file at `path` itself (symlinks not followed), or None when it is missing."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    return (st.st_dev, st.st_ino)


class _HeldFile:
    """
    A file descriptor kept open across appends, reopened whenever the path no longer names the same file.

    Opening the ledger and its lock file on every append cost about 4 ms per open on Windows (antivirus scans each
    open of a file being written). Holding them open keeps every check: before each use the path is re-checked
    for symlinks and compared, by device and inode, with the open descriptor, so a file swapped or replaced under
    the same name is reopened (and a symlink refused) rather than written through a stale handle.
    """

    def __init__(self, path: Path, flags: int) -> None:
        self.path = path
        self._flags = flags
        self.fd: int | None = None

    def get(self) -> int:
        _reject_symlink_path(self.path)
        if self.fd is not None:
            current = _file_identity(self.path)
            held = os.fstat(self.fd)
            if current == (held.st_dev, held.st_ino):
                return self.fd
            self.close()
        self.fd = _open_private_fd(self.path, self._flags)
        return self.fd

    def close(self) -> None:
        if self.fd is not None:
            fd, self.fd = self.fd, None
            os.close(fd)


def _rotate_aside(path: Path, *, tag: str, now_fn: Callable[[], datetime]) -> Path:
    """Rename a legacy ledger to `<name>.<tag>-<UTC>[-N]` in the same folder, never overwriting anything."""
    stamp = now_fn().astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    target = path.with_name(f"{path.name}.{tag}-{stamp}")
    counter = 1
    while target.exists() or target.is_symlink():
        target = path.with_name(f"{path.name}.{tag}-{stamp}-{counter}")
        counter += 1
    try:
        path.rename(target)
    except OSError as exc:
        raise LedgerIntegrityError(f"Could not move legacy audit ledger '{path}' aside: {exc}") from exc
    return target


def _default_rotation_event(rotated_path: Path, rotated_format: str, rotated_sha256: str) -> JsonObject:
    ts = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    return {
        "event_id": f"evt_rot_{secrets.token_hex(8)}",
        "timestamp_utc": ts,
        "zone": "core",
        "action": "audit/ledger_rotated",
        "verdict_allow": True,
        "severity": "INFO",
        "rule_id": "core.ledger_rotated",
        "reason": f"Moved {rotated_format} audit ledger to '{rotated_path.name}' and started schema_version=2 chain.",
        "artifact_sha256": rotated_sha256,
        "tool_name": "audit/ledger",
        "request_id": None,
        "redactions": [],
        "metadata": {
            "event_type": "ledger_rotated",
            "rotated_from": rotated_path.name,
            "rotated_format": rotated_format,
            "rotated_sha256": rotated_sha256,
        },
    }


class CoreAuditLedger:
    """
    Unified `schema_version = 2` append-only redacted hash-chained JSONL writer.

    Supports file-backed ledgers (with symlink refusal, `0o600` file creation, cross-process OS lock,
    `fsync`, v1/pre-chain move-aside rotation, and external anchor checks) as well as in-memory / `TextIO`
    sinks for isolated tests.
    """

    def __init__(
        self,
        path: Path | None = None,
        *,
        sink: TextIO | None = None,
        source: str = "airlock",
        canary_tokens: Sequence[str] = (),
        redactor: Callable[[str], str] | None = None,
        anchor: LedgerAnchor | None = None,
        create_empty: bool = False,
        start_seq: int = 0,
        prev_hash: str = GENESIS_PREV_HASH,
        now_fn: Callable[[], datetime] | None = None,
        rotation_event_factory: Callable[[Path, str, str], JsonObject] | None = None,
        keep_open: bool = False,
    ) -> None:
        """
        `keep_open=True` holds the ledger and lock file descriptors open between appends (see `_HeldFile`); the
        owner must call `close()`. The gateway/authorizer logger uses it; the Airlock opens per append.
        """
        if source not in LEDGER_SOURCES:
            raise ValueError(f"Unsupported ledger source: {source!r}")
        if path is not None and sink is not None:
            raise ValueError("Cannot specify both a file path and a TextIO sink.")

        self.path = path
        self._sink = sink
        self.source = source
        self.canary_tokens = tuple(t for t in canary_tokens if t)
        self._extra_redactor = redactor
        self._now_fn = now_fn or (lambda: datetime.now(UTC))
        self._thread_lock = threading.Lock()
        self._next_seq = start_seq
        self._prev_hash = prev_hash
        self._known_size = 0
        self._known_tail = b""
        self._closed = False
        self.rotated_legacy_path: Path | None = None
        self.rotated_legacy_format: str | None = None
        self.rotation_entry: CoreLedgerEntry | None = None
        self._held_ledger: _HeldFile | None = None
        self._held_lock: _HeldFile | None = None

        if self.path is None:
            self._lock_path: Path | None = None
            return

        _reject_symlink_path(self.path)
        if self.path.exists() and self.path.is_dir():
            raise LedgerIntegrityError(f"Audit ledger path '{self.path}' is a directory.")

        self.path.parent.mkdir(parents=True, exist_ok=True)
        _reject_symlink_path(self.path)
        self._lock_path = self.path.with_name(self.path.name + ".lock")
        _reject_symlink_path(self._lock_path)

        with _exclusive_lock(self._lock_path):
            raw = self.path.read_bytes() if self.path.exists() else b""
            if raw:
                check = verify_ledger_bytes_core(raw, anchor=anchor)
                if check.valid and check.ledger_format == "v2":
                    self._next_seq = check.entry_count
                    self._prev_hash = check.last_hash if check.last_hash is not None else GENESIS_PREV_HASH
                    self._known_size = len(raw)
                    self._known_tail = raw[raw.rfind(b"\n", 0, len(raw) - 1) + 1 :]
                elif check.valid and check.ledger_format in ("v1_airlock", "v1_gateway"):
                    rotated_format = check.ledger_format
                    rotated_sha = hashlib.sha256(raw).hexdigest()
                    rotated = _rotate_aside(self.path, tag="v1", now_fn=self._now_fn)
                    self.rotated_legacy_path = rotated
                    self.rotated_legacy_format = rotated_format
                    factory = rotation_event_factory or _default_rotation_event
                    self.rotation_entry = self._append_locked(
                        factory(rotated, rotated_format, rotated_sha),
                        source=self.source,
                        pre_sanitized=False,
                    )
                elif not check.valid and anchor is None and is_legacy_unchained_bytes(raw):
                    rotated_sha = hashlib.sha256(raw).hexdigest()
                    rotated = _rotate_aside(self.path, tag="pre-chain", now_fn=self._now_fn)
                    self.rotated_legacy_path = rotated
                    self.rotated_legacy_format = "pre_chain"
                    factory = rotation_event_factory or _default_rotation_event
                    self.rotation_entry = self._append_locked(
                        factory(rotated, "pre_chain", rotated_sha),
                        source=self.source,
                        pre_sanitized=False,
                    )
                else:
                    raise LedgerIntegrityError(
                        f"Refusing to append to tampered audit ledger '{self.path}': {check.reason}"
                    )
            else:
                if anchor is not None:
                    raise LedgerIntegrityError(
                        f"Refusing empty/missing audit ledger '{self.path}': anchor expects seq {anchor[0]}."
                    )
                if create_empty:
                    fd = _open_private_fd(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
                    os.close(fd)

        if keep_open:
            self._held_ledger = _HeldFile(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND)
            self._held_lock = _HeldFile(self._lock_path, os.O_RDWR | os.O_CREAT)

    @property
    def next_seq(self) -> int:
        return self._next_seq

    @property
    def prev_hash(self) -> str:
        return self._prev_hash

    @property
    def head(self) -> LedgerAnchor | None:
        return None if self._next_seq == 0 else (self._next_seq - 1, self._prev_hash)

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        with self._thread_lock:
            if self._sink is not None and not self._closed:
                close_fn = getattr(self._sink, "close", None)
                if callable(close_fn):
                    close_fn()
            for held in (self._held_ledger, self._held_lock):
                if held is not None:
                    held.close()
            self._closed = True

    def flush(self) -> None:
        with self._thread_lock:
            if self._sink is not None and not self._closed:
                self._sink.flush()

    def _file_unchanged_since_last_write(self) -> bool:
        if self.path is None or not self.path.exists():
            return self._known_size == 0
        size = self.path.stat().st_size
        if size != self._known_size:
            return False
        if not self._known_tail:
            return True
        with self.path.open("rb") as fh:
            fh.seek(size - len(self._known_tail))
            return fh.read(len(self._known_tail)) == self._known_tail

    def _fd_unchanged_since_last_write(self, fd: int) -> bool:
        """`_file_unchanged_since_last_write`, read through the append handle so each append opens the file once."""
        size = os.fstat(fd).st_size
        if size != self._known_size:
            return False
        if not self._known_tail:
            return True
        os.lseek(fd, size - len(self._known_tail), os.SEEK_SET)
        return os.read(fd, len(self._known_tail)) == self._known_tail

    def _adopt_verified_tail(self, *, anchor: LedgerAnchor | None) -> None:
        if self.path is None:
            return
        _reject_symlink_path(self.path)
        check = verify_ledger_file_core(self.path, anchor=anchor)
        if not check.valid or (check.entry_count > 0 and check.ledger_format != "v2"):
            raise LedgerIntegrityError(
                f"Refusing to append to tampered audit ledger '{self.path}': "
                f"{check.reason or 'unexpected ledger format.'}"
            )
        self._next_seq = check.entry_count
        self._prev_hash = check.last_hash if check.last_hash is not None else GENESIS_PREV_HASH

    def _append_locked(
        self,
        event_dict: JsonObject,
        *,
        source: str,
        pre_sanitized: bool,
    ) -> CoreLedgerEntry:
        safe_event = (
            event_dict
            if pre_sanitized
            else _sanitize_json_event(
                event_dict,
                canary_tokens=self.canary_tokens,
                extra_redactor=self._extra_redactor,
            )
        )
        canonical_event = cast(JsonObject, json.loads(canonical_json_bytes(safe_event).decode("utf-8")))

        if self.path is None:
            return self._write_entry(canonical_event, source=source, fd=None, size_before=0)

        # One open per append: the tail check, the write and the fsync all use this handle. Reopening the file to
        # compare its tail cost about 8 ms per append on Windows.
        if self._held_ledger is not None:
            fd = self._held_ledger.get()  # re-checks symlinks and file identity
            if not self._fd_unchanged_since_last_write(fd):
                self._adopt_verified_tail(anchor=self.head)
            return self._write_entry(canonical_event, source=source, fd=fd, size_before=os.fstat(fd).st_size)

        _reject_symlink_path(self.path)
        fd = _open_private_fd(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND)
        try:
            if not self._fd_unchanged_since_last_write(fd):
                self._adopt_verified_tail(anchor=self.head)
            return self._write_entry(canonical_event, source=source, fd=fd, size_before=os.fstat(fd).st_size)
        finally:
            os.close(fd)

    def _write_entry(
        self,
        canonical_event: JsonObject,
        *,
        source: str,
        fd: int | None,
        size_before: int,
    ) -> CoreLedgerEntry:
        seq = self._next_seq
        prev_hash = self._prev_hash
        entry_hash = sha256_canonical(
            {
                "schema_version": LEDGER_SCHEMA_VERSION,
                "seq": seq,
                "prev_hash": prev_hash,
                "source": source,
                "event": canonical_event,
            }
        )
        entry_obj: JsonObject = {
            "schema_version": LEDGER_SCHEMA_VERSION,
            "seq": seq,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
            "source": source,
            "event": canonical_event,
        }
        line_bytes = encode_ledger_line(entry_obj)
        line_text = line_bytes.decode("utf-8")

        # Hard defense-in-depth invariant: refuse to flush if any canary form survived sanitization.
        for canary in self.canary_tokens:
            if canary in line_text or canary_present(line_text, canary) or canary_present_in_json(entry_obj, canary):
                raise RuntimeError("Audit redaction invariant violated: canary value survived sanitization.")

        if fd is not None:
            payload_line = line_bytes + b"\n"
            view = memoryview(payload_line)
            while view:
                written = os.write(fd, view)  # O_APPEND: always at the end, whatever the read offset
                view = view[written:]
            os.fsync(fd)
            self._known_size = size_before + len(payload_line)
            self._known_tail = payload_line
        elif self._sink is not None:
            self._sink.write(line_text + "\n")
            self._sink.flush()

        self._next_seq = seq + 1
        self._prev_hash = entry_hash
        return CoreLedgerEntry(
            schema_version=LEDGER_SCHEMA_VERSION,
            seq=seq,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
            source=source,
            event=canonical_event,
        )

    def append(
        self,
        event_dict: JsonObject,
        *,
        source: str | None = None,
        pre_sanitized: bool = False,
    ) -> CoreLedgerEntry:
        """Sanitize, chain, verify zero canary leakage, persist, and fsync one v2 ledger entry."""
        eff_source = self.source if source is None else source
        if eff_source not in LEDGER_SOURCES:
            raise ValueError(f"Unsupported ledger source: {eff_source!r}")
        if self._closed:
            raise LedgerIntegrityError("Audit ledger handle is closed.")

        with self._thread_lock:
            if self._held_lock is not None:
                with _locked_fd(self._held_lock.get()):
                    return self._append_locked(event_dict, source=eff_source, pre_sanitized=pre_sanitized)
            if self._lock_path is not None:
                with _exclusive_lock(self._lock_path):
                    return self._append_locked(event_dict, source=eff_source, pre_sanitized=pre_sanitized)
            return self._append_locked(event_dict, source=eff_source, pre_sanitized=pre_sanitized)


class AuditLedger:
    """
    Append-only, redacted, hash-chained `schema_version = 2` Airlock flight recorder (`audit.jsonl`).

    Backed by `CoreAuditLedger(source="airlock")` with Pydantic `ZoneEvent` / `AuditLedgerEntry` contracts.
    """

    def __init__(
        self,
        path: Path,
        *,
        canary_tokens: tuple[str, ...] = (),
        redactor: Callable[[str], str] | None = None,
        anchor: LedgerAnchor | None = None,
    ) -> None:
        self._core = CoreAuditLedger(
            path,
            source="airlock",
            canary_tokens=canary_tokens,
            redactor=redactor,
            anchor=anchor,
            create_empty=False,
        )
        self.path = path
        self.canary_tokens = self._core.canary_tokens

    @property
    def next_seq(self) -> int:
        return self._core.next_seq

    @property
    def prev_hash(self) -> str:
        return self._core.prev_hash

    @property
    def head(self) -> LedgerAnchor | None:
        """`(seq, entry_hash)` of the last entry this instance knows of; persist outside the file as an anchor."""
        return self._core.head

    @property
    def rotated_legacy_path(self) -> Path | None:
        return self._core.rotated_legacy_path

    @property
    def rotated_legacy_format(self) -> str | None:
        return self._core.rotated_legacy_format

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
        from mellyn.core.schemas import AuditLedgerEntry, ZoneEvent

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
            extra_redactor=self._core._extra_redactor,
        )
        canonical_event_obj = json.loads(
            canonical_json_bytes(cast(JsonObject, safe_event.model_dump(mode="json"))).decode("utf-8")
        )
        canonical_event = ZoneEvent.model_validate(canonical_event_obj)
        entry = self._core.append(
            cast(JsonObject, canonical_event.model_dump(mode="json")),
            source="airlock",
            pre_sanitized=True,
        )
        return AuditLedgerEntry(
            schema_version=LEDGER_SCHEMA_VERSION,
            seq=entry.seq,
            prev_hash=entry.prev_hash,
            entry_hash=entry.entry_hash,
            source="airlock",
            event=canonical_event,
        )
