"""
Stdlib obfuscated canary, secret, and blocked-pattern scanner for Mellyn Security Control Plane.

Imports strictly from the Python standard library so both container builds and local CLI installs share
one zero-dependency, fail-closed egress/telemetry scanner without circular imports.
"""

from __future__ import annotations

import base64
import binascii
import functools
import hashlib
import re
import sys
import unicodedata
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

SECRET_REDACTION_PATTERNS: tuple[re.Pattern[str], ...] = (
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
)

KNOWN_SECRET_RULE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("openai-api-key", re.compile(r"sk-(?:proj|svcacct|None)-[A-Za-z0-9_-]{10,}|sk-[A-Za-z0-9]{48}")),
    ("anthropic-api-key", re.compile(r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{10,}")),
    ("google-gemini-api-key", re.compile(r"AIza[0-9A-Za-z_-]{20,}")),
    ("huggingface-access-token", re.compile(r"hf_[A-Za-z0-9]{20,}")),
    ("langsmith-api-key", re.compile(r"lsv2_(?:pt|sk)_[a-f0-9]{16,}_[a-f0-9]{6,}")),
    ("github-token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("github-pat", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("aws-access-key", re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")),
    ("slack-token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{16,}")),
    ("stripe-live-key", re.compile(r"(?:sk|rk)_live_[0-9A-Za-z]{16,}")),
    ("http-auth-header", re.compile(r"(?i)(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}")),
    (
        "private-key-pem",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:(?!-----BEGIN )[\s\S])*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
    ),
)

_URL_USERINFO_SECRET_RE = re.compile(r"(?<![A-Za-z0-9+.-])([A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+(@)")
_INVISIBLE_UNICODE_RE = re.compile(
    r"[\u034f\u115f\u1160\u17b4\u17b5\u180b-\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f"
    r"\u2800\u3164\ufeff\uffa0\ufe00-\ufe0f\U000e0000-\U000e007f\U000e0100-\U000e01ef]"
)
_NON_ALNUM_RE = re.compile(r"[^A-Za-z0-9]+")
_HEX_CANDIDATE_RE = re.compile(r"[0-9A-Fa-f]{16,}")
_HEX_SECRET_CANDIDATE_RE = re.compile(r"[0-9A-Fa-f]{32,}")
_DELIMITED_HEX_CANDIDATE_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:\-\s]+){7,}[0-9A-Fa-f]{2}")
_B64_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_ESCAPE_SEQUENCE_RE = re.compile(r"\\(?:x([0-9A-Fa-f]{2})|u\{([0-9A-Fa-f]{1,6})\}|u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8}))")
_SECRET_DELIMITED_HEX_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:\-\s,]+){15,}[0-9A-Fa-f]{2}")
_SECRET_0X_HEX_RE = re.compile(r"(?:0[xX][0-9A-Fa-f]{2}[\s,]*){16,}")
_SECRET_DECIMAL_RE = re.compile(r"(?<![\d.])(?:\d{1,3}[\s,;]+){15,}\d{1,3}")
_SECRET_B64_RE = re.compile(r"[A-Za-z0-9+/_-]{20,}={0,2}")
_NON_HEX_RE = re.compile(r"[^0-9A-Fa-f]")
_OX_BYTE_RE = re.compile(r"0[xX]([0-9A-Fa-f]{2})")

SPLIT_COVERAGE_MIN_CANARY_CHARS = 16
_HEX_ALPHABET = frozenset("0123456789abcdef")
_SPLIT_SCAN_CHUNK_CHARS = 65_536
_MAX_SCAN_DEPTH = 64


@dataclass(frozen=True)
class ScannerConfig:
    """Configuration for deterministic obfuscated canary, secret, and regex payload scanning."""

    canary_tokens: tuple[str, ...] = ()
    block_known_secrets: bool = True
    aad_kill_on_leak: bool = True
    blocked_patterns: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for idx, pattern in enumerate(self.blocked_patterns):
            if not isinstance(pattern, str) or not pattern:
                raise ValueError(f"blocked_patterns[{idx}] must be a non-empty regex string.")
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"Invalid regex in blocked_patterns[{idx}]: {exc}") from exc


@dataclass(frozen=True)
class ScanFinding:
    """Redacted finding record (holds only rule IDs, field path, and SHA-256 digest of matched text)."""

    kind: str
    rule_id: str
    field_path: str
    match_sha256: str


@dataclass(frozen=True)
class ScanResult:
    """Summary of scanning a request or response payload."""

    clean: bool
    canary_matched: bool
    secret_matched: bool
    blocked_pattern_matched: bool
    findings: tuple[ScanFinding, ...]


def strip_invisible_unicode(text: str) -> str:
    """Remove invisible tag, zero-width, bidi override, variation selector, and filler codepoints."""
    return _INVISIBLE_UNICODE_RE.sub("", text)


def _has_invisible_unicode(value: Any) -> bool:
    stack: list[Any] = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            if _INVISIBLE_UNICODE_RE.search(node) is not None:
                return True
        elif isinstance(node, list | tuple):
            stack.extend(node)
        elif isinstance(node, dict):
            for key, val in node.items():
                stack.append(str(key))
                stack.append(val)
    return False


def invisible_unicode_tools(entries: Sequence[Any]) -> list[str]:
    """
    Labels of tool or resource definitions containing invisible format/tag characters anywhere, keys included.

    Such characters hide text from a human reviewer while the model still reads it, so a definition carrying them is
    treated as pre-poisoned: refused when pinning and blocked when listed.
    """
    flagged: list[str] = []
    for idx, entry in enumerate(entries):
        if _has_invisible_unicode(entry):
            raw_name = entry.get("name") if isinstance(entry, dict) else None
            label = raw_name if isinstance(raw_name, str) and not _has_invisible_unicode(raw_name) else f"#{idx}"
            flagged.append(repr(label))
    return flagged


def normalize_scan_text(text: str) -> str:
    """Normalize text for stricter detection checks (never for relaxing allow rules)."""
    return unicodedata.normalize("NFKC", strip_invisible_unicode(text))


def _hash_match(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def _unescape_text(text: str) -> str | None:
    if "\\" not in text:
        return None

    def _sub(m: re.Match[str]) -> str:
        code = int(next(g for g in m.groups() if g is not None), 16)
        return chr(code) if code <= sys.maxunicode else m.group(0)

    out = _ESCAPE_SEQUENCE_RE.sub(_sub, text)
    return out if out != text else None


def _compile_obfuscated_canary_regex(norm_canary: str) -> re.Pattern[str]:
    if not norm_canary:
        return re.compile("$^")
    gap = (
        r"[\u034f\u115f\u1160\u17b4\u17b5\u180b-\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f"
        r"\u2800\u3164\ufeff\uffa0\ufe00-\ufe0f\U000e0000-\U000e007f\U000e0100-\U000e01ef]*"
    )
    escaped_chars = [re.escape(ch) for ch in norm_canary]
    return re.compile(gap.join(escaped_chars), re.IGNORECASE)


@dataclass(frozen=True)
class _CanarySignature:
    norm_canary: str
    folded: str
    obfuscated_re: re.Pattern[str]
    reversed_folded: str | None
    hex_lower: str | None
    hex_reversed: str | None
    delimited_hex_re: re.Pattern[str] | None
    ox_hex_re: re.Pattern[str] | None
    decimal_re: re.Pattern[str] | None
    b64_slices: tuple[str, ...]
    b64_reversed_slices: tuple[str, ...]
    b32_slices: tuple[str, ...]
    alnum_skeleton: str | None


@functools.lru_cache(maxsize=256)
def _canary_signature(norm_canary: str) -> _CanarySignature:
    folded = norm_canary.casefold()
    raw_bytes = norm_canary.encode("utf-8")
    hex_lower = raw_bytes.hex() if len(raw_bytes) >= 6 else None
    hex_reversed = hex_lower[::-1] if (hex_lower is not None and len(norm_canary) >= 8) else None
    delimited_hex_re = (
        re.compile(r"[:\-\s]+".join(f"{b:02x}" for b in raw_bytes), re.IGNORECASE) if len(norm_canary) >= 8 else None
    )
    ox_hex_re = (
        re.compile(r"[\s,]+".join(f"0x{b:02x}" for b in raw_bytes), re.IGNORECASE) if len(norm_canary) >= 8 else None
    )
    decimal_re = (
        re.compile(r"(?<!\d)" + r"[\s,;]+".join(str(b) for b in raw_bytes) + r"(?!\d)")
        if len(norm_canary) >= 8
        else None
    )
    b64_slices: list[str] = []
    seen_b64: set[str] = set()
    for enc_fn in (base64.b64encode, base64.urlsafe_b64encode):
        for offset in (0, 1, 2):
            padded = (b"\x00" * offset) + raw_bytes
            unpadded = enc_fn(padded).decode("ascii").rstrip("=")
            lead = 0 if offset == 0 else (2 if offset == 1 else 3)
            trail = 0 if (len(padded) % 3 == 0) else 1
            end = len(unpadded) - trail if trail else len(unpadded)
            inv = unpadded[lead:end]
            if len(inv) >= 12 and inv not in seen_b64:
                seen_b64.add(inv)
                b64_slices.append(inv)
    b64_reversed_slices = tuple(sl[::-1] for sl in b64_slices)

    b32_slices: list[str] = []
    seen_b32: set[str] = set()
    for offset in (0, 1, 2, 3, 4):
        padded = (b"\x00" * offset) + raw_bytes
        unpadded = base64.b32encode(padded).decode("ascii").rstrip("=")
        lead = (offset * 8 + 4) // 5
        trail = 0 if (len(padded) % 5 == 0) else 1
        end = len(unpadded) - trail if trail else len(unpadded)
        inv = unpadded[lead:end]
        if len(inv) >= 12 and inv not in seen_b32:
            seen_b32.add(inv)
            b32_slices.append(inv)

    skel = _NON_ALNUM_RE.sub("", norm_canary).casefold()
    alnum_skeleton = skel if len(skel) >= 8 else None
    return _CanarySignature(
        norm_canary=norm_canary,
        folded=folded,
        obfuscated_re=_compile_obfuscated_canary_regex(norm_canary),
        reversed_folded=norm_canary[::-1].casefold() if len(norm_canary) >= 8 else None,
        hex_lower=hex_lower,
        hex_reversed=hex_reversed,
        delimited_hex_re=delimited_hex_re,
        ox_hex_re=ox_hex_re,
        decimal_re=decimal_re,
        b64_slices=tuple(b64_slices),
        b64_reversed_slices=b64_reversed_slices,
        b32_slices=tuple(b32_slices),
        alnum_skeleton=alnum_skeleton,
    )


def _match_plain_forms(norm: str, sig: _CanarySignature) -> bool:
    norm_folded = norm.casefold()
    if sig.folded in norm_folded:
        return True
    if sig.reversed_folded is not None and sig.reversed_folded in norm_folded:
        return True
    if sig.alnum_skeleton is not None and sig.alnum_skeleton in _NON_ALNUM_RE.sub("", norm).casefold():
        return True
    return False


def _canary_present_plain(text: str, sig: _CanarySignature) -> bool:
    norm = normalize_scan_text(text)
    if _match_plain_forms(norm, sig):
        return True
    if "%" in norm:
        u1 = normalize_scan_text(unquote(norm))
        if _match_plain_forms(u1, sig):
            return True
        if "%" in u1:
            u2 = normalize_scan_text(unquote(u1))
            if _match_plain_forms(u2, sig):
                return True
    return False


def _decoded_contains_canary(decoded: str, sig: _CanarySignature, depth: int) -> bool:
    if not decoded:
        return False
    if depth >= 1:
        return _canary_present_plain(decoded, sig)
    return _canary_present_in_variant(normalize_scan_text(decoded), sig, _depth=depth + 1)


def _canary_present_in_variant(norm: str, sig: _CanarySignature, *, _depth: int = 0) -> bool:
    if _canary_present_plain(norm, sig):
        return True
    norm_folded = norm.casefold()
    if sig.hex_lower is not None and sig.hex_lower in norm_folded:
        return True
    if sig.hex_reversed is not None and sig.hex_reversed in norm_folded:
        return True
    if sig.delimited_hex_re is not None and sig.delimited_hex_re.search(norm) is not None:
        return True
    if sig.ox_hex_re is not None and sig.ox_hex_re.search(norm) is not None:
        return True
    if sig.decimal_re is not None and sig.decimal_re.search(norm) is not None:
        return True
    if any(sl in norm for sl in sig.b64_slices):
        return True
    if any(sl in norm for sl in sig.b64_reversed_slices):
        return True
    if sig.b32_slices:
        norm_upper = norm.upper()
        if any(sl in norm_upper for sl in sig.b32_slices):
            return True

    if any(ch.isspace() for ch in norm):
        compact_ws = "".join(norm.split())
        compact_folded = compact_ws.casefold()
        if sig.hex_lower is not None and sig.hex_lower in compact_folded:
            return True
        if sig.hex_reversed is not None and sig.hex_reversed in compact_folded:
            return True
        if any(sl in compact_ws for sl in sig.b64_slices) or any(sl in compact_ws for sl in sig.b64_reversed_slices):
            return True
        if sig.b32_slices and any(sl in compact_ws.upper() for sl in sig.b32_slices):
            return True

    for m in _HEX_CANDIDATE_RE.finditer(norm):
        tok = m.group(0)
        candidates = (tok,) if len(tok) % 2 == 0 else (tok[:-1], tok[1:])
        for cand in candidates:
            try:
                decoded = bytes.fromhex(cand).decode("utf-8", errors="ignore")
            except ValueError:
                continue
            if _decoded_contains_canary(decoded, sig, _depth):
                return True

    for m in _DELIMITED_HEX_CANDIDATE_RE.finditer(norm):
        compact = re.sub(r"[:\-\s]+", "", m.group(0))
        if len(compact) % 2 != 0:
            compact = compact[:-1]
        try:
            decoded = bytes.fromhex(compact).decode("utf-8", errors="ignore")
        except ValueError:
            continue
        if _decoded_contains_canary(decoded, sig, _depth):
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
            if _decoded_contains_canary(decoded, sig, _depth):
                return True

    return False


def canary_present_in_text(text: str, canary: str) -> bool:
    """Detect raw, obfuscated, encoded, reversed, or separator-interleaved canary variants in `text`."""
    norm_canary = normalize_scan_text(canary)
    if not norm_canary:
        return False
    sig = _canary_signature(norm_canary)
    norm = normalize_scan_text(text)
    if _canary_present_in_variant(norm, sig):
        return True
    if "%" in norm:
        u1 = normalize_scan_text(unquote(norm))
        if _canary_present_in_variant(u1, sig):
            return True
        if "%" in u1 and _canary_present_in_variant(normalize_scan_text(unquote(u1)), sig):
            return True
    unescaped = _unescape_text(norm)
    if unescaped is not None and _canary_present_in_variant(normalize_scan_text(unescaped), sig):
        return True
    return False


def redact_canaries_in_text(text: str, canary_tokens: Sequence[str]) -> str:
    """Redact any raw, invisible-obfuscated, or encoded occurrence of `canary_tokens` before persisting telemetry."""
    sanitized = text
    for canary in canary_tokens:
        if not canary:
            continue
        norm_canary = normalize_scan_text(canary)
        if not norm_canary:
            continue
        if not (canary in sanitized or canary_present_in_text(sanitized, canary)):
            continue
        sanitized = sanitized.replace(canary, "[REDACTED_CANARY]")
        sanitized = _canary_signature(norm_canary).obfuscated_re.sub("[REDACTED_CANARY]", sanitized)
        if canary in sanitized or canary_present_in_text(sanitized, canary):
            sanitized = "[REDACTED_CANARY]"
    return sanitized


def _hex_token_texts(tok: str) -> Iterator[str]:
    hex_digits = _NON_HEX_RE.sub("", tok)
    candidates = (hex_digits,) if len(hex_digits) % 2 == 0 else (hex_digits[:-1], hex_digits[1:])
    for cand in candidates:
        try:
            yield bytes.fromhex(cand).decode("utf-8", errors="ignore")
        except ValueError:
            continue


def _ox_hex_token_texts(tok: str) -> Iterator[str]:
    yield bytes.fromhex("".join(_OX_BYTE_RE.findall(tok))).decode("utf-8", errors="ignore")


def _decimal_token_texts(tok: str) -> Iterator[str]:
    values = [int(n) for n in re.findall(r"\d+", tok)]
    if all(v <= 255 for v in values):
        yield bytes(values).decode("utf-8", errors="ignore")


def _b64_token_texts(tok: str) -> Iterator[str]:
    core = tok.rstrip("=").replace("-", "+").replace("_", "/")
    for offset in (0, 1, 2, 3):
        shifted = core[offset:]
        rem = len(shifted) % 4
        if rem == 1:
            shifted = shifted[:-1]
        elif rem:
            shifted += "=" * (4 - rem)
        try:
            yield base64.b64decode(shifted, validate=False).decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            continue


_ENCODED_SECRET_DECODERS: tuple[tuple[re.Pattern[str], Callable[[str], Iterator[str]]], ...] = (
    (_SECRET_0X_HEX_RE, _ox_hex_token_texts),
    (_SECRET_DECIMAL_RE, _decimal_token_texts),
    (_SECRET_DELIMITED_HEX_RE, _hex_token_texts),
    (_HEX_SECRET_CANDIDATE_RE, _hex_token_texts),
    (_SECRET_B64_RE, _b64_token_texts),
)


def _match_secret_variants(
    text: str,
    *,
    field_path: str,
    findings: list[ScanFinding],
    check_encoded: bool,
) -> bool:
    hit = False
    for m in _URL_USERINFO_SECRET_RE.finditer(text):
        hit = True
        findings.append(
            ScanFinding(
                kind="secret",
                rule_id="url-userinfo-password",
                field_path=field_path,
                match_sha256=_hash_match(m.group(0)),
            )
        )
    for rule_id, pat in KNOWN_SECRET_RULE_PATTERNS:
        for m in pat.finditer(text):
            val = m.group(0)
            if val == "[REDACTED_SECRET]":
                continue
            hit = True
            findings.append(
                ScanFinding(kind="secret", rule_id=rule_id, field_path=field_path, match_sha256=_hash_match(val))
            )
    if check_encoded:
        for pattern, decode in _ENCODED_SECRET_DECODERS:
            for m in pattern.finditer(text):
                for decoded in decode(m.group(0)):
                    if decoded and _match_secret_variants(
                        normalize_scan_text(decoded),
                        field_path=field_path,
                        findings=findings,
                        check_encoded=False,
                    ):
                        hit = True
                        break
    return hit


def _split_fragment_length(norm_canary: str) -> int:
    return 7 if set(norm_canary.casefold()) <= _HEX_ALPHABET else 5


def _check_split_canary(leaves: Sequence[str], canary: str) -> bool:
    norm_canary = normalize_scan_text(canary)
    if len(norm_canary) < SPLIT_COVERAGE_MIN_CANARY_CHARS or not leaves:
        return False

    joined_norm = "".join(normalize_scan_text(piece) for piece in leaves)
    if joined_norm and canary_present_in_text(joined_norm, canary):
        return True

    # Order-free fragment coverage: catches 2+ field splits in arbitrary key/value order.
    folded = norm_canary.casefold()
    k = _split_fragment_length(norm_canary)
    if len(folded) < k:
        return False
    windows = {folded[i : i + k] for i in range(len(folded) - k + 1)}
    pending = set(windows)

    chunk: list[str] = []
    chunk_chars = 0

    def _flush() -> None:
        text = "\x00".join(chunk)
        for w in [w for w in pending if w in text]:
            pending.discard(w)

    for piece in leaves:
        folded_piece = normalize_scan_text(piece).casefold()
        if not folded_piece:
            continue
        chunk.append(folded_piece)
        chunk_chars += len(folded_piece)
        if chunk_chars >= _SPLIT_SCAN_CHUNK_CHARS:
            _flush()
            chunk.clear()
            chunk_chars = 0
            if not pending:
                break
    if chunk and pending:
        _flush()

    found = windows - pending
    covered = [False] * len(folded)
    for i in range(len(folded) - k + 1):
        if folded[i : i + k] in found:
            covered[i : i + k] = [True] * k
    return all(covered)


def _iter_string_leaves(payload: Any, too_deep: list[bool] | None = None) -> Iterator[tuple[str, str]]:
    """
    Yield every string in `payload`, at any depth. The walk uses an explicit stack, so depth costs no recursion.

    Nesting beyond `_MAX_SCAN_DEPTH` is still scanned (skipping it let a canary through unseen) and is reported in
    `too_deep`, so the caller can refuse the payload as well.
    """
    stack: list[tuple[str, Any, int]] = [("$", payload, 0)]
    while stack:
        path, node, depth = stack.pop()
        if depth > _MAX_SCAN_DEPTH and too_deep is not None and not too_deep:
            too_deep.append(True)
        if isinstance(node, str):
            yield path, node
        elif isinstance(node, list | tuple):
            for idx in range(len(node) - 1, -1, -1):
                stack.append((f"{path}[{idx}]", node[idx], depth + 1))
        elif isinstance(node, dict):
            items = list(node.items())
            for key, val in reversed(items):
                child_path = f"{path}.{key}"
                stack.append((child_path, val, depth + 1))
                if isinstance(key, str):
                    stack.append((f"{child_path}#key", key, depth + 1))


def scan_value(payload: Any, config: ScannerConfig) -> ScanResult:
    """Scan nested JSON/Python payloads for canaries, known secrets, and custom blocked patterns."""
    findings: list[ScanFinding] = []
    canary_hit = False
    secret_hit = False
    blocked_hit = False

    compiled_blocked = tuple((f"blocked-{idx}", re.compile(pat)) for idx, pat in enumerate(config.blocked_patterns))
    leaves: list[str] = []
    too_deep: list[bool] = []

    for field_path, raw_text in _iter_string_leaves(payload, too_deep):
        leaves.append(raw_text)
        if not raw_text:
            continue

        norm = normalize_scan_text(raw_text)
        pct1 = normalize_scan_text(unquote(norm)) if "%" in norm else None
        pct2 = normalize_scan_text(unquote(pct1)) if (pct1 is not None and "%" in pct1) else None
        unescaped = _unescape_text(norm)
        unesc_norm = normalize_scan_text(unescaped) if unescaped is not None else None
        variants = tuple(v for v in (raw_text, norm, pct1, pct2, unesc_norm) if v is not None)

        for idx, canary in enumerate(config.canary_tokens):
            if not canary:
                continue
            if canary_present_in_text(raw_text, canary):
                canary_hit = True
                findings.append(
                    ScanFinding(
                        kind="canary",
                        rule_id=f"canary-{idx}",
                        field_path=field_path,
                        match_sha256=_hash_match(canary),
                    )
                )

        if config.block_known_secrets:
            checked_variants: set[str] = set()
            for var in variants:
                if var in checked_variants:
                    continue
                checked_variants.add(var)
                if _match_secret_variants(
                    var,
                    field_path=field_path,
                    findings=findings,
                    check_encoded=(var == raw_text or var == norm),
                ):
                    secret_hit = True
                    break

        for rule_id, pat in compiled_blocked:
            matched_obj = pat.search(raw_text) or pat.search(norm)
            if matched_obj is not None:
                blocked_hit = True
                findings.append(
                    ScanFinding(
                        kind="blocked_pattern",
                        rule_id=rule_id,
                        field_path=field_path,
                        match_sha256=_hash_match(matched_obj.group(0)),
                    )
                )

    if len(leaves) > 1:
        for idx, canary in enumerate(config.canary_tokens):
            if canary and _check_split_canary(leaves, canary):
                canary_hit = True
                findings.append(
                    ScanFinding(
                        kind="canary",
                        rule_id=f"canary-{idx}-split",
                        field_path="$",
                        match_sha256=_hash_match(canary),
                    )
                )

    if too_deep:
        # No legitimate MCP payload nests this deep; one that does is treated as an evasion attempt and blocked.
        blocked_hit = True
        findings.append(
            ScanFinding(kind="structure", rule_id="nesting-too-deep", field_path="$", match_sha256=_hash_match(""))
        )

    return ScanResult(
        clean=not (canary_hit or secret_hit or blocked_hit),
        canary_matched=canary_hit,
        secret_matched=secret_hit,
        blocked_pattern_matched=blocked_hit,
        findings=tuple(findings),
    )
