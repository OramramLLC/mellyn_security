"""
Unified standard-library scanning and redaction core for Mellyn Security.

Shared single source of truth used by `mellyn.egress.scanner` (Airlock), `mellyn.scanner`
(Gateway/Authorizer), `mellyn.core.audit` (Airlock ledger), and `mellyn.audit` (Gateway ledger).

Strict DAG & bare-venv invariant: imports ONLY from the Python standard library and `mellyn.core.normalize`.
"""

from __future__ import annotations

import base64
import binascii
import functools
import hashlib
import math
import re
import sys
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

from mellyn.core.normalize import (
    JsonValue,
    has_invisible_unicode,
    normalize_str,
    strip_invisible,
)

KNOWN_SECRET_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "url-userinfo-password",
        # The lookbehind makes a scheme start only at a token boundary; without it every letter of a long word
        # starts a new attempt and the scan becomes quadratic.
        re.compile(r"(?<![A-Za-z0-9+-])[A-Za-z][A-Za-z0-9+-]*://[^/\s:@]+:([^@\s/]+)@"),
    ),
    (
        "openai-api-key",
        re.compile(r"sk-(?:proj|svcacct|None)-[A-Za-z0-9_-]{10,}|sk-[A-Za-z0-9]{48}"),
    ),
    (
        "anthropic-api-key",
        re.compile(r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{10,}"),
    ),
    (
        "google-gemini-api-key",
        re.compile(r"AIza[0-9A-Za-z_-]{20,}"),
    ),
    (
        "huggingface-access-token",
        re.compile(r"hf_[A-Za-z0-9]{20,}"),
    ),
    (
        "langsmith-api-key",
        re.compile(r"lsv2_(?:pt|sk)_[a-f0-9]{16,}_[a-f0-9]{6,}"),
    ),
    (
        "github-token",
        re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    ),
    (
        "github-pat",
        re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    ),
    (
        "aws-access-key",
        re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    ),
    (
        "slack-token",
        re.compile(r"xox[baprs]-[0-9A-Za-z-]{16,}"),
    ),
    (
        "stripe-live-key",
        re.compile(r"(?:sk|rk)_live_[0-9A-Za-z]{16,}"),
    ),
    (
        "private-key-pem",
        # The body may not cross another BEGIN header, so many unterminated headers stay linear to scan.
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:(?!-----BEGIN )[\s\S])*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
    ),
    (
        "http-auth-header",
        re.compile(r"(?i:(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,})"),
    ),
)

SECRET_REDACTION_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    pat for rule_id, pat in KNOWN_SECRET_RULES if rule_id != "url-userinfo-password"
)
_FAST_SECRET_PREFILTER_RE = re.compile(
    "|".join(
        f"(?:{pat.pattern})"
        for rule_id, pat in KNOWN_SECRET_RULES
        if rule_id not in ("url-userinfo-password", "private-key-pem")
    )
)
_URL_USERINFO_SECRET_RE = re.compile(r"(?<![A-Za-z0-9+-])([A-Za-z][A-Za-z0-9+-]*://[^/\s:@]+:)[^@\s/]+(@)")
_INVISIBLE_UNICODE_RE = re.compile(
    r"[\u034f\u115f\u1160\u17b4\u17b5\u180b-\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f"
    r"\u2800\u3164\ufeff\uffa0\ufe00-\ufe0f\U000e0000-\U000e007f\U000e0100-\U000e01ef]"
)

_CREDENTIAL_ASSIGN_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|token|secret|password|passwd|auth_token|access_key|bearer)\b"
    r"""\s*[:=]\s*["']?([A-Za-z0-9._~+/=-]{16,})["']?"""
)
_OPAQUE_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_+/=.-])([A-Za-z0-9_+/=-]{20,})(?![A-Za-z0-9_+/=.-])")
_JWT_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_+/=-])(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{10,})(?![A-Za-z0-9_+/=-])"
)
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_HEX_ONLY_RE = re.compile(r"^[0-9a-fA-F]+$")
_REDACTION_PLACEHOLDERS: frozenset[str] = frozenset(
    {"REDACTED_CANARY", "REDACTED_SECRET", "REDACTED_BLOCKED", "REDACTED_HIGH_ENTROPY"}
)
_FULL_REDACTION_PLACEHOLDERS: frozenset[str] = frozenset(
    {"[REDACTED_CANARY]", "[REDACTED_SECRET]", "[REDACTED_BLOCKED]", "[REDACTED_HIGH_ENTROPY]"}
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
MAX_SCAN_DEPTH = _MAX_SCAN_DEPTH


@dataclass(frozen=True)
class ScannerConfig:
    """Configuration for deterministic obfuscated canary, secret, high-entropy, and regex payload scanning."""

    canary_tokens: tuple[str, ...] = ()
    block_known_secrets: bool = True
    aad_kill_on_leak: bool = True
    blocked_patterns: tuple[str, ...] = ()
    detect_high_entropy: bool = False
    entropy_threshold: float = 4.0
    min_entropy_length: int = 20

    def __post_init__(self) -> None:
        if not isinstance(self.detect_high_entropy, bool):
            raise ValueError("detect_high_entropy must be a boolean.")
        if (
            isinstance(self.entropy_threshold, bool)
            or not isinstance(self.entropy_threshold, int | float)
            or not math.isfinite(self.entropy_threshold)
            or self.entropy_threshold <= 0.0
        ):
            raise ValueError("entropy_threshold must be a finite number > 0.")
        if (
            isinstance(self.min_entropy_length, bool)
            or not isinstance(self.min_entropy_length, int)
            or self.min_entropy_length < 8
        ):
            raise ValueError("min_entropy_length must be an integer >= 8.")
        for idx, pattern in enumerate(self.blocked_patterns):
            if not isinstance(pattern, str) or not pattern:
                raise ValueError(f"blocked_patterns[{idx}] must be a non-empty regex string.")
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"Invalid regex in blocked_patterns[{idx}]: {exc}") from exc


@dataclass(frozen=True)
class ScanFinding:
    """Redacted finding record (holds only kind, rule ID, field path, and SHA-256 digest of matched text)."""

    kind: str
    rule_id: str
    field_path: str
    match_sha256: str


@dataclass(frozen=True)
class ScanResult:
    """Summary of scanning a request or response payload through the gateway interface."""

    clean: bool
    canary_matched: bool
    secret_matched: bool
    blocked_pattern_matched: bool
    findings: tuple[ScanFinding, ...]
    high_entropy_matched: bool = False


@dataclass(frozen=True)
class CoreScanOutcome:
    """Full scan result including redacted payload when `redact=True`."""

    clean: bool
    canary_matched: bool
    secret_matched: bool
    high_entropy_matched: bool
    blocked_pattern_matched: bool
    findings: tuple[ScanFinding, ...]
    redacted_payload: Any = None


def strip_invisible_unicode(text: str) -> str:
    """Remove invisible format, tag, variation-selector, and filler codepoints from `text`."""
    return strip_invisible(text)


def normalize_scan_text(text: str) -> str:
    """Normalize text for stricter detection checks (never for relaxing allow rules)."""
    return normalize_str(text)


def invisible_unicode_tools(entries: Sequence[Any]) -> list[str]:
    """
    Labels of tool or resource definitions containing invisible format/tag characters anywhere, keys included.

    Uses `has_invisible_unicode` so every `Cf`, tag, variation-selector, and filler character is caught without
    relying on recursion depth limits.
    """
    flagged: list[str] = []
    for idx, entry in enumerate(entries):
        if has_invisible_unicode(entry):
            raw_name = entry.get("name") if isinstance(entry, dict) else None
            label = raw_name if isinstance(raw_name, str) and not has_invisible_unicode(raw_name) else f"#{idx}"
            flagged.append(repr(label))
    return flagged


def _hash_match(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def shannon_entropy(token: str) -> float:
    """Compute Shannon entropy in bits per character for `token`."""
    if not token:
        return 0.0
    length = len(token)
    counts: dict[str, int] = {}
    for ch in token:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _character_classes(token: str) -> int:
    has_lower = has_upper = has_digit = has_other = False
    for c in token:
        if "a" <= c <= "z":
            has_lower = True
        elif "A" <= c <= "Z":
            has_upper = True
        elif "0" <= c <= "9":
            has_digit = True
        else:
            has_other = True
    return has_lower + has_upper + has_digit + has_other


def _is_high_entropy_candidate(token: str, *, threshold: float, min_length: int, contextual: bool) -> bool:
    if token in _REDACTION_PLACEHOLDERS:
        return False
    eff_min = min(min_length, 16) if contextual else min_length
    if len(token) < eff_min:
        return False
    if len(token) == 36 and _UUID_RE.fullmatch(token):
        return False
    if not contextual and token == token.lower() and _HEX_ONLY_RE.fullmatch(token):
        # Plain lowercase hex (such as SHA-256 digests) is skipped unless paired with a credential label.
        return False
    required_classes = 2 if contextual else 3
    if _character_classes(token) < required_classes:
        return False
    return shannon_entropy(token) >= threshold


def unescape_text(text: str) -> str | None:
    """Decode `\\xNN`, `\\uNNNN`, `\\u{N..}` and `\\UNNNNNNNN` escapes; `None` when there are none to decode."""
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
    alnum_skeleton = skel if (len(norm_canary) >= 8 and len(skel) >= 8) else None
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


def _match_plain_forms(norm_folded: str, sig: _CanarySignature) -> bool:
    if len(norm_folded) >= len(sig.folded) and sig.folded in norm_folded:
        return True
    if (
        sig.reversed_folded is not None
        and len(norm_folded) >= len(sig.reversed_folded)
        and sig.reversed_folded in norm_folded
    ):
        return True
    if sig.alnum_skeleton is not None and len(norm_folded) >= len(sig.alnum_skeleton):
        if sig.alnum_skeleton in _NON_ALNUM_RE.sub("", norm_folded):
            return True
    return False


def _canary_present_plain(norm: str, sig: _CanarySignature, *, check_percent: bool) -> bool:
    if _match_plain_forms(norm.casefold(), sig):
        return True
    if check_percent and "%" in norm:
        u1 = normalize_str(unquote(norm))
        if _match_plain_forms(u1.casefold(), sig):
            return True
        if "%" in u1:
            u2 = normalize_str(unquote(u1))
            if _match_plain_forms(u2.casefold(), sig):
                return True
    return False


def _decoded_contains_canary(decoded: str, sig: _CanarySignature, depth: int) -> bool:
    """Check decoded text; one more decoding layer is tried so Base64-of-hex and double Base64 are caught."""
    if not decoded:
        return False
    norm = normalize_str(decoded)
    if depth >= 1:
        return _canary_present_plain(norm, sig, check_percent=True)
    return _canary_present_in_variant(norm, sig, _depth=depth + 1)


def _canary_present_in_variant(norm: str, sig: _CanarySignature, *, _depth: int = 0) -> bool:
    norm_folded = norm.casefold()
    if _match_plain_forms(norm_folded, sig):
        return True
    if _depth > 0 and "%" in norm and _canary_present_plain(norm, sig, check_percent=True):
        return True

    norm_len = len(norm)
    if sig.hex_lower is not None and norm_len >= len(sig.hex_lower) and sig.hex_lower in norm_folded:
        return True
    if sig.hex_reversed is not None and norm_len >= len(sig.hex_reversed) and sig.hex_reversed in norm_folded:
        return True
    if sig.delimited_hex_re is not None and norm_len >= 23 and sig.delimited_hex_re.search(norm) is not None:
        return True
    if (
        sig.ox_hex_re is not None
        and norm_len >= 39
        and ("0x" in norm_folded)
        and sig.ox_hex_re.search(norm) is not None
    ):
        return True
    if sig.decimal_re is not None and norm_len >= 15 and sig.decimal_re.search(norm) is not None:
        return True
    if norm_len >= 12:
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
        compact_len = len(compact_ws)
        compact_folded = compact_ws.casefold()
        if sig.hex_lower is not None and compact_len >= len(sig.hex_lower) and sig.hex_lower in compact_folded:
            return True
        if sig.hex_reversed is not None and compact_len >= len(sig.hex_reversed) and sig.hex_reversed in compact_folded:
            return True
        if compact_len >= 12:
            if any(sl in compact_ws for sl in sig.b64_slices) or any(
                sl in compact_ws for sl in sig.b64_reversed_slices
            ):
                return True
            if sig.b32_slices and any(sl in compact_ws.upper() for sl in sig.b32_slices):
                return True

    if norm_len >= 16:
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

    if norm_len >= 23:
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

    if norm_len >= 16:
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


def _canary_present_with_sig(norm: str, sig: _CanarySignature) -> bool:
    if _canary_present_in_variant(norm, sig):
        return True
    if "%" in norm:
        u1 = normalize_str(unquote(norm))
        if _canary_present_in_variant(u1, sig):
            return True
        if "%" in u1 and _canary_present_in_variant(normalize_str(unquote(u1)), sig):
            return True
    if "\\" in norm:
        unescaped = unescape_text(norm)
        if unescaped is not None and _canary_present_in_variant(normalize_str(unescaped), sig):
            return True
    return False


@functools.lru_cache(maxsize=256)
def _normalized_canary(canary: str) -> str:
    return normalize_str(canary)


def canary_present(text: str, canary: str) -> bool:
    """
    Detect raw, NFKC/invisible-obfuscated, percent-encoded (1x/2x), escape-decoded, reversed,
    punctuation/alnum-skeleton interleaved, hex (contiguous/delimited/0x/reversed), decimal,
    Base32, and Base64/Base64url canary forms inside `text`.
    """
    norm_canary = _normalized_canary(canary)
    if not norm_canary:
        return False
    sig = _canary_signature(norm_canary)
    norm = normalize_str(text)
    return _canary_present_with_sig(norm, sig)


canary_present_in_text = canary_present


def _redact_canary_with_norm(text: str, norm_text: str, canary: str) -> tuple[str, bool]:
    if not canary:
        return text, False
    norm_canary = _normalized_canary(canary)
    raw_in = canary in text
    if not raw_in and not norm_canary:
        return text, False
    sig = _canary_signature(norm_canary) if norm_canary else None
    matched = raw_in or (sig is not None and _canary_present_with_sig(norm_text, sig))
    if not matched:
        return text, False
    sanitized = text.replace(canary, "[REDACTED_CANARY]")
    if sig is not None:
        sanitized = sig.obfuscated_re.sub("[REDACTED_CANARY]", sanitized)
        norm_after = normalize_str(sanitized)
        if canary in sanitized or _canary_present_with_sig(norm_after, sig):
            sanitized = "[REDACTED_CANARY]"
    return sanitized, True


def redact_canary_in_text(text: str, canary: str) -> tuple[str, bool]:
    """Detect and redact any plain, obfuscated, reversed, interleaved, or encoded occurrence of `canary`."""
    return _redact_canary_with_norm(text, normalize_str(text), canary)


def redact_canaries_in_text(text: str, canary_tokens: Sequence[str]) -> str:
    """Redact any raw, invisible-obfuscated, or encoded occurrence of `canary_tokens`."""
    sanitized = text
    for canary in canary_tokens:
        if canary:
            sanitized, _ = redact_canary_in_text(sanitized, canary)
    return sanitized


def _iter_json_strings(value: Any) -> Iterator[str]:
    """Yield every dict key and string value inside `value` iteratively."""
    stack: list[Any] = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            yield node
        elif isinstance(node, list | tuple):
            stack.extend(reversed(node))
        elif isinstance(node, dict):
            for k, v in reversed(list(node.items())):
                stack.append(v)
                stack.append(k if isinstance(k, str) else str(k))


def _extract_split_views_and_pieces(
    value: Any, *, max_chars: int | None = 131_072
) -> tuple[tuple[str, int], tuple[str, int], tuple[str, int], list[str], int]:
    val_parts: list[str] = []
    key_parts: list[str] = []
    both_parts: list[str] = []
    norm_pieces: list[str] = []
    val_count = key_count = both_count = total_norm_chars = 0
    budget = [max_chars, max_chars, max_chars] if max_chars is not None else None

    def _append(parts: list[str], idx: int, piece: str) -> None:
        if not piece:
            return
        if budget is None:
            parts.append(piece)
            return
        if budget[idx] <= 0:
            return
        if len(piece) > budget[idx]:
            parts.append(piece[: budget[idx]])
            budget[idx] = 0
        else:
            parts.append(piece)
            budget[idx] -= len(piece)

    stack: list[tuple[Any, bool]] = [(value, False)]
    while stack:
        node, is_key = stack.pop()
        if isinstance(node, str):
            if not node:
                continue
            norm = normalize_str(node)
            if norm:
                norm_pieces.append(norm)
                total_norm_chars += len(norm)
            both_count += 1
            if is_key:
                key_count += 1
                _append(key_parts, 1, node)
            else:
                val_count += 1
                _append(val_parts, 0, node)
            _append(both_parts, 2, node)
        elif isinstance(node, list | tuple):
            for item in reversed(node):
                stack.append((item, False))
        elif isinstance(node, dict):
            for k, v in reversed(list(node.items())):
                stack.append((v, False))
                stack.append((k if isinstance(k, str) else str(k), True))

    return (
        ("".join(val_parts), val_count),
        ("".join(key_parts), key_count),
        ("".join(both_parts), both_count),
        norm_pieces,
        total_norm_chars,
    )


def extract_split_canary_views(value: Any, *, max_chars: int = 131_072) -> tuple[str, str, str]:
    """
    Extract contiguous `(values_only, keys_only, keys_and_values)` views from nested containers iteratively
    in bounded O(n) time to detect canary tokens split across adjacent list/tuple/dict fields.
    """
    (val_view, _), (key_view, _), (both_view, _), _, _ = _extract_split_views_and_pieces(value, max_chars=max_chars)
    return val_view, key_view, both_view


def split_fragment_length(norm_canary: str) -> int:
    """Shortest canary piece the order-free split check looks for: 7 characters for hex-only canaries, else 5."""
    return 7 if set(norm_canary.casefold()) <= _HEX_ALPHABET else 5


def _split_fragments_from_normalized(norm_pieces: Sequence[str], norm_canary: str) -> bool:
    folded = norm_canary.casefold()
    k = split_fragment_length(norm_canary)
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

    for piece in norm_pieces:
        folded_piece = piece.casefold()
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


def _split_fragments_cover_canary(value: Any, norm_canary: str) -> bool:
    """
    True when every character of the canary lies inside some fragment (of at least `split_fragment_length` chars)
    found in one of the strings in `value`, regardless of piece order, interleaving, or padding size.
    """
    norm_pieces = [n for s in _iter_json_strings(value) if (n := normalize_str(s))]
    return _split_fragments_from_normalized(norm_pieces, norm_canary)


_SPLIT_VIEW_WINDOW_CHARS = 131_072


def _view_has_canary(view: str, canary: str, *, overlap_chars: int) -> bool:
    if len(view) <= _SPLIT_VIEW_WINDOW_CHARS:
        return canary_present(view, canary)
    step = max(1, _SPLIT_VIEW_WINDOW_CHARS - overlap_chars)
    for start in range(0, len(view), step):
        window = view[start : start + _SPLIT_VIEW_WINDOW_CHARS]
        if canary_present(window, canary):
            return True
        if start + _SPLIT_VIEW_WINDOW_CHARS >= len(view):
            break
    return False


def _canary_present_in_json_extracted(
    canary: str,
    *,
    val_view_info: tuple[str, int],
    key_view_info: tuple[str, int],
    both_view_info: tuple[str, int],
    norm_pieces: Sequence[str],
    total_norm_chars: int,
    include_single_piece_views: bool,
) -> bool:
    norm_canary = _normalized_canary(canary)
    if len(norm_canary) < 8:
        return False
    min_count = 1 if include_single_piece_views else 2
    candidate_views = dict.fromkeys(
        view for view, count in (val_view_info, key_view_info, both_view_info) if view and count >= min_count
    )
    overlap_chars = max(2_048, 8 * len(norm_canary))
    if any(_view_has_canary(view, canary, overlap_chars=overlap_chars) for view in candidate_views):
        return True
    return (
        len(norm_canary) >= SPLIT_COVERAGE_MIN_CANARY_CHARS
        and total_norm_chars >= len(norm_canary)
        and _split_fragments_from_normalized(norm_pieces, norm_canary)
    )


def canary_present_in_json(value: Any, canary: str) -> bool:
    """
    Detect a canary split across the strings of a list/tuple/dict.

    A `>= 8`-char canary is found when its pieces sit in adjacent entries across any supported encoding;
    a `>= 16`-char canary is also found via order-free k-gram fragment coverage.
    """
    if not isinstance(value, list | tuple | dict) or not canary:
        return False
    norm_canary = _normalized_canary(canary)
    if len(norm_canary) < 8:
        return False
    val_info, key_info, both_info, norm_pieces, total_norm_chars = _extract_split_views_and_pieces(
        value, max_chars=None
    )
    return _canary_present_in_json_extracted(
        canary,
        val_view_info=val_info,
        key_view_info=key_info,
        both_view_info=both_info,
        norm_pieces=norm_pieces,
        total_norm_chars=total_norm_chars,
        include_single_piece_views=True,
    )


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
    run: list[int] = []
    for raw_n in re.findall(r"\d+", tok):
        val = int(raw_n)
        if val <= 255:
            run.append(val)
        else:
            if len(run) >= 12:
                yield bytes(run).decode("utf-8", errors="ignore")
            run.clear()
    if len(run) >= 12:
        yield bytes(run).decode("utf-8", errors="ignore")


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


_ENCODED_SECRET_DECODERS: tuple[tuple[int, str | None, re.Pattern[str], Callable[[str], Iterator[str]]], ...] = (
    (64, "0x", _SECRET_0X_HEX_RE, _ox_hex_token_texts),
    (31, None, _SECRET_DECIMAL_RE, _decimal_token_texts),
    (47, None, _SECRET_DELIMITED_HEX_RE, _hex_token_texts),
    (32, None, _HEX_SECRET_CANDIDATE_RE, _hex_token_texts),
    (20, None, _SECRET_B64_RE, _b64_token_texts),
)


def redact_encoded_secret_tokens(text: str, is_secret: Callable[[str], bool]) -> tuple[str, bool]:
    """
    Replace each hex (contiguous, delimited, `0x`), decimal-byte, or Base64/Base64url token whose decoded text
    `is_secret` reports as a credential with `[REDACTED_SECRET]`. Returns `(text, any_replaced)`.
    """
    if len(text) < 20:
        return text, False
    hit = False
    for min_len, hint, pattern, decode in _ENCODED_SECRET_DECODERS:
        if len(text) < min_len:
            continue
        if hint is not None and hint not in text.lower():
            continue
        if pattern.search(text) is None:
            continue

        def _sub(m: re.Match[str], decode: Callable[[str], Iterator[str]] = decode) -> str:
            nonlocal hit
            for decoded in decode(m.group(0)):
                if decoded and len(decoded) >= 10 and is_secret(normalize_str(decoded)):
                    hit = True
                    return "[REDACTED_SECRET]"
            return m.group(0)

        text = pattern.sub(_sub, text)
    return text, hit


def _has_potential_known_secret(text: str) -> bool:
    return (
        ("://" in text)
        or ("-----BEGIN " in text)
        or (len(text) >= 18 and _FAST_SECRET_PREFILTER_RE.search(text) is not None)
    )


def _redact_secret_matches_in_text(
    text: str,
    *,
    field_path: str,
    findings: list[ScanFinding],
    ignore_placeholder: bool,
) -> tuple[str, bool]:
    if not _has_potential_known_secret(text):
        return text, False

    sanitized = text
    secret_hit = False
    for rule_id, pattern in KNOWN_SECRET_RULES:
        if rule_id == "url-userinfo-password" and "://" not in sanitized:
            continue
        if rule_id == "private-key-pem" and "-----BEGIN " not in sanitized:
            continue
        matches = [
            m
            for m in pattern.finditer(sanitized)
            if not (ignore_placeholder and (m.group(1) if m.lastindex else m.group(0)) == "[REDACTED_SECRET]")
        ]
        if not matches:
            continue
        secret_hit = True
        for match in matches:
            matched_val = match.group(1) if match.lastindex else match.group(0)
            findings.append(
                ScanFinding(
                    kind="secret",
                    rule_id=rule_id,
                    field_path=field_path,
                    match_sha256=_hash_match(matched_val),
                )
            )
        if rule_id == "url-userinfo-password":
            sanitized = pattern.sub(
                lambda m: (
                    m.group(0)
                    if (ignore_placeholder and m.group(1) == "[REDACTED_SECRET]")
                    else m.group(0)[: m.start(1) - m.start(0)] + "[REDACTED_SECRET]@"
                ),
                sanitized,
            )
        else:
            sanitized = pattern.sub("[REDACTED_SECRET]", sanitized)
    return sanitized, secret_hit


def _scan_secrets_all_layers(
    text: str,
    *,
    field_path: str,
    findings: list[ScanFinding],
) -> tuple[str, bool]:
    """Run all 13 secret rules across raw, normalized, 1x/2x percent-decoded, unescaped, and encoded layers."""
    sanitized, raw_hit = _redact_secret_matches_in_text(
        text,
        field_path=field_path,
        findings=findings,
        ignore_placeholder=False,
    )
    secret_hit = raw_hit
    decoded_layers: list[str] = []

    raw_norm = normalize_str(sanitized)
    if raw_norm != sanitized:
        decoded_layers.append(raw_norm)
        norm_redacted, norm_hit = _redact_secret_matches_in_text(
            raw_norm,
            field_path=field_path,
            findings=findings,
            ignore_placeholder=True,
        )
        if norm_hit:
            secret_hit = True
            sanitized = norm_redacted
            pct_base = norm_redacted
        else:
            pct_base = raw_norm
    else:
        pct_base = sanitized

    u1_for_esc: str | None = None
    if "%" in sanitized or "%" in pct_base:
        pct_source = pct_base if "%" in pct_base else sanitized
        u1 = normalize_str(unquote(pct_source))
        u1_for_esc = u1
        decoded_layers.append(u1)
        u1_redacted, u1_hit = _redact_secret_matches_in_text(
            u1,
            field_path=field_path,
            findings=findings,
            ignore_placeholder=True,
        )
        if u1_hit:
            secret_hit = True
            sanitized = u1_redacted
        u2_source = u1_redacted if u1_hit else u1
        if "%" in u2_source:
            u2 = normalize_str(unquote(u2_source))
            decoded_layers.append(u2)
            u2_redacted, u2_hit = _redact_secret_matches_in_text(
                u2,
                field_path=field_path,
                findings=findings,
                ignore_placeholder=True,
            )
            if u2_hit:
                secret_hit = True
                sanitized = u2_redacted

    esc_source = next(
        (cand for cand in (sanitized, pct_base, u1_for_esc) if cand is not None and "\\" in cand),
        None,
    )
    if esc_source is not None:
        unescaped = unescape_text(esc_source)
        if unescaped is not None:
            norm_unesc = normalize_str(unescaped)
            decoded_layers.append(norm_unesc)
            esc_redacted, esc_hit = _redact_secret_matches_in_text(
                norm_unesc,
                field_path=field_path,
                findings=findings,
                ignore_placeholder=True,
            )
            if esc_hit:
                secret_hit = True
                sanitized = esc_redacted

    def _decoded_is_secret(decoded: str) -> bool:
        return _redact_secret_matches_in_text(
            decoded,
            field_path=field_path,
            findings=findings,
            ignore_placeholder=False,
        )[1]

    sanitized, encoded_hit = redact_encoded_secret_tokens(sanitized, _decoded_is_secret)
    secret_hit = secret_hit or encoded_hit
    for layer in dict.fromkeys(decoded_layers):
        if layer == sanitized:
            continue
        layer_redacted, layer_enc_hit = redact_encoded_secret_tokens(layer, _decoded_is_secret)
        if layer_enc_hit:
            secret_hit = True
            sanitized = layer_redacted
    return sanitized, secret_hit


def redact_core_secrets(
    text: str,
    *,
    canary_tokens: tuple[str, ...] = (),
    extra_redactor: Callable[[str], str] | None = None,
) -> str:
    """
    Redact canary tokens (raw, tag-obfuscated, NFKC, percent-encoded, escape-decoded, hex, decimal,
    Base32, Base64, reversed, interleaved) and all 13 known credential patterns (raw, normalized, 1x/2x
    percent-decoded, escaped, and encoded). High-entropy strings without a rule/canary match stay intact.
    """
    sanitized = text
    for canary in canary_tokens:
        if canary:
            sanitized, _ = redact_canary_in_text(sanitized, canary)

    scratch_findings: list[ScanFinding] = []
    if sanitized == "[REDACTED_CANARY]" and text != "[REDACTED_CANARY]":
        # If an encoded canary collapsed the whole string to [REDACTED_CANARY], keep that stronger mask
        # while still honoring any extra_redactor if configured.
        if extra_redactor is not None:
            sanitized = extra_redactor(sanitized)
        return sanitized

    sanitized, _ = _scan_secrets_all_layers(
        sanitized,
        field_path="$",
        findings=scratch_findings,
    )
    if extra_redactor is not None:
        sanitized = extra_redactor(sanitized)
    return sanitized


def _scan_single_string(
    text: str,
    *,
    field_path: str,
    canary_tokens: tuple[str, ...],
    block_known_secrets: bool,
    blocked_regexes: tuple[tuple[str, re.Pattern[str]], ...],
    detect_high_entropy: bool,
    entropy_threshold: float,
    min_entropy_length: int,
    findings: list[ScanFinding],
    matched_canary_indices: set[int],
) -> tuple[str, bool, bool, bool, bool]:
    sanitized = text
    canary_hit = False
    secret_hit = False
    entropy_hit = False
    blocked_hit = False

    # 1. Planted canary tokens (run all configured canaries; no early break)
    if canary_tokens:
        norm_text = normalize_str(sanitized)
        for idx, canary in enumerate(canary_tokens):
            rule_id = f"canary-{idx}"
            next_sanitized, matched = _redact_canary_with_norm(sanitized, norm_text, canary)
            if not matched and sanitized != text and canary_present(text, canary):
                matched = True
            if matched:
                canary_hit = True
                matched_canary_indices.add(idx)
                findings.append(
                    ScanFinding(
                        kind="canary",
                        rule_id=rule_id,
                        field_path=field_path,
                        match_sha256=_hash_match(canary),
                    )
                )
            if next_sanitized != sanitized:
                sanitized = next_sanitized
                norm_text = normalize_str(sanitized)

    # 2. All 13 secret rules across raw, normalized, 1x/2x percent-decoded, unescaped, and encoded layers
    if block_known_secrets:
        if sanitized == "[REDACTED_CANARY]" and text != "[REDACTED_CANARY]":
            _, extra_secret_hit = _scan_secrets_all_layers(text, field_path=field_path, findings=findings)
            secret_hit = extra_secret_hit
        else:
            sanitized, secret_hit = _scan_secrets_all_layers(sanitized, field_path=field_path, findings=findings)

    # 3. Blocked regex patterns from policy (checked against normalized form too)
    if blocked_regexes:
        for rule_id, blk_pattern in blocked_regexes:
            raw_matches = list(blk_pattern.finditer(sanitized))
            if raw_matches:
                blocked_hit = True
                for m in raw_matches:
                    findings.append(
                        ScanFinding(
                            kind="blocked_pattern",
                            rule_id=rule_id,
                            field_path=field_path,
                            match_sha256=_hash_match(m.group(0)),
                        )
                    )
                sanitized = blk_pattern.sub("[REDACTED_BLOCKED]", sanitized)

            norm_candidate = normalize_str(sanitized)
            if norm_candidate != sanitized:
                norm_matches = [m for m in blk_pattern.finditer(norm_candidate) if m.group(0) != "[REDACTED_BLOCKED]"]
                if norm_matches:
                    blocked_hit = True
                    for m in norm_matches:
                        findings.append(
                            ScanFinding(
                                kind="blocked_pattern",
                                rule_id=rule_id,
                                field_path=field_path,
                                match_sha256=_hash_match(m.group(0)),
                            )
                        )
                    sanitized = blk_pattern.sub(
                        lambda m: m.group(0) if m.group(0) == "[REDACTED_BLOCKED]" else "[REDACTED_BLOCKED]",
                        norm_candidate,
                    )

    # 4. Deterministic high-entropy secret candidates (when enabled)
    if detect_high_entropy and math.isfinite(entropy_threshold) and len(sanitized) >= min(min_entropy_length, 16):

        def _redact_contextual(m: re.Match[str]) -> str:
            nonlocal entropy_hit
            candidate = m.group(1)
            if candidate in _FULL_REDACTION_PLACEHOLDERS:
                return m.group(0)
            if _is_high_entropy_candidate(
                candidate, threshold=entropy_threshold, min_length=min_entropy_length, contextual=True
            ):
                entropy_hit = True
                findings.append(
                    ScanFinding(
                        kind="high_entropy",
                        rule_id="high-entropy-credential",
                        field_path=field_path,
                        match_sha256=_hash_match(candidate),
                    )
                )
                prefix = m.group(0)[: m.start(1) - m.start(0)]
                suffix = m.group(0)[m.end(1) - m.start(0) :]
                return f"{prefix}[REDACTED_HIGH_ENTROPY]{suffix}"
            return m.group(0)

        sanitized = _CREDENTIAL_ASSIGN_RE.sub(_redact_contextual, sanitized)

        if len(sanitized) >= min_entropy_length:

            def _redact_jwt(m: re.Match[str]) -> str:
                nonlocal entropy_hit
                token = m.group(1)
                sig = token.rsplit(".", 1)[1]
                if _is_high_entropy_candidate(
                    sig,
                    threshold=entropy_threshold,
                    min_length=min(min_entropy_length, 16),
                    contextual=False,
                ):
                    entropy_hit = True
                    findings.append(
                        ScanFinding(
                            kind="high_entropy",
                            rule_id="high-entropy-token",
                            field_path=field_path,
                            match_sha256=_hash_match(token),
                        )
                    )
                    return "[REDACTED_HIGH_ENTROPY]"
                return token

            sanitized = _JWT_TOKEN_RE.sub(_redact_jwt, sanitized)

            def _redact_standalone(m: re.Match[str]) -> str:
                nonlocal entropy_hit
                candidate = m.group(1)
                if _is_high_entropy_candidate(
                    candidate, threshold=entropy_threshold, min_length=min_entropy_length, contextual=False
                ):
                    entropy_hit = True
                    findings.append(
                        ScanFinding(
                            kind="high_entropy",
                            rule_id="high-entropy-token",
                            field_path=field_path,
                            match_sha256=_hash_match(candidate),
                        )
                    )
                    return "[REDACTED_HIGH_ENTROPY]"
                return candidate

            sanitized = _OPAQUE_TOKEN_RE.sub(_redact_standalone, sanitized)

    return sanitized, canary_hit, secret_hit, entropy_hit, blocked_hit


def _compile_blocked_patterns(blocked_patterns: Sequence[str]) -> tuple[tuple[str, re.Pattern[str]], ...]:
    return tuple((f"blocked-pattern-{idx}", re.compile(raw)) for idx, raw in enumerate(blocked_patterns) if raw)


def scan_payload_core(
    payload: Any,
    *,
    canary_tokens: Sequence[str] = (),
    block_known_secrets: bool = True,
    blocked_patterns: Sequence[str] = (),
    detect_high_entropy: bool = True,
    entropy_threshold: float = 4.0,
    min_entropy_length: int = 20,
    redact: bool = True,
) -> CoreScanOutcome:
    """
    Scan `payload` iteratively with an explicit stack (no recursion) for planted canaries (including
    split keys/values across containers), all 13 known secret rules, blocked regex patterns, optional
    high-entropy tokens, and nesting depth > `MAX_SCAN_DEPTH` (`nesting-too-deep`).
    """
    clean_canaries = tuple(t for t in canary_tokens if t)
    compiled_blocked = _compile_blocked_patterns(blocked_patterns)
    findings: list[ScanFinding] = []
    matched_canary_indices: set[int] = set()

    c_hit = s_hit = e_hit = b_hit = False
    too_deep = False
    leaf_count = 0

    root_box: list[Any] = [payload]

    def _assign(parent: Any, slot: Any, value: Any) -> None:
        if redact:
            parent[slot] = value

    # Stack entries: (parent_container, slot_key_or_idx, field_path, value, depth)
    stack: list[tuple[Any, Any, str, Any, int]] = [(root_box, 0, "$", payload, 0)]
    while stack:
        parent, slot, path, node, depth = stack.pop()
        if depth > _MAX_SCAN_DEPTH:
            too_deep = True

        if isinstance(node, str):
            leaf_count += 1
            if not node:
                _assign(parent, slot, node)
                continue
            r_str, c, s, e, b = _scan_single_string(
                node,
                field_path=path,
                canary_tokens=clean_canaries,
                block_known_secrets=block_known_secrets,
                blocked_regexes=compiled_blocked,
                detect_high_entropy=detect_high_entropy,
                entropy_threshold=entropy_threshold,
                min_entropy_length=min_entropy_length,
                findings=findings,
                matched_canary_indices=matched_canary_indices,
            )
            _assign(parent, slot, r_str)
            c_hit = c_hit or c
            s_hit = s_hit or s
            e_hit = e_hit or e
            b_hit = b_hit or b
        elif isinstance(node, list | tuple):
            out_list: list[Any] | None = [None] * len(node) if redact else None
            _assign(parent, slot, out_list)
            for idx in range(len(node) - 1, -1, -1):
                stack.append((out_list, idx, f"{path}[{idx}]", node[idx], depth + 1))
        elif isinstance(node, dict):
            out_dict: dict[Any, Any] | None = {} if redact else None
            _assign(parent, slot, out_dict)
            pending_children: list[tuple[Any, str, Any]] = []
            for raw_k, raw_v in node.items():
                if isinstance(raw_k, str):
                    leaf_count += 1
                    if not raw_k:
                        rk = raw_k
                        key_label = raw_k
                    else:
                        key_hash = _hash_match(raw_k)[:12]
                        rk, ck, sk, ek, bk = _scan_single_string(
                            raw_k,
                            field_path=f"{path}.<key:{key_hash}>",
                            canary_tokens=clean_canaries,
                            block_known_secrets=block_known_secrets,
                            blocked_regexes=compiled_blocked,
                            detect_high_entropy=detect_high_entropy,
                            entropy_threshold=entropy_threshold,
                            min_entropy_length=min_entropy_length,
                            findings=findings,
                            matched_canary_indices=matched_canary_indices,
                        )
                        c_hit = c_hit or ck
                        s_hit = s_hit or sk
                        e_hit = e_hit or ek
                        b_hit = b_hit or bk
                        key_label = f"<redacted_key:{key_hash}>" if (ck or sk or ek or bk) else raw_k
                else:
                    rk = raw_k
                    key_label = str(raw_k)
                if redact and out_dict is not None:
                    out_dict[rk] = None
                pending_children.append((rk, f"{path}.{key_label}", raw_v))
            for rk, child_path, raw_v in reversed(pending_children):
                stack.append((out_dict, rk, child_path, raw_v, depth + 1))
        else:
            _assign(parent, slot, node)

    redacted = root_box[0] if redact else None

    if isinstance(payload, list | tuple | dict) and clean_canaries and leaf_count > 1:
        split_target = redacted if redact else payload
        val_info, key_info, both_info, norm_pieces, total_norm_chars = _extract_split_views_and_pieces(
            split_target, max_chars=None
        )
        if any(info[1] >= 2 for info in (val_info, key_info, both_info)):
            split_hit = False
            for idx, canary in enumerate(clean_canaries):
                if not redact and idx in matched_canary_indices:
                    continue
                if _canary_present_in_json_extracted(
                    canary,
                    val_view_info=val_info,
                    key_view_info=key_info,
                    both_view_info=both_info,
                    norm_pieces=norm_pieces,
                    total_norm_chars=total_norm_chars,
                    include_single_piece_views=False,
                ):
                    c_hit = True
                    split_hit = True
                    findings.append(
                        ScanFinding(
                            kind="canary",
                            rule_id=f"canary-{idx}",
                            field_path="$[split]",
                            match_sha256=_hash_match(canary),
                        )
                    )
            if redact and split_hit:
                redacted = "[REDACTED_CANARY]"

    if too_deep:
        # No legitimate MCP payload nests past MAX_SCAN_DEPTH; deeper input is rejected fail-closed.
        b_hit = True
        findings.append(
            ScanFinding(
                kind="structure",
                rule_id="nesting-too-deep",
                field_path="$",
                match_sha256=_hash_match(""),
            )
        )

    clean = not (c_hit or s_hit or e_hit or b_hit)
    return CoreScanOutcome(
        clean=clean,
        canary_matched=c_hit,
        secret_matched=s_hit,
        high_entropy_matched=e_hit,
        blocked_pattern_matched=b_hit,
        findings=tuple(findings),
        redacted_payload=redacted,
    )


def scan_value(payload: JsonValue | Any, config: ScannerConfig) -> ScanResult:
    """Scan nested JSON/Python payloads using `ScannerConfig` through the unified stdlib core."""
    outcome = scan_payload_core(
        payload,
        canary_tokens=config.canary_tokens,
        block_known_secrets=config.block_known_secrets,
        blocked_patterns=config.blocked_patterns,
        detect_high_entropy=config.detect_high_entropy,
        entropy_threshold=config.entropy_threshold,
        min_entropy_length=config.min_entropy_length,
        redact=False,
    )
    return ScanResult(
        clean=outcome.clean,
        canary_matched=outcome.canary_matched,
        secret_matched=outcome.secret_matched,
        blocked_pattern_matched=outcome.blocked_pattern_matched,
        findings=outcome.findings,
        high_entropy_matched=outcome.high_entropy_matched,
    )
