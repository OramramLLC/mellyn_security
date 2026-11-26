"""
Canonical Unicode & JSON normalization primitives.

Guarantees deterministic SHA-256 inputs across AgBOM tool pins and audit ledger entries:
  1. Detects and strips invisible Unicode format characters (`Cf`), Unicode Tags (`U+E0000`-`U+E007F`),
     variation selectors (`U+FE00`-`U+FE0F`, `U+E0100`-`U+E01EF`), and invisible fillers.
  2. Applies Unicode NFKC normalization recursively across strings, lists, and dict keys/values.
  3. Serializes canonical JSON using `sort_keys=True, separators=(",", ":"), ensure_ascii=False`.

Strict DAG invariant: imports only the Python standard library.
"""

from __future__ import annotations

import functools
import hashlib
import json
import math
import re
import unicodedata

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, JsonValue]

# Non-Cf codepoints frequently abused for invisible prompt/tag smuggling or blank rendering.
_EXTRA_INVISIBLE_CODEPOINTS: frozenset[int] = frozenset(
    {
        0x034F,  # Combining Grapheme Joiner
        0x115F,  # Hangul Choseong Filler
        0x1160,  # Hangul Jungseong Filler
        0x17B4,  # Khmer Vowel Inherent Aq
        0x17B5,  # Khmer Vowel Inherent Aa
        0x180B,  # Mongolian Free Variation Selector One
        0x180C,  # Mongolian Free Variation Selector Two
        0x180D,  # Mongolian Free Variation Selector Three
        0x180E,  # Mongolian Vowel Separator
        0x200B,  # Zero Width Space (explicit in addition to Cf)
        0x200C,  # Zero Width Non-Joiner
        0x200D,  # Zero Width Joiner
        0x2060,  # Word Joiner
        0x2800,  # Braille Pattern Blank
        0x3164,  # Hangul Filler
        0xFEFF,  # Zero Width No-Break Space / BOM
        0xFFA0,  # Halfwidth Hangul Filler
    }
)


def is_invisible_codepoint(char: str) -> bool:
    """Return True if `char` is an invisible tag, format (`Cf`), variation selector, or blank filler."""
    cp = ord(char)
    if 0xE0000 <= cp <= 0xE007F:  # Unicode Tags block
        return True
    if 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:  # Variation Selectors & Supplement
        return True
    if unicodedata.category(char) == "Cf":  # All format characters (ZWSP, ZWNJ, ZWJ, bidi overrides, soft hyphen)
        return True
    return cp in _EXTRA_INVISIBLE_CODEPOINTS


# Every codepoint `is_invisible_codepoint` can accept lies in these planes: Cf characters are in planes 0, 1 and 14
# (a test scans the whole range to keep this true on each Python's Unicode version), the tags and the variation
# selector supplement are in plane 14, and the rest are in plane 0.
_INVISIBLE_SCAN_RANGES: tuple[range, ...] = (range(0x0000, 0x20000), range(0xE0000, 0xF0000))


def _ranges_class(codepoints: list[int]) -> str:
    parts: list[str] = []
    start = prev = codepoints[0]
    for cp in [*codepoints[1:], -1]:
        if cp == prev + 1:
            prev = cp
            continue
        parts.append(re.escape(chr(start)) if start == prev else f"{re.escape(chr(start))}-{re.escape(chr(prev))}")
        start = prev = cp
    return "[" + "".join(parts) + "]"


@functools.cache
def _invisible_re() -> re.Pattern[str]:
    """
    One compiled character class for exactly the codepoints `is_invisible_codepoint` accepts.

    Stripping with it runs in C. The per-character Python check it replaces cost about 0.3 s per MiB of non-ASCII
    text, and the scanner strips every decoded variant of a string, so a 1 MiB payload took seconds. Built once,
    on first use (about 0.04 s).
    """
    codepoints = [cp for span in _INVISIBLE_SCAN_RANGES for cp in span if is_invisible_codepoint(chr(cp))]
    return re.compile(_ranges_class(codepoints))


def strip_invisible(text: str) -> str:
    """Remove all invisible format, tag, variation-selector, and filler codepoints from `text`."""
    # No ASCII codepoint is invisible here (ASCII controls are category Cc, not Cf), so ASCII text is returned
    # as is. This is exact, not an approximation, and skips the scan on the common case.
    if text.isascii():
        return text
    return _invisible_re().sub("", text)


def normalize_str(text: str) -> str:
    """Strip invisible codepoints and apply NFKC normalization twice (idempotent against layered compatibility)."""
    if text.isascii():  # NFKC maps every ASCII string to itself, and nothing ASCII is invisible.
        return text
    stripped = strip_invisible(text)
    if unicodedata.is_normalized("NFKC", stripped):
        return stripped
    first = strip_invisible(unicodedata.normalize("NFKC", stripped))
    if first.isascii() or unicodedata.is_normalized("NFKC", first):
        return first
    return strip_invisible(unicodedata.normalize("NFKC", first))


def has_invisible_unicode(value: object) -> bool:
    """Iteratively return True if any string key or value inside `value` contains invisible codepoints."""
    stack: list[object] = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            if not node.isascii() and _invisible_re().search(node) is not None:
                return True
        elif isinstance(node, list | tuple):
            stack.extend(node)
        elif isinstance(node, dict):
            for k, v in node.items():
                stack.append(k if isinstance(k, str) else str(k))
                stack.append(v)
    return False


def normalize_value(value: JsonValue) -> JsonValue:
    """
    Recursively validate and normalize strict JSON data for canonical serialization.

    - Strings are stripped of invisible characters and NFKC-normalized.
    - Booleans remain distinct from integers.
    - Finite floats canonicalize `-0.0` to `0.0`; NaN/Inf fail closed with `ValueError`.
    - Dict keys are normalized; collisions after NFKC/stripping fail closed with `ValueError`.
    """
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Non-finite float values (NaN/Inf) are forbidden.")
        return 0.0 if value == 0.0 else value
    if isinstance(value, str):
        return normalize_str(value)
    if isinstance(value, list):
        return [normalize_value(item) for item in value]
    if isinstance(value, dict):
        out: dict[str, JsonValue] = {}
        for raw_key, raw_val in value.items():
            if not isinstance(raw_key, str):
                raise TypeError(f"JSON object keys must be strings, got {type(raw_key).__name__}.")
            norm_key = normalize_str(raw_key)
            if norm_key in out:
                raise ValueError(f"Canonical key collision after Unicode normalization: {norm_key!r}")
            out[norm_key] = normalize_value(raw_val)
        return out
    raise TypeError(f"Unsupported non-JSON value type: {type(value).__name__}")


def canonical_json_bytes(obj: JsonValue) -> bytes:
    """
    Normalize `obj` (NFKC + invisible stripping) and encode canonical UTF-8 JSON bytes.

    Uses `json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)`.
    """
    normalized = normalize_value(obj)
    serialized = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return serialized.encode("utf-8")


def sha256_canonical(obj: JsonValue) -> str:
    """Return the lowercase hex SHA-256 digest of `canonical_json_bytes(obj)`."""
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest()


def _validate_strict_json(value: JsonValue) -> None:
    stack: list[JsonValue] = [value]
    while stack:
        node = stack.pop()
        if node is None or isinstance(node, bool | int | str):
            continue
        if isinstance(node, float):
            if not math.isfinite(node):
                raise ValueError("Non-finite float values (NaN/Inf) are forbidden.")
            continue
        if isinstance(node, list):
            stack.extend(node)
            continue
        if isinstance(node, dict):
            for key, item in node.items():
                if not isinstance(key, str):
                    raise TypeError(f"JSON object keys must be strings, got {type(key).__name__}.")
                stack.append(item)
            continue
        raise TypeError(f"Unsupported non-JSON value type: {type(node).__name__}")


def exact_json_bytes(obj: JsonValue) -> bytes:
    """
    Encode `obj` as sorted-key UTF-8 JSON WITHOUT Unicode normalization or invisible-character stripping.

    Use this for anything that must describe the bytes actually forwarded: AgBOM pins, request/response artifact
    hashes, and payload size caps. Normalizing first would let two different payloads (one carrying hidden or
    compatibility characters) share a hash or slip under a size cap. Lone surrogates fail with `ValueError`.
    """
    _validate_strict_json(obj)
    serialized = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return serialized.encode("utf-8")


def sha256_exact(obj: JsonValue) -> str:
    """Return the lowercase hex SHA-256 digest of `exact_json_bytes(obj)`."""
    return hashlib.sha256(exact_json_bytes(obj)).hexdigest()
