"""Strict parsing of untrusted JSON bodies and HTTP `Content-Length` values (stdlib-only).

One copy shared by the HTTP authorizer (`mellyn.api`), the approval server and relay (`mellyn.approvals`,
`mellyn.approval_relay`), and the Streamable HTTP downstream client (`mellyn.http_downstream`), so the three
parse the same bytes the same way.
"""

from __future__ import annotations

import json
import re
from typing import Any

# RFC 9110: Content-Length = 1*DIGIT, ASCII digits only. `int()` alone would also accept "+16", "1_6",
# surrounding whitespace, and non-ASCII digits such as "١٦", which other HTTP parsers read differently.
_CONTENT_LENGTH_RE = re.compile(r"[0-9]{1,18}")

# Deepest array/object nesting accepted. The parser's own limit depends on the Python version (3.14 accepts far
# deeper documents than 3.12), so an explicit cap keeps the result the same everywhere and keeps pathological
# documents away from json and pydantic. It is above the gateway scanner's 64-level nesting rule.
MAX_JSON_DEPTH = 128


class StrictJsonError(ValueError):
    """A JSON document was well-formed but used a forbidden construct (duplicate key, NaN/Infinity, deep nesting)."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise StrictJsonError(f"Duplicate JSON key '{key}' is forbidden.")
        out[key] = value
    return out


def _reject_constant(token: str) -> Any:
    raise StrictJsonError(f"Non-standard JSON constant is forbidden: {token!r}.")


def _check_depth(text: str, max_depth: int) -> None:
    if text.count("[") + text.count("{") <= max_depth:
        return  # cannot nest deeper than the total number of openers (O(N) fast path in C)
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > max_depth:
                raise StrictJsonError(f"JSON nesting is deeper than {max_depth} levels.")
        elif char in "]}" and depth > 0:
            depth -= 1


def strict_json_loads(raw: str | bytes, *, max_depth: int = MAX_JSON_DEPTH) -> Any:
    """Parse JSON, rejecting duplicate object keys, NaN/Infinity, and nesting deeper than `max_depth`.

    Raises `StrictJsonError` for those, `json.JSONDecodeError` for malformed JSON, and `UnicodeDecodeError` for
    bytes that are not UTF-8. All three are `ValueError` subclasses.
    """
    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    _check_depth(text, max_depth)
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)
    except RecursionError:
        raise StrictJsonError("JSON nesting is too deep.") from None


def parse_content_length(raw: str | bytes) -> int | None:
    """Return the value of one `Content-Length` header, or None unless it is plain ASCII digits."""
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("ascii")
        except UnicodeDecodeError:
            return None
    value = raw.strip(" \t")
    if not _CONTENT_LENGTH_RE.fullmatch(value):
        return None
    return int(value)


__all__ = [
    "MAX_JSON_DEPTH",
    "StrictJsonError",
    "parse_content_length",
    "strict_json_loads",
]
