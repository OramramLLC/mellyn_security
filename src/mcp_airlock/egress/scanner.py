"""
Deterministic egress content scanner for planted canary tokens, known API/bearer secrets,
high-entropy secret candidates, and policy-defined blocked patterns.

Architectural invariants:
  - Imports ONLY from `mcp_airlock.core` (+ stdlib / pydantic).
  - Always computes `artifact_sha256` on the unredacted payload first via `sha256_exact()`.
  - Returns structured `RedactionRecord` hashes and `redacted_payload`; never leaks raw matches.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Sequence
from urllib.parse import unquote

from pydantic import BaseModel, ConfigDict, Field

from mcp_airlock.core.normalize import JsonValue, normalize_str, sha256_exact
from mcp_airlock.core.schemas import RedactionRecord

KNOWN_SECRET_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "url-userinfo-password",
        # The lookbehind makes a scheme start only at a token boundary; without it every letter of a long word
        # starts a new attempt and the scan becomes quadratic.
        re.compile(r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:([^@\s/]+)@"),
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
        re.compile(r"(?i)(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}"),
    ),
)

_CREDENTIAL_ASSIGN_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|token|secret|password|passwd|auth_token|access_key|bearer)\b"
    r"""\s*[:=]\s*["']?([A-Za-z0-9._~+/=-]{16,})["']?"""
)
_OPAQUE_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_+/=.-])([A-Za-z0-9_+/=-]{20,})(?![A-Za-z0-9_+/=.-])")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_HEX_ONLY_RE = re.compile(r"^[0-9a-fA-F]+$")
_REDACTION_PLACEHOLDERS: frozenset[str] = frozenset(
    {"REDACTED_CANARY", "REDACTED_SECRET", "REDACTED_BLOCKED", "REDACTED_HIGH_ENTROPY"}
)


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
    classes = 0
    if any("a" <= c <= "z" for c in token):
        classes += 1
    if any("A" <= c <= "Z" for c in token):
        classes += 1
    if any("0" <= c <= "9" for c in token):
        classes += 1
    if any(not c.isalnum() for c in token):
        classes += 1
    return classes


def _is_high_entropy_candidate(token: str, *, threshold: float, min_length: int, contextual: bool) -> bool:
    if token in _REDACTION_PLACEHOLDERS:
        return False
    eff_min = min(min_length, 16) if contextual else min_length
    if len(token) < eff_min:
        return False
    if _UUID_RE.fullmatch(token):
        return False
    if not contextual and _HEX_ONLY_RE.fullmatch(token) and token == token.lower():
        # Plain lowercase hex (such as SHA-256 digests) is skipped unless paired with a credential label.
        return False
    required_classes = 2 if contextual else 3
    if _character_classes(token) < required_classes:
        return False
    return shannon_entropy(token) >= threshold


def _compile_obfuscated_canary_regex(token: str) -> re.Pattern[str]:
    norm_token = normalize_str(token)
    if not norm_token:
        return re.compile(re.escape(token))
    gap = (
        r"[\u034f\u115f\u1160\u17b4\u17b5\u180b-\u180e\u200b-\u200f\u2060\u2800"
        r"\u3164\ufeff\uffa0\ufe00-\ufe0f\U000e0000-\U000e007f\U000e0100-\U000e01ef]*"
    )
    return re.compile(gap.join(re.escape(ch) for ch in norm_token), re.IGNORECASE)


def _canary_present(text: str, folded_canary: str) -> bool:
    """
    True if the canary appears in `text` after invisible stripping + NFKC, ignoring case, either directly or
    after percent-decoding. Splitting a canary across separate fields is NOT detected (a known limit of
    per-string scanning); planted canaries should be long random tokens so partial leaks are still unique.
    """
    norm = normalize_str(text)
    return folded_canary in norm.casefold() or folded_canary in normalize_str(unquote(norm)).casefold()


class EgressScanResult(BaseModel):
    """Structured redacted output from `egress.scanner`."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    artifact_sha256: str
    clean: bool
    canary_matched: bool
    secret_matched: bool
    high_entropy_matched: bool
    blocked_pattern_matched: bool
    findings: list[RedactionRecord] = Field(default_factory=list)
    redacted_payload: JsonValue = None


def _scan_single_string(
    text: str,
    *,
    field_path: str,
    canary_tokens: tuple[str, ...],
    blocked_regexes: tuple[tuple[str, re.Pattern[str]], ...],
    entropy_threshold: float,
    min_entropy_length: int,
    findings: list[RedactionRecord],
) -> tuple[str, bool, bool, bool, bool]:
    sanitized = text
    canary_hit = False
    secret_hit = False
    entropy_hit = False
    blocked_hit = False

    # 1. Planted canary tokens (raw, any letter case, tag/ZWSP-obfuscated, NFKC homoglyphs, percent-encoded)
    for idx, canary in enumerate(canary_tokens):
        if not canary:
            continue
        rule_id = f"canary-{idx}"
        norm_canary = normalize_str(canary)
        matched_raw = canary in sanitized
        matched_norm = bool(norm_canary) and _canary_present(sanitized, norm_canary.casefold())

        if matched_raw or matched_norm:
            canary_hit = True
            findings.append(
                RedactionRecord(
                    kind="canary",
                    rule_id=rule_id,
                    field_path=field_path,
                    match_sha256=_hash_match(canary),
                )
            )
            sanitized = sanitized.replace(canary, "[REDACTED_CANARY]")
            if norm_canary:
                sanitized = _compile_obfuscated_canary_regex(norm_canary).sub("[REDACTED_CANARY]", sanitized)
                if _canary_present(sanitized, norm_canary.casefold()):
                    # Homoglyph or percent-encoded residue cannot be cut out in place; redact the whole string.
                    sanitized = "[REDACTED_CANARY]"

    # 2. Known credential & API secret regexes (raw + NFKC/invisible-stripped obfuscation)
    for rule_id, pattern in KNOWN_SECRET_RULES:
        raw_matches = list(pattern.finditer(sanitized))
        if raw_matches:
            secret_hit = True
            for match in raw_matches:
                matched_val = match.group(1) if match.lastindex else match.group(0)
                findings.append(
                    RedactionRecord(
                        kind="secret",
                        rule_id=rule_id,
                        field_path=field_path,
                        match_sha256=_hash_match(matched_val),
                    )
                )
            if rule_id == "url-userinfo-password":
                sanitized = pattern.sub(
                    lambda m: m.group(0)[: m.start(1) - m.start(0)] + "[REDACTED_SECRET]@",
                    sanitized,
                )
            else:
                sanitized = pattern.sub("[REDACTED_SECRET]", sanitized)

        norm_candidate = normalize_str(sanitized)
        if norm_candidate != sanitized:
            norm_matches = [
                m
                for m in pattern.finditer(norm_candidate)
                if (m.group(1) if m.lastindex else m.group(0)) != "[REDACTED_SECRET]"
            ]
            if norm_matches:
                secret_hit = True
                for match in norm_matches:
                    matched_val = match.group(1) if match.lastindex else match.group(0)
                    findings.append(
                        RedactionRecord(
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
                            if m.group(1) == "[REDACTED_SECRET]"
                            else m.group(0)[: m.start(1) - m.start(0)] + "[REDACTED_SECRET]@"
                        ),
                        norm_candidate,
                    )
                else:
                    sanitized = pattern.sub("[REDACTED_SECRET]", norm_candidate)

    # 3. Blocked regex patterns from policy (checked against normalized form too)
    for rule_id, blk_pattern in blocked_regexes:
        raw_matches = list(blk_pattern.finditer(sanitized))
        if raw_matches:
            blocked_hit = True
            for m in raw_matches:
                findings.append(
                    RedactionRecord(
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
                        RedactionRecord(
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

    # 4. Deterministic high-entropy secret candidates (contextual + standalone)
    def _redact_contextual(m: re.Match[str]) -> str:
        nonlocal entropy_hit
        candidate = m.group(1)
        if candidate in ("[REDACTED_CANARY]", "[REDACTED_SECRET]", "[REDACTED_BLOCKED]", "[REDACTED_HIGH_ENTROPY]"):
            return m.group(0)
        if _is_high_entropy_candidate(
            candidate, threshold=entropy_threshold, min_length=min_entropy_length, contextual=True
        ):
            entropy_hit = True
            findings.append(
                RedactionRecord(
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

    def _redact_standalone(m: re.Match[str]) -> str:
        nonlocal entropy_hit
        candidate = m.group(1)
        if _is_high_entropy_candidate(
            candidate, threshold=entropy_threshold, min_length=min_entropy_length, contextual=False
        ):
            entropy_hit = True
            findings.append(
                RedactionRecord(
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


def _scan_recursive(
    value: JsonValue,
    *,
    field_path: str,
    canary_tokens: tuple[str, ...],
    blocked_regexes: tuple[tuple[str, re.Pattern[str]], ...],
    entropy_threshold: float,
    min_entropy_length: int,
    findings: list[RedactionRecord],
) -> tuple[JsonValue, bool, bool, bool, bool]:
    if isinstance(value, str):
        return _scan_single_string(
            value,
            field_path=field_path,
            canary_tokens=canary_tokens,
            blocked_regexes=blocked_regexes,
            entropy_threshold=entropy_threshold,
            min_entropy_length=min_entropy_length,
            findings=findings,
        )
    if isinstance(value, list):
        c_any = s_any = e_any = b_any = False
        out_list: list[JsonValue] = []
        for idx, item in enumerate(value):
            r_item, c, s, e, b = _scan_recursive(
                item,
                field_path=f"{field_path}[{idx}]",
                canary_tokens=canary_tokens,
                blocked_regexes=blocked_regexes,
                entropy_threshold=entropy_threshold,
                min_entropy_length=min_entropy_length,
                findings=findings,
            )
            out_list.append(r_item)
            c_any = c_any or c
            s_any = s_any or s
            e_any = e_any or e
            b_any = b_any or b
        return out_list, c_any, s_any, e_any, b_any
    if isinstance(value, dict):
        c_any = s_any = e_any = b_any = False
        out_dict: dict[str, JsonValue] = {}
        for k, v in value.items():
            key_findings: list[RedactionRecord] = []
            rk, ck, sk, ek, bk = _scan_single_string(
                k,
                field_path=f"{field_path}.<key:{_hash_match(k)[:12]}>",
                canary_tokens=canary_tokens,
                blocked_regexes=blocked_regexes,
                entropy_threshold=entropy_threshold,
                min_entropy_length=min_entropy_length,
                findings=key_findings,
            )
            findings.extend(key_findings)
            key_label = f"<redacted_key:{_hash_match(k)[:12]}>" if (ck or sk or ek or bk) else k
            rv, cv, sv, ev, bv = _scan_recursive(
                v,
                field_path=f"{field_path}.{key_label}",
                canary_tokens=canary_tokens,
                blocked_regexes=blocked_regexes,
                entropy_threshold=entropy_threshold,
                min_entropy_length=min_entropy_length,
                findings=findings,
            )
            out_dict[rk] = rv
            c_any = c_any or ck or cv
            s_any = s_any or sk or sv
            e_any = e_any or ek or ev
            b_any = b_any or bk or bv
        return out_dict, c_any, s_any, e_any, b_any
    return value, False, False, False, False


def _compile_blocked_patterns(blocked_patterns: Sequence[str]) -> tuple[tuple[str, re.Pattern[str]], ...]:
    compiled: list[tuple[str, re.Pattern[str]]] = []
    for idx, raw in enumerate(blocked_patterns):
        if raw:
            compiled.append((f"blocked-pattern-{idx}", re.compile(raw)))
    return tuple(compiled)


def scan_payload(
    payload: JsonValue,
    *,
    canary_tokens: Sequence[str] = (),
    blocked_patterns: Sequence[str] = (),
    entropy_threshold: float = 4.0,
    min_entropy_length: int = 20,
) -> EgressScanResult:
    """
    Compute `artifact_sha256` on `payload` first, then scan recursively for planted canaries,
    known API/bearer secrets, high-entropy strings, and blocked patterns.
    """
    artifact_sha256 = sha256_exact(payload)
    findings: list[RedactionRecord] = []
    clean_canaries = tuple(t for t in canary_tokens if t)
    compiled_blocked = _compile_blocked_patterns(blocked_patterns)

    redacted, c_hit, s_hit, e_hit, b_hit = _scan_recursive(
        payload,
        field_path="$",
        canary_tokens=clean_canaries,
        blocked_regexes=compiled_blocked,
        entropy_threshold=entropy_threshold,
        min_entropy_length=min_entropy_length,
        findings=findings,
    )
    clean = not (c_hit or s_hit or e_hit or b_hit)
    return EgressScanResult(
        artifact_sha256=artifact_sha256,
        clean=clean,
        canary_matched=c_hit,
        secret_matched=s_hit,
        high_entropy_matched=e_hit,
        blocked_pattern_matched=b_hit,
        findings=findings,
        redacted_payload=redacted,
    )


def scan_text(
    text: str,
    *,
    canary_tokens: Sequence[str] = (),
    blocked_patterns: Sequence[str] = (),
    entropy_threshold: float = 4.0,
    min_entropy_length: int = 20,
) -> EgressScanResult:
    """Convenience wrapper scanning a single string payload via `scan_payload`."""
    return scan_payload(
        text,
        canary_tokens=canary_tokens,
        blocked_patterns=blocked_patterns,
        entropy_threshold=entropy_threshold,
        min_entropy_length=min_entropy_length,
    )
