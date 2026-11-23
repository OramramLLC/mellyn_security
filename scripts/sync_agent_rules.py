#!/usr/bin/env python3
"""
Keep every AI coding assistant's instruction file in sync with one canonical ruleset,
and reject hidden Unicode in those files ("Rules File Backdoor"-style injection).

Canonical source : .agent/rules/owasp-secure-ai-coding.md   (Antigravity reads it directly)
Imported by      : CLAUDE.md  (via an @-import line)
Generated        : .cursorrules, .github/copilot-instructions.md

Usage:
  python scripts/sync_agent_rules.py           # regenerate the generated files
  python scripts/sync_agent_rules.py --check   # fail on drift or hidden characters (pre-commit / CI)

In a repository without the canonical file (a client repo using the Mellyn hook pack or reusable workflow),
the sync and import checks do not apply: --check only scans every AI instruction file it finds for hidden
characters. Without --check, it refuses to generate anything.
"""

from __future__ import annotations

import argparse
import sys
import unicodedata
from pathlib import Path

CANONICAL = Path(".agent/rules/owasp-secure-ai-coding.md")
GENERATED = (Path(".cursorrules"), Path(".github/copilot-instructions.md"))
CLAUDE_MD = Path("CLAUDE.md")
CLAUDE_IMPORT = f"@{CANONICAL.as_posix()}"
SELF_POLICY_SOURCE = Path("config/mellyn-policy.example.toml")
SELF_POLICY_TARGET = Path("config/mellyn-self-policy.toml")
SELF_PROTECTED_PATHS: tuple[str, ...] = (
    "backend/mellyn/",
    "src/",
    "scripts/",
    "tests/",
    "config/",
    "deploy/",
    "Dockerfile",
    ".dockerignore",
    "pyproject.toml",
    "docs/THREAT_MODEL.md",
)
# Other instruction files agents may read; scanned for hidden characters if present.
EXTRA_SCANNED = (Path("AGENTS.md"), Path("GEMINI.md"), Path(".windsurfrules"), Path(".clinerules"))
# Directories of instruction files (any depth), scanned for hidden characters.
EXTRA_SCANNED_GLOBS = (".agent/rules/**/*.md", ".cursor/rules/**/*.mdc", ".github/instructions/**/*.md")

HEADER = (
    "<!-- GENERATED FILE — DO NOT EDIT. Source: {src}\n     Regenerate with: python scripts/sync_agent_rules.py -->\n\n"
)
SELF_POLICY_HEADER = (
    "# GENERATED FILE — DO NOT EDIT. Source: config/mellyn-policy.example.toml\n"
    "# Regenerate with: python scripts/sync_agent_rules.py\n"
    "# Mellyn Security — Policy for agents working on THIS repository (Mellyn Security itself)\n"
    "# Loaded strictly and fail-closed by `mellyn.policy_loader.load_policy_file()`.\n"
)


def read_text(path: Path) -> str:
    """
    Read with CRLF normalized to LF, so Windows CRLF checkouts do not register as drift.

    Decoded from bytes on purpose: text mode's universal newlines would also turn a lone CR into LF, hiding the
    carriage-return overwrite trick (`visible text\\rhidden instruction`) from hidden_characters().
    """
    return path.read_bytes().decode("utf-8").replace("\r\n", "\n")


def strip_frontmatter(text: str) -> str:
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        if end != -1:
            return text[end + len("\n---\n") :].lstrip("\n")
    return text


def render_generated(root: Path) -> str:
    body = strip_frontmatter(read_text(root / CANONICAL))
    return HEADER.format(src=CANONICAL.as_posix()) + body


def render_self_policy(root: Path) -> str:
    source_text = read_text(root / SELF_POLICY_SOURCE)
    lines = source_text.split("\n")
    idx = 0
    while idx < len(lines) and lines[idx].startswith("#"):
        idx += 1
    body = "\n".join(lines[idx:])
    target_block = "\nprotected_paths = []\n"
    if body.count(target_block) != 1:
        raise ValueError(f"{SELF_POLICY_SOURCE.as_posix()} must contain exactly one 'protected_paths = []' line")
    rendered_paths = "".join(f'    "{entry}",\n' for entry in SELF_PROTECTED_PATHS)
    replacement = f"\nprotected_paths = [\n{rendered_paths}]\n"
    return SELF_POLICY_HEADER + body.replace(target_block, replacement, 1)


# Non-Cf invisible fillers, joiners, and variation selectors used in hidden-prompt smuggling.
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
        0x2800,  # Braille Pattern Blank
        0x3164,  # Hangul Filler
        0xFFA0,  # Halfwidth Hangul Filler
    }
)


def _is_hidden_codepoint(char: str) -> bool:
    cp = ord(char)
    cat = unicodedata.category(char)
    if cat in ("Cf", "Zl", "Zp"):
        return True
    if cat == "Cc" and char != "\t":
        return True
    if 0xE0000 <= cp <= 0xE007F:  # Tags block
        return True
    if 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:  # Variation Selectors & Supplement
        return True
    return cp in _EXTRA_INVISIBLE_CODEPOINTS


_PRESENTATION_SELECTORS = frozenset({0xFE0E, 0xFE0F})  # text / emoji presentation (VS15, VS16)
_ZERO_WIDTH_JOINER = 0x200D
_KEYCAP_BASES = frozenset("0123456789#*")


def _is_emoji_base(char: str) -> bool:
    """A character that ordinary text legitimately follows with VS15/VS16: a symbol (So/Sk) or a keycap base."""
    return unicodedata.category(char) in ("So", "Sk") or char in _KEYCAP_BASES


def _legitimate_emoji_join(line: str, col: int) -> bool:
    """
    True for the two invisible characters that ordinary emoji need, used in their normal position:
    VS15/VS16 right after an emoji or symbol base ("⚠️"), and a zero-width joiner between two
    emoji ("👨‍💻"). Anywhere else (inside a word, doubled, at a line start) they
    are still reported, because that is how text gets smuggled.
    """
    cp = ord(line[col])
    prev = line[col - 1] if col > 0 else ""
    if cp in _PRESENTATION_SELECTORS:
        return bool(prev) and _is_emoji_base(prev)
    if cp == _ZERO_WIDTH_JOINER:
        before = prev if prev and ord(prev) not in _PRESENTATION_SELECTORS else (line[col - 2] if col > 1 else "")
        after = line[col + 1] if col + 1 < len(line) else ""
        return bool(before) and bool(after) and _is_emoji_base(before) and _is_emoji_base(after)
    return False


def hidden_characters(text: str) -> list[tuple[int, int, str]]:
    """Return (line, column, codepoint) for invisible format/bidi/tag/variation-selector/filler/control characters."""
    found: list[tuple[int, int, str]] = []
    normalized = text.replace("\r\n", "\n")
    for line_no, line in enumerate(normalized.split("\n"), 1):
        for index, char in enumerate(line):
            if _is_hidden_codepoint(char) and not _legitimate_emoji_join(line, index):
                found.append((line_no, index + 1, f"U+{ord(char):04X}"))
    return found


def instruction_files(root: Path) -> list[Path]:
    """Every AI instruction file present under root, as paths relative to it, without duplicates."""
    found: dict[str, Path] = {}
    for rel in (CANONICAL, CLAUDE_MD, *GENERATED, *EXTRA_SCANNED):
        if (root / rel).is_file():
            found[rel.as_posix()] = rel
    for pattern in EXTRA_SCANNED_GLOBS:
        for path in sorted(root.glob(pattern)):
            if path.is_file():
                rel = path.relative_to(root)
                found[rel.as_posix()] = rel
    return sorted(found.values(), key=lambda rel: rel.as_posix())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--check", action="store_true", help="Report drift instead of rewriting files")
    args = parser.parse_args(argv)
    root: Path = args.root.resolve()
    problems: list[str] = []
    has_canonical = (root / CANONICAL).is_file()

    if not has_canonical and not args.check:
        print(f"No {CANONICAL.as_posix()} in {root}; nothing to generate.")
        return 1

    expected = render_generated(root) if has_canonical else ""
    for rel in GENERATED if has_canonical else ():
        path = root / rel
        current = read_text(path) if path.exists() else None
        if current == expected:
            continue
        if args.check:
            problems.append(f"[DRIFT] {rel.as_posix()} differs from {CANONICAL.as_posix()}; run sync_agent_rules.py")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(expected, encoding="utf-8", newline="\n")
            print(f"Regenerated {rel.as_posix()}")

    if has_canonical and (root / SELF_POLICY_SOURCE).is_file():
        expected_policy = render_self_policy(root)
        policy_path = root / SELF_POLICY_TARGET
        current_policy = read_text(policy_path) if policy_path.exists() else None
        if current_policy != expected_policy:
            if args.check:
                problems.append(
                    f"[DRIFT] {SELF_POLICY_TARGET.as_posix()} differs from {SELF_POLICY_SOURCE.as_posix()}; "
                    "run sync_agent_rules.py"
                )
            else:
                policy_path.parent.mkdir(parents=True, exist_ok=True)
                policy_path.write_text(expected_policy, encoding="utf-8", newline="\n")
                print(f"Regenerated {SELF_POLICY_TARGET.as_posix()}")

    claude = root / CLAUDE_MD
    if has_canonical and (not claude.exists() or CLAUDE_IMPORT not in read_text(claude).splitlines()):
        problems.append(f"[MISSING IMPORT] {CLAUDE_MD} must contain a line '{CLAUDE_IMPORT}'")

    scanned = instruction_files(root)
    for rel in scanned:
        try:
            text = read_text(root / rel)
        except UnicodeDecodeError:
            problems.append(f"[NOT UTF-8] {rel.as_posix()} is not valid UTF-8; cannot check it for hidden characters")
            continue
        for line_no, col, codepoint in hidden_characters(text):
            problems.append(f"[HIDDEN CHARACTER] {rel.as_posix()}:{line_no}:{col} contains invisible {codepoint}")

    if problems:
        print("Agent rules check FAILED:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    if has_canonical:
        print("Agent rules check PASSED: instruction files are in sync and free of hidden characters.")
    else:
        print(
            f"Agent rules check PASSED: {len(scanned)} instruction file(s) free of hidden characters "
            f"(no {CANONICAL.as_posix()}, so the sync check does not apply)."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
