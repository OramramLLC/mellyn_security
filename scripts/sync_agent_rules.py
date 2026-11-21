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
# Other instruction files agents may read; scanned for hidden characters if present.
EXTRA_SCANNED = (Path("AGENTS.md"), Path("GEMINI.md"), Path(".windsurfrules"))

HEADER = (
    "<!-- GENERATED FILE — DO NOT EDIT. Source: {src}\n     Regenerate with: python scripts/sync_agent_rules.py -->\n\n"
)


def read_text(path: Path) -> str:
    """Read with newlines normalized, so Windows CRLF checkouts do not register as drift."""
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def strip_frontmatter(text: str) -> str:
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        if end != -1:
            return text[end + len("\n---\n") :].lstrip("\n")
    return text


def render_generated(root: Path) -> str:
    body = strip_frontmatter(read_text(root / CANONICAL))
    return HEADER.format(src=CANONICAL.as_posix()) + body


def hidden_characters(text: str) -> list[tuple[int, int, str]]:
    """Return (line, column, codepoint) for invisible format/bidi/tag characters."""
    found: list[tuple[int, int, str]] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        for col, char in enumerate(line, 1):
            if unicodedata.category(char) == "Cf" or 0xE0000 <= ord(char) <= 0xE007F:
                found.append((line_no, col, f"U+{ord(char):04X}"))
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--check", action="store_true", help="Report drift instead of rewriting files")
    args = parser.parse_args(argv)
    root: Path = args.root.resolve()
    problems: list[str] = []

    expected = render_generated(root)
    for rel in GENERATED:
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

    claude = root / CLAUDE_MD
    if not claude.exists() or CLAUDE_IMPORT not in read_text(claude).splitlines():
        problems.append(f"[MISSING IMPORT] {CLAUDE_MD} must contain a line '{CLAUDE_IMPORT}'")

    for rel in (CANONICAL, CLAUDE_MD, *GENERATED, *EXTRA_SCANNED):
        path = root / rel
        if path.exists():
            for line_no, col, codepoint in hidden_characters(read_text(path)):
                problems.append(f"[HIDDEN CHARACTER] {rel.as_posix()}:{line_no}:{col} contains invisible {codepoint}")

    if problems:
        print("Agent rules check FAILED:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("Agent rules check PASSED: instruction files are in sync and free of hidden characters.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
