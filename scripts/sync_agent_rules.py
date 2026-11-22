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
# Other instruction files agents may read; scanned for hidden characters if present.
EXTRA_SCANNED = (Path("AGENTS.md"), Path("GEMINI.md"), Path(".windsurfrules"), Path(".clinerules"))
# Directories of instruction files (any depth), scanned for hidden characters.
EXTRA_SCANNED_GLOBS = (".agent/rules/**/*.md", ".cursor/rules/**/*.mdc", ".github/instructions/**/*.md")

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
