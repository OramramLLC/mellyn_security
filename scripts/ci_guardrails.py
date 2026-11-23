#!/usr/bin/env python3
"""
Trusted CI guardrail helpers shared by Mellyn's own security gate and reusable workflow.

Centralizes (single source of truth):
  - Checksum-verified Gitleaks binary installation and suppression-proof invocation
  - First-parent / baseline `.mellyn-allowlist.toml` extraction (blocking PR self-exemptions)
  - Candidate `.semgrepignore` replacement and `--disable-nosem` Semgrep invocation
  - Baseline-vs-candidate guardrail execution so candidate PR edits cannot judge themselves

Uses only the Python 3.12+ standard library.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path

GITLEAKS_VERSION = "8.30.1"
GITLEAKS_LINUX_X64_SHA256 = "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"

# Every pattern is anchored to the repository root (leading `/`). An unanchored `build/` or `vendor/` matches at any
# depth, so a PR could commit code under `backend/app/build/` and import it while Semgrep never scans it. Semgrep
# already scans only git-tracked files, so uncommitted build output and virtualenvs need no pattern at all.
SAFE_SEMGREPIGNORE_PATTERNS: tuple[str, ...] = ("/node_modules/",)
# Semgrep's own rule test fixtures (intentionally vulnerable code) at the repository root only. Not `--exclude
# .semgrep`, which matches a `.semgrep` directory at any depth.
SELF_FIXTURES_IGNORE_PATTERN = "/.semgrep/"

_HEX_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
_ZERO_SHA40 = "0" * 40


def is_valid_commit_sha(value: str) -> bool:
    return bool(_HEX_SHA40_RE.match(value)) and value != _ZERO_SHA40


def select_guardrail_root(baseline_root: Path, candidate_root: Path, *, use_candidate: bool = False) -> Path:
    """Return the directory whose scripts, rules, and scanner configs judge `candidate_root`."""
    chosen = (candidate_root if use_candidate else baseline_root).resolve()
    if not chosen.is_dir():
        raise FileNotFoundError(f"Guardrail root does not exist: {chosen}")
    return chosen


def _default_download(url: str, dest: Path) -> None:
    if not url.startswith("https://github.com/gitleaks/gitleaks/releases/download/"):
        raise ValueError(f"Refusing unexpected Gitleaks download URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "mellyn-ci-guardrails/1.0"})  # noqa: S310
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - HTTPS URL prefix checked above, SHA-256 verified below
        dest.write_bytes(resp.read())


def install_gitleaks(
    dest_dir: Path,
    *,
    version: str = GITLEAKS_VERSION,
    expected_sha256: str = GITLEAKS_LINUX_X64_SHA256,
    downloader: Callable[[str, Path], None] | None = None,
) -> Path:
    """Download pinned Gitleaks release archive, verify SHA-256 strictly, and extract the binary."""
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError(f"Invalid Gitleaks version: {version!r}")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError(f"Invalid Gitleaks SHA-256: {expected_sha256!r}")

    dest_dir.mkdir(parents=True, exist_ok=True)
    archive_path = dest_dir / f"gitleaks_{version}_linux_x64.tar.gz"
    url = f"https://github.com/gitleaks/gitleaks/releases/download/v{version}/gitleaks_{version}_linux_x64.tar.gz"
    fetch = downloader or _default_download
    fetch(url, archive_path)

    try:
        actual_sha256 = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        if actual_sha256 != expected_sha256:
            raise RuntimeError(
                f"Gitleaks SHA-256 mismatch for v{version}: expected {expected_sha256}, got {actual_sha256}"
            )
        binary_path = dest_dir / "gitleaks"
        with tarfile.open(archive_path, mode="r:gz") as tf:
            member = next((m for m in tf.getmembers() if m.name == "gitleaks" and m.isfile()), None)
            if member is None:
                raise RuntimeError("Pinned Gitleaks archive did not contain a regular 'gitleaks' binary.")
            extracted = tf.extractfile(member)
            if extracted is None:
                raise RuntimeError("Could not read 'gitleaks' binary from verified archive.")
            binary_path.write_bytes(extracted.read())
        binary_path.chmod(stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        return binary_path
    finally:
        archive_path.unlink(missing_ok=True)


def extract_base_allowlist(
    repo_root: Path,
    output_path: Path,
    *,
    event_name: str = "",
    baseline_root: Path | None = None,
) -> Path:
    """
    Write the trusted `.mellyn-allowlist.toml` to `output_path` (or remove `output_path` if none applies).

    On pull requests, exemptions come strictly from the base revision (never the candidate PR tree).
    """
    output_path.unlink(missing_ok=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    is_pr = event_name in ("pull_request", "pull_request_target")
    if is_pr:
        if baseline_root is not None:
            base_file = baseline_root / ".mellyn-allowlist.toml"
            if base_file.is_file():
                shutil.copyfile(base_file, output_path)
            return output_path

        git = shutil.which("git")
        if not git:
            return output_path
        parents = subprocess.run(  # noqa: S603 - fixed git argv
            [git, "rev-list", "--parents", "-n", "1", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
        )
        # Only a 2-parent PR merge commit (`<merge> <base> <head>`) has a trusted first parent `HEAD^1`.
        if parents.returncode == 0 and len(parents.stdout.split()) == 3:
            shown = subprocess.run(  # noqa: S603 - fixed git argv
                [git, "show", "HEAD^1:.mellyn-allowlist.toml"],
                cwd=repo_root,
                capture_output=True,
                check=False,
            )
            if shown.returncode == 0:
                output_path.write_bytes(shown.stdout)
        return output_path

    merged_file = repo_root / ".mellyn-allowlist.toml"
    if merged_file.is_file():
        shutil.copyfile(merged_file, output_path)
    return output_path


def prepare_semgrepignore(target_root: Path, *, exclude_self_fixtures: bool = False) -> Path:
    """
    Delete every `.semgrepignore` under `target_root` (except `.git`) and write the standard root-anchored list,
    plus `/.semgrep/` when the target is Mellyn itself and its rule fixtures must not be scanned as code.
    """
    for dirpath, dirnames, filenames in os.walk(target_root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        if ".semgrepignore" in filenames:
            (Path(dirpath) / ".semgrepignore").unlink()
    patterns = [*SAFE_SEMGREPIGNORE_PATTERNS, *([SELF_FIXTURES_IGNORE_PATTERN] if exclude_self_fixtures else [])]
    out = target_root / ".semgrepignore"
    out.write_text("\n".join(patterns) + "\n", encoding="utf-8", newline="\n")
    return out


def compute_gitleaks_log_range(repo_root: Path, *, mode: str, env: Mapping[str, str]) -> str | None:
    """Return `--log-opts` commit range for `caller-range` mode, or `None` for full-history scans."""
    if mode == "full":
        return None
    if mode != "caller-range":
        raise ValueError(f"Unsupported Gitleaks scan mode: {mode!r}")

    event_name = env.get("EVENT_NAME", "")
    pr_base = env.get("PR_BASE_SHA", "")
    pr_head = env.get("PR_HEAD_SHA", "")
    push_before = env.get("PUSH_BEFORE_SHA", "")
    commit_sha = env.get("COMMIT_SHA", "")

    if event_name == "pull_request" and is_valid_commit_sha(pr_base) and is_valid_commit_sha(pr_head):
        return f"{pr_base}..{pr_head}"
    if event_name == "push" and is_valid_commit_sha(push_before) and is_valid_commit_sha(commit_sha):
        git = shutil.which("git")
        if git:
            exists = subprocess.run(  # noqa: S603 - fixed git argv with hex-validated SHA
                [git, "cat-file", "-e", f"{push_before}^{{commit}}"],
                cwd=repo_root,
                capture_output=True,
                check=False,
            )
            if exists.returncode == 0:
                return f"{push_before}..{commit_sha}"
    return None


def build_gitleaks_command(
    gitleaks_bin: Path,
    *,
    target_root: Path,
    guardrails_root: Path,
    empty_ignore_dir: Path,
    log_range: str | None = None,
) -> list[str]:
    """Strip `.gitleaksignore` from `target_root` and build a suppression-proof Gitleaks CLI command."""
    (target_root / ".gitleaksignore").unlink(missing_ok=True)
    empty_ignore_dir.mkdir(parents=True, exist_ok=True)
    for child in empty_ignore_dir.iterdir():
        if child.is_file():
            child.unlink()
    cmd = [
        str(gitleaks_bin.resolve()),
        "git",
        ".",
        "--config",
        str((guardrails_root / ".gitleaks.toml").resolve()),
        "--ignore-gitleaks-allow",
        "--gitleaks-ignore-path",
        str(empty_ignore_dir.resolve()),
        "--redact",
        "--no-banner",
        "--exit-code",
        "1",
    ]
    if log_range:
        cmd.append(f"--log-opts={log_range}")
    return cmd


def build_semgrep_command(
    *,
    target_root: Path,
    guardrails_root: Path,
    exclude_self_fixtures: bool = False,
) -> list[str]:
    """Replace `.semgrepignore` in `target_root` and build a `--disable-nosem` Semgrep command."""
    prepare_semgrepignore(target_root, exclude_self_fixtures=exclude_self_fixtures)
    return [
        "semgrep",
        "scan",
        "--config",
        str((guardrails_root / ".semgrep" / "owasp-ai-code-rules.yaml").resolve()),
        "--disable-nosem",
        "--error",
        "--metrics=off",
        ".",
    ]


def run_guardrail_suite(
    *,
    baseline_root: Path,
    candidate_root: Path,
    use_candidate_guardrails: bool = False,
    check_online: bool = False,
    min_age_days: int = 90,
    event_name: str = "",
    check_agent_rules: bool = True,
    run_semgrep: bool = False,
    exclude_self_fixtures: bool = False,
    quiet: bool = False,
) -> int:
    """
    Execute dependency verification, agent-rule checks, and optional Semgrep SAST against `candidate_root`
    using rules and scripts loaded strictly from the selected guardrail root (`baseline_root` by default).
    """
    guardrails = select_guardrail_root(baseline_root, candidate_root, use_candidate=use_candidate_guardrails)
    candidate = candidate_root.resolve()
    stdio_kwargs = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL} if quiet else {}

    with tempfile.TemporaryDirectory() as tmp:
        allowlist_path = Path(tmp) / "mellyn-allowlist.toml"
        # Exemptions ALWAYS come from `baseline_root` on PRs, even when testing candidate guardrail scripts!
        extract_base_allowlist(
            candidate,
            allowlist_path,
            event_name=event_name,
            baseline_root=baseline_root.resolve() if baseline_root.resolve() != candidate else None,
        )

        dep_cmd = [
            sys.executable,
            str(guardrails / "scripts" / "verify_dependencies.py"),
            "--root",
            str(candidate),
            "--min-age-days",
            str(min_age_days),
            "--allowlist",
            str(allowlist_path),
        ]
        if check_online:
            dep_cmd.append("--online")
        dep_res = subprocess.run(dep_cmd, check=False, **stdio_kwargs)  # noqa: S603
        if dep_res.returncode != 0:
            return dep_res.returncode

        if check_agent_rules:
            rules_cmd = [
                sys.executable,
                str(guardrails / "scripts" / "sync_agent_rules.py"),
                "--check",
                "--root",
                str(candidate),
            ]
            rules_res = subprocess.run(rules_cmd, check=False, **stdio_kwargs)  # noqa: S603
            if rules_res.returncode != 0:
                return rules_res.returncode

        if run_semgrep:
            semgrep_cmd = build_semgrep_command(
                target_root=candidate,
                guardrails_root=guardrails,
                exclude_self_fixtures=exclude_self_fixtures,
            )
            sg_res = subprocess.run(semgrep_cmd, cwd=candidate, check=False, **stdio_kwargs)  # noqa: S603
            if sg_res.returncode != 0:
                return sg_res.returncode

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mellyn Security trusted CI guardrail runner")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_gl_install = sub.add_parser("install-gitleaks", help="Download and SHA-256-verify pinned Gitleaks binary")
    p_gl_install.add_argument("--dest-dir", type=Path, required=True)

    p_gl_run = sub.add_parser("run-gitleaks", help="Run suppression-proof Gitleaks scan using trusted config")
    p_gl_run.add_argument("--gitleaks-bin", type=Path, required=True)
    p_gl_run.add_argument("--target", type=Path, required=True)
    p_gl_run.add_argument("--guardrails", type=Path, required=True)
    p_gl_run.add_argument("--mode", choices=("full", "caller-range"), default="full")

    p_allow = sub.add_parser("extract-allowlist", help="Extract base-commit allowlist without PR self-exemptions")
    p_allow.add_argument("--repo", type=Path, required=True)
    p_allow.add_argument("--output", type=Path, required=True)
    p_allow.add_argument("--baseline", type=Path, default=None)
    p_allow.add_argument("--event-name", default=os.environ.get("EVENT_NAME", ""))

    p_sg_ignore = sub.add_parser("prepare-semgrepignore", help="Replace all .semgrepignore files in target tree")
    p_sg_ignore.add_argument("--target", type=Path, required=True)

    p_sg_run = sub.add_parser("run-semgrep", help="Replace .semgrepignore and run Semgrep with --disable-nosem")
    p_sg_run.add_argument("--target", type=Path, required=True)
    p_sg_run.add_argument("--guardrails", type=Path, required=True)
    p_sg_run.add_argument("--exclude-self-fixtures", action="store_true")

    p_suite = sub.add_parser("run-suite", help="Run baseline or candidate guardrail checks against candidate tree")
    p_suite.add_argument("--baseline", type=Path, required=True)
    p_suite.add_argument("--candidate", type=Path, required=True)
    p_suite.add_argument("--use-candidate-guardrails", action="store_true")
    p_suite.add_argument("--online", action="store_true")
    p_suite.add_argument("--min-age-days", type=int, default=90)
    p_suite.add_argument("--event-name", default=os.environ.get("EVENT_NAME", ""))
    p_suite.add_argument("--skip-agent-rules", action="store_true")
    p_suite.add_argument("--run-semgrep", action="store_true")
    p_suite.add_argument("--exclude-self-fixtures", action="store_true")

    args = parser.parse_args(argv)

    if args.subcommand == "install-gitleaks":
        binary = install_gitleaks(args.dest_dir)
        print(f"Installed verified Gitleaks v{GITLEAKS_VERSION} -> {binary}")
        return 0

    if args.subcommand == "run-gitleaks":
        target = args.target.resolve()
        guardrails = args.guardrails.resolve()
        log_range = compute_gitleaks_log_range(target, mode=args.mode, env=os.environ)
        print(f"Scanning {log_range or 'full history'} in {target} with {guardrails / '.gitleaks.toml'}")
        with tempfile.TemporaryDirectory() as empty_dir:
            cmd = build_gitleaks_command(
                args.gitleaks_bin,
                target_root=target,
                guardrails_root=guardrails,
                empty_ignore_dir=Path(empty_dir),
                log_range=log_range,
            )
            return subprocess.run(cmd, cwd=target, check=False).returncode  # noqa: S603

    if args.subcommand == "extract-allowlist":
        extract_base_allowlist(
            args.repo.resolve(),
            args.output.resolve(),
            event_name=args.event_name,
            baseline_root=args.baseline.resolve() if args.baseline else None,
        )
        return 0

    if args.subcommand == "prepare-semgrepignore":
        prepare_semgrepignore(args.target.resolve())
        return 0

    if args.subcommand == "run-semgrep":
        target = args.target.resolve()
        cmd = build_semgrep_command(
            target_root=target,
            guardrails_root=args.guardrails.resolve(),
            exclude_self_fixtures=args.exclude_self_fixtures,
        )
        return subprocess.run(cmd, cwd=target, check=False).returncode  # noqa: S603

    if args.subcommand == "run-suite":
        return run_guardrail_suite(
            baseline_root=args.baseline,
            candidate_root=args.candidate,
            use_candidate_guardrails=args.use_candidate_guardrails,
            check_online=args.online,
            min_age_days=args.min_age_days,
            event_name=args.event_name,
            check_agent_rules=not args.skip_agent_rules,
            run_semgrep=args.run_semgrep,
            exclude_self_fixtures=args.exclude_self_fixtures,
        )

    return 2


if __name__ == "__main__":
    sys.exit(main())
