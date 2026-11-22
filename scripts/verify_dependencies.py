#!/usr/bin/env python3
"""
OWASP Secure Coding with AI — Dependency & Anti-Slopsquatting Verifier.

Threat model: a coding agent adds a dependency whose name it hallucinated. Attackers
pre-register commonly hallucinated names ("slopsquatting"), so "the package exists"
proves nothing. This verifier therefore checks:

Offline (always):
  1. Every dependency is version-constrained with a meaningful floor (no ``>=0``, ``*``, ``latest``).
  2. No dependency is pulled from a non-registry source (git, URL, local path, tarball).
  3. Names are syntactically valid and do not match known hallucinated names.

Online (``--online``), against PyPI and the npm registry:
  4. The package exists.
  5. The package's first release is older than ``--min-age-days`` (default 90). Freshly
     registered packages are the signature of a slopsquat; review them by hand and add
     them to ``--allow-new`` once vetted.

Network failures fail closed: a package that cannot be verified is reported.
Only the Python standard library is used.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# Known AI-hallucinated / squatted names. A denylist can never be complete; the online
# age check is the real control. Keep this list for fast offline feedback only.
KNOWN_SLOPSQUAT_NAMES: frozenset[str] = frozenset(
    {
        "openai-sdk",
        "anthropic-cli-tools",
        "fastapi-security-utils",
        "langchain-secure-agent",
        "python-jwt-auth",
        "nextjs-auth-guard",
        "crypto-hash-utils",
    }
)

DEFAULT_MIN_AGE_DAYS = 90
USER_AGENT = "dependency-verifier/2.0 (+stdlib urllib)"
_NO_EXEMPTIONS: frozenset[str] = frozenset()

PYPI_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
NPM_NAME_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")

# PEP 508: name, optional extras, then the rest (specifiers, URL, markers).
PEP508_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")
PY_FLOOR_RE = re.compile(r"(==|>=|~=|===)\s*([0-9][0-9A-Za-z_.+!-]*)")
ZERO_VERSION_RE = re.compile(r"^0+(?:\.0+)*$")

NPM_NON_REGISTRY_PREFIXES = ("git", "http:", "https:", "file:", "link:", "github:", "gitlab:", "bitbucket:", "npm:")
NPM_FLOOR_RE = re.compile(r"(?:^|[\s^~=>v])(\d+(?:\.\d+){0,2})")


def normalize_pypi_name(name: str) -> str:
    """PEP 503 normalization."""
    return re.sub(r"[-_.]+", "-", name).lower()


def check_package_name_hygiene(pkg_name: str, ecosystem: str) -> list[str]:
    """Validate package-name syntax and compare against known hallucinated names."""
    issues: list[str] = []
    name_re = PYPI_NAME_RE if ecosystem == "pypi" else NPM_NAME_RE
    if not name_re.match(pkg_name):
        issues.append(f"[INVALID NAME] '{pkg_name}' is not a valid {ecosystem} package name.")
        return issues
    normalized = normalize_pypi_name(pkg_name) if ecosystem == "pypi" else pkg_name.lower()
    if normalized in KNOWN_SLOPSQUAT_NAMES:
        issues.append(f"[SLOPSQUAT ALERT] '{pkg_name}' is a known AI-hallucinated package name.")
    return issues


# --------------------------------------------------------------------------- #
# Spec parsing
# --------------------------------------------------------------------------- #
def parse_python_spec(spec: str, source: str) -> tuple[str | None, list[str]]:
    """Return (package name, issues) for one PEP 508 requirement string."""
    match = PEP508_RE.match(spec)
    if not match:
        return None, [f"[UNPARSEABLE] '{spec}' in {source} is not a valid requirement."]
    name, _extras, rest = match.groups()
    requirement = rest.split(";", 1)[0].strip()  # drop environment markers
    issues: list[str] = []

    if requirement.startswith("@") or "://" in requirement:
        issues.append(f"[NON-REGISTRY SOURCE] '{spec}' in {source} installs from a URL/VCS, bypassing registry checks.")
        return name, issues

    floors = PY_FLOOR_RE.findall(requirement)
    if not floors:
        issues.append(f"[UNPINNED DEP] '{spec}' in {source} has no version floor (use ==, ~=, or >=X.Y).")
    elif all(ZERO_VERSION_RE.match(version) for _op, version in floors):
        issues.append(f"[UNPINNED DEP] '{spec}' in {source} has a zero floor, which constrains nothing.")
    return name, issues


def parse_requirements_txt(path: Path) -> list[str]:
    """Extract requirement strings from a requirements file (options and includes are skipped)."""
    specs: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-e", "--editable")):
            specs.append(line)  # reported as non-registry below
            continue
        if line.startswith("-"):
            continue  # -r, -c, --hash, --index-url, ...
        specs.append(line.split(" --hash", 1)[0].rstrip(" \\"))
    return specs


def check_npm_spec(pkg_name: str, version_spec: str, source: str) -> list[str]:
    spec = version_spec.strip()
    if spec.startswith("workspace:"):
        return []  # local monorepo package, resolved by the package manager, not the registry
    if spec.startswith(NPM_NON_REGISTRY_PREFIXES) or ("/" in spec and not spec.startswith("@")):
        return [f"[NON-REGISTRY SOURCE] npm '{pkg_name}' in {source} uses '{spec}', bypassing registry checks."]
    if spec in ("", "*", "x", "X", "latest", "next") or spec.startswith(("*", "x.", "X.")):
        return [f"[UNPINNED DEP] npm '{pkg_name}' in {source} uses wildcard/tag '{spec}'."]
    floors = NPM_FLOOR_RE.findall(spec)
    if not floors or all(ZERO_VERSION_RE.match(v) for v in floors):
        return [f"[UNPINNED DEP] npm '{pkg_name}' in {source} uses '{spec}', which has no meaningful floor."]
    return []


# --------------------------------------------------------------------------- #
# Registry checks
# --------------------------------------------------------------------------- #
def _fetch_json(url: str, timeout: float) -> dict:
    """GET a JSON document. Callers only pass fixed https:// registry URLs."""
    if not url.startswith(("https://pypi.org/", "https://registry.npmjs.org/")):
        raise ValueError(f"refusing to fetch non-registry URL: {url}")
    # S310 is satisfied by the https + registry-host allowlist check above.
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": USER_AGENT})  # noqa: S310
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8"))


def _parse_time(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)


def pypi_first_release(pkg_name: str, timeout: float) -> dt.datetime | None:
    data = _fetch_json(f"https://pypi.org/pypi/{urllib.parse.quote(pkg_name, safe='')}/json", timeout)
    uploads = [
        _parse_time(f["upload_time_iso_8601"])
        for files in data.get("releases", {}).values()
        for f in files
        if f.get("upload_time_iso_8601")
    ]
    return min(uploads) if uploads else None


def npm_first_release(pkg_name: str, timeout: float) -> dt.datetime | None:
    data = _fetch_json(f"https://registry.npmjs.org/{urllib.parse.quote(pkg_name, safe='@')}", timeout)
    created = data.get("time", {}).get("created")
    return _parse_time(created) if created else None


def verify_registry(
    pkg_name: str,
    ecosystem: str,
    min_age_days: int,
    allow_new: frozenset[str],
    timeout: float = 10.0,
    now: dt.datetime | None = None,
) -> list[str]:
    """Confirm the package exists and is not freshly registered. Fails closed."""
    lookup = pypi_first_release if ecosystem == "pypi" else npm_first_release
    try:
        first_release = lookup(pkg_name, timeout)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return [f"[HALLUCINATION] {ecosystem} package '{pkg_name}' does not exist (HTTP 404)."]
        return [f"[UNVERIFIED] {ecosystem} package '{pkg_name}': registry returned HTTP {exc.code} (failing closed)."]
    except (OSError, ValueError) as exc:  # URLError, timeouts, resets, bad JSON
        return [f"[UNVERIFIED] {ecosystem} package '{pkg_name}': {exc} (failing closed)."]

    if first_release is None:
        return [f"[SUPPLY CHAIN] {ecosystem} package '{pkg_name}' has no published releases."]

    key = normalize_pypi_name(pkg_name) if ecosystem == "pypi" else pkg_name.lower()
    age_days = ((now or dt.datetime.now(dt.UTC)) - first_release).days
    if age_days < min_age_days and key not in allow_new:
        return [
            f"[NEW PACKAGE] {ecosystem} package '{pkg_name}' was first published {age_days} days ago "
            f"(< {min_age_days}). Review it manually, then pass --allow-new {pkg_name}."
        ]
    return []


# --------------------------------------------------------------------------- #
# Manifest verification
# --------------------------------------------------------------------------- #
def _check_python_specs(
    specs: list[str], source: str, online: bool, min_age_days: int, allow_new: frozenset[str]
) -> list[str]:
    issues: list[str] = []
    for spec in specs:
        if spec.startswith(("-e", "--editable")):
            issues.append(f"[NON-REGISTRY SOURCE] '{spec}' in {source} is an editable/local install.")
            continue
        name, spec_issues = parse_python_spec(spec, source)
        issues.extend(spec_issues)
        if not name:
            continue
        name_issues = check_package_name_hygiene(name, "pypi")
        issues.extend(name_issues)
        if online and not name_issues:
            issues.extend(verify_registry(name, "pypi", min_age_days, allow_new))
    return issues


def verify_pyproject_toml(
    path: Path,
    check_online: bool = False,
    min_age_days: int = DEFAULT_MIN_AGE_DAYS,
    allow_new: frozenset[str] = _NO_EXEMPTIONS,
) -> list[str]:
    if not path.exists():
        return []
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    project = data.get("project", {})
    specs = list(project.get("dependencies", []))
    for group in project.get("optional-dependencies", {}).values():
        specs.extend(group)
    for group in data.get("dependency-groups", {}).values():  # PEP 735
        specs.extend(s for s in group if isinstance(s, str))
    return _check_python_specs(specs, path.name, check_online, min_age_days, allow_new)


def verify_requirements_txt(
    path: Path,
    check_online: bool = False,
    min_age_days: int = DEFAULT_MIN_AGE_DAYS,
    allow_new: frozenset[str] = _NO_EXEMPTIONS,
) -> list[str]:
    if not path.exists():
        return []
    return _check_python_specs(parse_requirements_txt(path), path.name, check_online, min_age_days, allow_new)


def verify_package_json(
    path: Path,
    check_online: bool = False,
    min_age_days: int = DEFAULT_MIN_AGE_DAYS,
    allow_new: frozenset[str] = _NO_EXEMPTIONS,
) -> list[str]:
    if not path.exists():
        return []
    issues: list[str] = []
    data = json.loads(path.read_text(encoding="utf-8"))
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for pkg_name, version_spec in data.get(section, {}).items():
            issues.extend(check_npm_spec(pkg_name, str(version_spec), str(path)))
            name_issues = check_package_name_hygiene(pkg_name, "npm")
            issues.extend(name_issues)
            if check_online and not name_issues:
                issues.extend(verify_registry(pkg_name, "npm", min_age_days, allow_new))
    return issues


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OWASP AI Supply Chain & Slopsquatting Dependency Verifier")
    parser.add_argument("--root", type=Path, default=Path("."), help="Repository root directory")
    parser.add_argument("--online", action="store_true", help="Check PyPI/npm for existence and package age")
    parser.add_argument("--min-age-days", type=int, default=DEFAULT_MIN_AGE_DAYS, help="Minimum package age")
    parser.add_argument(
        "--allow-new", nargs="*", default=[], metavar="PKG", help="Manually vetted packages exempt from the age check"
    )
    args = parser.parse_args(argv)

    root: Path = args.root.resolve()
    allow_new = frozenset(normalize_pypi_name(p) for p in args.allow_new) | frozenset(p.lower() for p in args.allow_new)
    opts = {"check_online": args.online, "min_age_days": args.min_age_days, "allow_new": allow_new}

    issues: list[str] = []
    issues.extend(verify_pyproject_toml(root / "pyproject.toml", **opts))
    for req in sorted(root.glob("requirements*.txt")) + sorted((root / "backend").glob("requirements*.txt")):
        issues.extend(verify_requirements_txt(req, **opts))
    issues.extend(verify_package_json(root / "package.json", **opts))
    issues.extend(verify_package_json(root / "frontend" / "package.json", **opts))

    if issues:
        print("OWASP AI Dependency Verification FAILED:")
        for issue in issues:
            print(f"  - {issue}")
        return 1

    mode = f"online, min age {args.min_age_days}d" if args.online else "offline; run with --online for registry checks"
    print(f"OWASP AI Dependency Verification PASSED ({mode}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
