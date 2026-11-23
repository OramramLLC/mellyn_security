#!/usr/bin/env python3
"""
OWASP Secure Coding with AI — Dependency, Lockfile & Anti-Slopsquatting Verifier.

Threat model:
  1. A coding agent adds a dependency whose name it hallucinated ("slopsquatting").
  2. A transitive dependency in a lockfile pulls from an unverified git/URL source or lacks hashes.
  3. An attacker compromises an older, established package and pushes a brand-new malicious version.

Checks performed:
  Offline (always):
    - Direct manifests (`pyproject.toml`, `requirements*.txt`, `package.json`): meaningful version
      floors (no `>=0`, `*`, `latest`), registry-only sources, valid syntax, and slopsquat denylist.
    - Lockfiles (`requirements*.lock` / `deploy/requirements.lock`, `uv.lock`, `package-lock.json`):
      exact versions, SHA-256 hashes (for `.lock`), registry-only sources, and transitive hygiene.
    - `.mellyn-allowlist.toml` (if present): strict schema, non-empty reviewer/rationale, and
      non-expired `expires = "YYYY-MM-DD"` dates (expired exemptions fail closed).

  Online (`--online`), against PyPI and the npm registry:
    - Every direct AND locked transitive package exists.
    - Package's first release is at least `--min-age-days` old (default 90).
    - Every exact-pinned version (`==X.Y.Z` or lockfile version) exists and was published at least
      `--min-release-age-days` ago (default 14), defending against sudden account-takeover pushes.

Network failures fail closed. Uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, NamedTuple

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
DEFAULT_MIN_RELEASE_AGE_DAYS = 14
USER_AGENT = "dependency-verifier/3.0 (+stdlib urllib)"
_NO_EXEMPTIONS: frozenset[str] = frozenset()

PYPI_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
NPM_NAME_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")

PEP508_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")
PY_FLOOR_RE = re.compile(r"(==|>=|~=|===)\s*([0-9][0-9A-Za-z_.+!-]*)")
PY_EXACT_RE = re.compile(r"^\s*(?:==|===)\s*([0-9][0-9A-Za-z_.+!-]*)\s*$")
ZERO_VERSION_RE = re.compile(r"^0+(?:\.0+)*$")
SHA256_HASH_RE = re.compile(r"--hash=sha256:[0-9a-f]{64}\b")

NPM_NON_REGISTRY_PREFIXES = ("git", "http:", "https:", "file:", "link:", "github:", "gitlab:", "bitbucket:", "npm:")
NPM_FLOOR_RE = re.compile(r"(?:^|[\s^~=>v])(\d+(?:\.\d+){0,2})")
NPM_EXACT_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")

_ALLOWLIST_TOP_KEYS = frozenset({"schema_version", "exemptions"})
_ALLOWLIST_ENTRY_KEYS = frozenset({"package", "ecosystem", "reason", "approved_by", "expires"})

# Per-process cache of fetched registry JSON documents so checking package age + exact version age
# for the same package issues only one HTTPS request.
_JSON_CACHE: dict[str, dict[str, Any]] = {}


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
# Audited allowlist (.mellyn-allowlist.toml)
# --------------------------------------------------------------------------- #
MAX_EXEMPTION_DAYS = 180


def release_exemption_key(ecosystem: str, normalized_name: str, version: str) -> str:
    """Key that exempts ONE exact version from the release-age cooldown (`pypi:name==1.2.3`)."""
    return f"{ecosystem}:{normalized_name}=={version}"


def load_allowlist_file(path: Path, *, now: dt.datetime | None = None) -> tuple[frozenset[str], list[str]]:
    """
    Load `.mellyn-allowlist.toml` if present. Returns `(exempt_keys, issues)`.

    An entry exempts its package from the new-package age check (`pypi:name`). The release-age cooldown is
    exempted only for the exact versions an entry lists under `versions` (`pypi:name==1.2.3`), so approving a
    package never pre-approves its future releases. Entries must expire within MAX_EXEMPTION_DAYS. Expired
    or malformed entries fail closed.
    """
    if not path.exists():
        return _NO_EXEMPTIONS, []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return _NO_EXEMPTIONS, [f"[ALLOWLIST ERROR] Failed to parse {path.name}: {exc}"]

    if not isinstance(data, dict) or (set(data) - _ALLOWLIST_TOP_KEYS):
        unknown = sorted(set(data) - _ALLOWLIST_TOP_KEYS) if isinstance(data, dict) else ["root"]
        return _NO_EXEMPTIONS, [f"[ALLOWLIST ERROR] Unknown key(s) in {path.name}: {unknown}"]
    if data.get("schema_version") != 1:
        return _NO_EXEMPTIONS, [f"[ALLOWLIST ERROR] {path.name} requires schema_version = 1."]

    entries = data.get("exemptions", [])
    if not isinstance(entries, list):
        return _NO_EXEMPTIONS, [f"[ALLOWLIST ERROR] 'exemptions' in {path.name} must be a list."]

    today = (now or dt.datetime.now(dt.UTC)).date()
    exempt: set[str] = set()
    issues: list[str] = []

    for idx, entry in enumerate(entries):
        keys = set(entry) if isinstance(entry, dict) else set()
        if not isinstance(entry, dict) or not _ALLOWLIST_ENTRY_KEYS <= keys <= _ALLOWLIST_ENTRY_KEYS | {"versions"}:
            issues.append(
                f"[ALLOWLIST ERROR] exemptions[{idx}] in {path.name} must have keys {sorted(_ALLOWLIST_ENTRY_KEYS)} "
                "and may add 'versions'."
            )
            continue
        pkg = entry["package"]
        eco = entry["ecosystem"]
        reason = entry["reason"]
        approved_by = entry["approved_by"]
        expires_raw = entry["expires"]
        versions = entry.get("versions", [])
        if not all(isinstance(v, str) and v.strip() for v in (pkg, eco, reason, approved_by, expires_raw)):
            issues.append(f"[ALLOWLIST ERROR] exemptions[{idx}] in {path.name} has empty or non-string fields.")
            continue
        if not isinstance(versions, list) or not all(isinstance(v, str) and v.strip() for v in versions):
            issues.append(f"[ALLOWLIST ERROR] exemptions[{idx}] 'versions' must be a list of exact version strings.")
            continue
        eco_norm = eco.strip().lower()
        if eco_norm not in ("pypi", "npm"):
            issues.append(f"[ALLOWLIST ERROR] exemptions[{idx}] ecosystem must be 'pypi' or 'npm', got '{eco}'.")
            continue
        try:
            exp_date = dt.date.fromisoformat(expires_raw.strip())
        except ValueError:
            issues.append(f"[ALLOWLIST ERROR] exemptions[{idx}] expires '{expires_raw}' must be YYYY-MM-DD.")
            continue
        if exp_date < today:
            issues.append(
                f"[ALLOWLIST EXPIRED] Exemption for {eco_norm} '{pkg}' expired on {exp_date.isoformat()}; "
                "re-review or remove it."
            )
            continue
        if (exp_date - today).days > MAX_EXEMPTION_DAYS:
            issues.append(
                f"[ALLOWLIST ERROR] Exemption for {eco_norm} '{pkg}' expires {exp_date.isoformat()}, more than "
                f"{MAX_EXEMPTION_DAYS} days ahead; exemptions must be re-reviewed at least that often."
            )
            continue
        norm_pkg = normalize_pypi_name(pkg.strip()) if eco_norm == "pypi" else pkg.strip().lower()
        exempt.add(f"{eco_norm}:{norm_pkg}")
        exempt.update(release_exemption_key(eco_norm, norm_pkg, v.strip()) for v in versions)
    return frozenset(exempt), issues


def _is_exempt(key: str, ecosystem: str, allow_new: frozenset[str]) -> bool:
    return key in allow_new or f"{ecosystem}:{key}" in allow_new


# --------------------------------------------------------------------------- #
# Spec & lockfile parsing
# --------------------------------------------------------------------------- #
class LockedPackage(NamedTuple):
    """One locked dependency: its registry name, exact version and the artifact hashes the lock pins."""

    name: str
    version: str
    hashes: tuple[str, ...] = ()  # "sha256:<hex>" (PyPI) or "sha512-<base64>" (npm integrity)
    alias: str | None = None  # npm: the name it is installed under, when that differs from `name`
    install_path: str | None = None  # lockfile occurrence path (e.g. "node_modules/a/node_modules/pkg")


# pip options that change where packages come from. In a requirements file or lockfile they would let the
# file install packages the registry checks never looked at.
_INDEX_OPTIONS: frozenset[str] = frozenset(
    {"-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--trusted-host"}
)
_INCLUDE_OPTIONS: frozenset[str] = frozenset({"-r", "--requirement", "-c", "--constraint"})
# Naming PyPI's own index changes nothing, so it is the one index value accepted.
_PYPI_INDEX_URLS: frozenset[str] = frozenset({"https://pypi.org/simple", "https://pypi.org/simple/"})
_EDITABLE_OPTIONS: frozenset[str] = frozenset({"-e", "--editable"})
# The only options a hash-pinned lockfile may carry.
_LOCK_ALLOWED_OPTIONS: frozenset[str] = frozenset({"--require-hashes", "--only-binary", "--prefer-binary"})


def _option_name(token: str) -> str:
    """'--index-url=https://x' -> '--index-url'; '-ihttps://x' -> '-i' (pip accepts both spellings)."""
    if token.startswith("--"):
        return token.split("=", 1)[0]
    return token[:2]


def _option_value(entry: str) -> str:
    token, _, rest = entry.partition(" ")
    if token.startswith("--") and "=" in token:
        return token.split("=", 1)[1].strip()
    if not token.startswith("--") and len(token) > 2:
        return token[2:].strip()
    return rest.strip()


def parse_python_spec(spec: str, source: str) -> tuple[str | None, list[str]]:
    """Return `(package name, issues)` for one PEP 508 requirement string."""
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


def extract_exact_python_version(spec: str) -> str | None:
    match = PEP508_RE.match(spec)
    if not match:
        return None
    requirement = match.group(3).split(";", 1)[0].strip()
    exact = PY_EXACT_RE.match(requirement)
    return exact.group(1) if exact else None


def _logical_lines(path: Path) -> list[str]:
    """Requirement-file lines with comments removed and `\\` continuations joined."""
    lines: list[str] = []
    buf = ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.split(" #", 1)[0].strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            buf += stripped[:-1].strip() + " "
        else:
            lines.append((buf + stripped).strip())
            buf = ""
    if buf.strip():
        lines.append(buf.strip())
    return lines


def read_requirements_txt(path: Path, root: Path) -> tuple[list[str], list[Path], list[str]]:
    """
    Read a requirements file in a single pass, returning `(specs, included_files, option_issues)`.

    Index and find-links options are rejected (they redirect where packages come from). `-r`/`-c` includes
    are followed so the included file is verified as well, but only for local files inside the repository.
    """
    specs: list[str] = []
    includes: list[Path] = []
    issues: list[str] = []
    resolved_root = root.resolve()
    for line in _logical_lines(path):
        opt = _option_name(line.split()[0])
        if opt in _EDITABLE_OPTIONS:
            specs.append(line)  # reported as non-registry by _check_python_specs / parse_python_spec
            continue
        if line.startswith("-"):
            if opt in _INDEX_OPTIONS:
                if opt in ("-i", "--index-url") and _option_value(line) in _PYPI_INDEX_URLS:
                    continue
                issues.append(f"[NON-REGISTRY SOURCE] '{opt}' in {path.name} changes the package index; not allowed.")
            elif opt in _INCLUDE_OPTIONS:
                target = _option_value(line)
                if "://" in target:
                    issues.append(f"[NON-REGISTRY SOURCE] '{opt} {target}' in {path.name} includes a remote file.")
                    continue
                included = (path.parent / target).resolve()
                try:
                    included.relative_to(resolved_root)
                except ValueError:
                    issues.append(
                        f"[NON-REGISTRY SOURCE] '{opt} {target}' in {path.name} points outside the repository."
                    )
                    continue
                if not included.is_file():
                    issues.append(f"[UNPARSEABLE] '{opt} {target}' in {path.name}: included file does not exist.")
                    continue
                includes.append(included)
            continue
        specs.append(line.split(" --hash", 1)[0].strip())
    return specs, includes, issues


def parse_requirements_txt(path: Path) -> list[str]:
    """Extract requirement strings from a requirements file."""
    specs, _, _ = read_requirements_txt(path, path.parent)
    return specs


def requirements_txt_options(path: Path, root: Path) -> tuple[list[Path], list[str]]:
    """Extract `(included files, option issues)` from a requirements file."""
    _, includes, issues = read_requirements_txt(path, root)
    return includes, issues


def parse_requirements_lock(path: Path) -> tuple[list[LockedPackage], list[str]]:
    """
    Parse a pip hash-pinned `.lock` file (with `\\` line continuations).

    Every entry must pin an exact `==version` and at least one `--hash=sha256:...`. A lockfile must be
    self-contained: index/find-links options, includes and editables are rejected, and any other option
    outside _LOCK_ALLOWED_OPTIONS fails closed.
    """
    locked: list[LockedPackage] = []
    issues: list[str] = []
    for entry in _logical_lines(path):
        if entry.startswith("-"):
            opt = _option_name(entry.split()[0])
            if opt in ("-i", "--index-url") and _option_value(entry) in _PYPI_INDEX_URLS:
                continue
            if opt in _INDEX_OPTIONS or opt in _INCLUDE_OPTIONS or opt in _EDITABLE_OPTIONS:
                issues.append(f"[NON-REGISTRY SOURCE] Disallowed option '{opt}' in {path.name}.")
            elif opt not in _LOCK_ALLOWED_OPTIONS:
                issues.append(f"[DISALLOWED OPTION] '{opt}' in {path.name} is not allowed in a lockfile.")
            continue
        hashes = tuple(f"sha256:{h[len('--hash=sha256:') :]}" for h in SHA256_HASH_RE.findall(entry))
        if not hashes:
            issues.append(f"[MISSING HASH] '{entry.split()[0]}' in {path.name} lacks a --hash=sha256:... digest.")
        spec_part = entry.split("--hash=")[0].strip()
        name, spec_issues = parse_python_spec(spec_part, path.name)
        issues.extend(spec_issues)
        exact_ver = extract_exact_python_version(spec_part)
        if name and not exact_ver:
            issues.append(f"[UNPINNED LOCK] '{spec_part}' in {path.name} must use exact '==' pinning.")
        elif name and exact_ver:
            locked.append(LockedPackage(name, exact_ver, hashes))
    return locked, issues


_PYPI_FILES_PREFIX = "https://files.pythonhosted.org/"


def parse_uv_lock(path: Path) -> tuple[list[LockedPackage], list[str]]:
    """Parse `uv.lock` TOML `[[package]]` entries for third-party registry dependencies."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return [], [f"[UNPARSEABLE] Failed to parse {path.name}: {exc}"]

    locked: list[LockedPackage] = []
    issues: list[str] = []
    for pkg in data.get("package", []):
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        version = pkg.get("version")
        source = pkg.get("source", {})
        if not isinstance(source, dict):
            source = {}
        # Root workspace / virtual project entry in uv.lock
        if source.get("virtual") == "." or source.get("editable") == ".":
            continue
        if any(k in source for k in ("git", "url", "path", "directory", "editable")):
            issues.append(f"[NON-REGISTRY SOURCE] '{name}' in {path.name} uses non-registry source {source}.")
            continue
        registry = source.get("registry", "")
        if registry and not str(registry).startswith("https://pypi.org/"):
            issues.append(f"[NON-REGISTRY SOURCE] '{name}' in {path.name} uses untrusted registry '{registry}'.")
            continue
        if not isinstance(name, str) or not isinstance(version, str) or not version.strip():
            issues.append(f"[UNPINNED LOCK] Malformed package entry '{name}' in {path.name}.")
            continue
        artifacts = [pkg.get("sdist")] + list(pkg.get("wheels", []) or [])
        hashes: list[str] = []
        bad_url = False
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                continue
            url = str(artifact.get("url", ""))
            if url and not url.startswith(_PYPI_FILES_PREFIX):
                issues.append(f"[NON-REGISTRY SOURCE] '{name}' in {path.name} downloads an artifact from '{url}'.")
                bad_url = True
            digest = artifact.get("hash")
            if isinstance(digest, str) and digest.startswith("sha256:"):
                hashes.append(digest)
        if bad_url:
            continue
        locked.append(LockedPackage(name, version.strip(), tuple(hashes)))
    return locked, issues


def parse_package_lock_json(path: Path) -> tuple[list[LockedPackage], list[str]]:
    """
    Parse npm `package-lock.json` (lockfileVersion 2/3) transitive packages.

    An alias (`"lodash": "npm:evil-lodash@1.0.0"`) is stored under `node_modules/lodash` with
    `"name": "evil-lodash"`; it is checked under its real registry name, and its `resolved` URL must be
    that package's own tarball on registry.npmjs.org.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return [], [f"[UNPARSEABLE] Failed to parse {path.name}: {exc}"]

    packages = data.get("packages")
    if not isinstance(packages, dict):
        return [], [f"[UNPARSEABLE] {path.name} missing 'packages' object (use npm lockfileVersion 2 or 3)."]

    locked: list[LockedPackage] = []
    issues: list[str] = []
    for pkg_path, meta in packages.items():
        if pkg_path == "" or not isinstance(meta, dict) or meta.get("link") is True:
            continue
        if "node_modules/" not in pkg_path:
            continue
        installed_as = pkg_path.rsplit("node_modules/", 1)[-1]
        real_name = meta.get("name") if isinstance(meta.get("name"), str) else installed_as
        label = real_name if real_name == installed_as else f"{installed_as} (alias of {real_name})"
        version = meta.get("version")
        resolved = str(meta.get("resolved", ""))
        if resolved and not resolved.startswith(f"https://registry.npmjs.org/{real_name}/-/"):
            issues.append(
                f"[NON-REGISTRY SOURCE] npm '{label}' at '{pkg_path}' in {path.name} resolves from '{resolved}'."
            )
            continue
        if not isinstance(version, str) or not NPM_EXACT_RE.match(version.strip()):
            issues.append(
                f"[UNPINNED LOCK] npm '{label}' at '{pkg_path}' in {path.name} lacks an exact semver version."
            )
            continue
        integrity = meta.get("integrity")
        hashes = (integrity,) if isinstance(integrity, str) and integrity.startswith("sha512-") else ()
        alias = installed_as if installed_as != real_name else None
        locked.append(LockedPackage(real_name, version.strip(), hashes, alias, pkg_path))
    return locked, issues


def check_npm_spec(pkg_name: str, version_spec: str, source: str) -> list[str]:
    spec = version_spec.strip()
    if spec.startswith("workspace:"):
        return []
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
def _fetch_json(url: str, timeout: float) -> dict[str, Any]:
    """GET a JSON document from canonical PyPI or npm HTTPS endpoints (cached per URL)."""
    if not url.startswith(("https://pypi.org/", "https://registry.npmjs.org/")):
        raise ValueError(f"refusing to fetch non-registry URL: {url}")
    if url in _JSON_CACHE:
        return _JSON_CACHE[url]
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": USER_AGENT})  # noqa: S310
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        parsed: dict[str, Any] = json.loads(resp.read().decode("utf-8"))
    _JSON_CACHE[url] = parsed
    return parsed


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


def pypi_version_release(pkg_name: str, version: str, timeout: float) -> dt.datetime | None:
    data = _fetch_json(f"https://pypi.org/pypi/{urllib.parse.quote(pkg_name, safe='')}/json", timeout)
    files = data.get("releases", {}).get(version)
    if not files:
        return None
    uploads = [_parse_time(f["upload_time_iso_8601"]) for f in files if f.get("upload_time_iso_8601")]
    return min(uploads) if uploads else None


def npm_first_release(pkg_name: str, timeout: float) -> dt.datetime | None:
    data = _fetch_json(f"https://registry.npmjs.org/{urllib.parse.quote(pkg_name, safe='@')}", timeout)
    created = data.get("time", {}).get("created")
    return _parse_time(created) if created else None


def npm_version_release(pkg_name: str, version: str, timeout: float) -> dt.datetime | None:
    data = _fetch_json(f"https://registry.npmjs.org/{urllib.parse.quote(pkg_name, safe='@')}", timeout)
    ts = data.get("time", {}).get(version)
    return _parse_time(ts) if isinstance(ts, str) and ts else None


def pypi_release_sha256s(pkg_name: str, version: str, timeout: float) -> set[str] | None:
    """SHA-256 digests of every file PyPI serves for this release, as 'sha256:<hex>'; None if no such release."""
    data = _fetch_json(f"https://pypi.org/pypi/{urllib.parse.quote(pkg_name, safe='')}/json", timeout)
    files = data.get("releases", {}).get(version)
    if not files:
        return None
    return {f"sha256:{f['digests']['sha256']}" for f in files if f.get("digests", {}).get("sha256")}


def npm_release_integrity(pkg_name: str, version: str, timeout: float) -> str | None:
    """The registry's `dist.integrity` (sha512-...) for this version; None if the version does not exist."""
    data = _fetch_json(f"https://registry.npmjs.org/{urllib.parse.quote(pkg_name, safe='@')}", timeout)
    dist = data.get("versions", {}).get(version, {}).get("dist", {})
    integrity = dist.get("integrity") if isinstance(dist, dict) else None
    return integrity if isinstance(integrity, str) else None


def verify_locked_hashes(
    pkg: LockedPackage,
    ecosystem: str,
    timeout: float = 10.0,
    *,
    _published_cache: dict[tuple[str, str, str], set[str] | None | Exception] | None = None,
) -> list[str]:
    """
    Every hash a lockfile pins must be one the registry itself publishes for that exact release. Otherwise
    the lock can name a real, old package while installing a different artifact. Fails closed.
    """
    base_label = f"{pkg.alias} (alias of {pkg.name})" if pkg.alias else pkg.name
    loc = f" at '{pkg.install_path}'" if pkg.install_path else ""
    label = f"{base_label}{loc}"
    if not pkg.hashes:
        return [f"[MISSING HASH] {ecosystem} '{base_label}=={pkg.version}'{loc} has no artifact hash to verify."]
    norm_name = normalize_pypi_name(pkg.name) if ecosystem == "pypi" else pkg.name.lower()
    cache_key = (ecosystem, norm_name, pkg.version)
    if _published_cache is not None and cache_key in _published_cache:
        cached = _published_cache[cache_key]
        if isinstance(cached, Exception):
            return [f"[UNVERIFIED] {ecosystem} '{base_label}=={pkg.version}'{loc} hashes: {cached} (failing closed)."]
        published = cached
    else:
        try:
            if ecosystem == "pypi":
                published = pypi_release_sha256s(pkg.name, pkg.version, timeout)
            else:
                integrity = npm_release_integrity(pkg.name, pkg.version, timeout)
                published = {integrity} if integrity else None
        except (OSError, ValueError, KeyError) as exc:
            if _published_cache is not None:
                _published_cache[cache_key] = exc
            return [f"[UNVERIFIED] {ecosystem} '{base_label}=={pkg.version}'{loc} hashes: {exc} (failing closed)."]
        if _published_cache is not None:
            _published_cache[cache_key] = published
    if not published:
        return [f"[MISSING VERSION] {ecosystem} package '{label}' has no published release '{pkg.version}'."]
    unknown = [h for h in pkg.hashes if h not in published]
    if unknown:
        return [
            f"[HASH MISMATCH] {ecosystem} '{base_label}=={pkg.version}'{loc} pins {len(unknown)} hash(es) the registry "
            f"does not publish for that release (first: {unknown[0][:23]}...)."
        ]
    return []


def verify_registry(
    pkg_name: str,
    ecosystem: str,
    min_age_days: int,
    allow_new: frozenset[str],
    timeout: float = 10.0,
    now: dt.datetime | None = None,
    *,
    pinned_version: str | None = None,
    min_release_age_days: int = DEFAULT_MIN_RELEASE_AGE_DAYS,
) -> list[str]:
    """Confirm the package (and optional pinned version) exists and meets age cooldowns. Fails closed."""
    ref_now = now or dt.datetime.now(dt.UTC)
    lookup = pypi_first_release if ecosystem == "pypi" else npm_first_release
    try:
        first_release = lookup(pkg_name, timeout)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return [f"[HALLUCINATION] {ecosystem} package '{pkg_name}' does not exist (HTTP 404)."]
        return [f"[UNVERIFIED] {ecosystem} package '{pkg_name}': registry returned HTTP {exc.code} (failing closed)."]
    except (OSError, ValueError) as exc:
        return [f"[UNVERIFIED] {ecosystem} package '{pkg_name}': {exc} (failing closed)."]

    if first_release is None:
        return [f"[SUPPLY CHAIN] {ecosystem} package '{pkg_name}' has no published releases."]

    key = normalize_pypi_name(pkg_name) if ecosystem == "pypi" else pkg_name.lower()
    exempt = _is_exempt(key, ecosystem, allow_new)
    age_days = (ref_now - first_release).days
    if age_days < min_age_days and not exempt:
        return [
            f"[NEW PACKAGE] {ecosystem} package '{pkg_name}' was first published {age_days} days ago "
            f"(< {min_age_days}). Review it manually, then record an exemption in .mellyn-allowlist.toml "
            f"or pass --allow-new {pkg_name}."
        ]

    if pinned_version is not None and min_release_age_days > 0:
        ver_lookup = pypi_version_release if ecosystem == "pypi" else npm_version_release
        try:
            ver_time = ver_lookup(pkg_name, pinned_version, timeout)
        except (OSError, ValueError) as exc:
            return [f"[UNVERIFIED] {ecosystem} '{pkg_name}=={pinned_version}': {exc} (failing closed)."]
        if ver_time is None:
            return [f"[MISSING VERSION] {ecosystem} package '{pkg_name}' has no published release '{pinned_version}'."]
        ver_age_days = (ref_now - ver_time).days
        if (
            ver_age_days < min_release_age_days
            and release_exemption_key(ecosystem, key, pinned_version) not in allow_new
        ):
            return [
                f"[FRESH RELEASE] {ecosystem} '{pkg_name}=={pinned_version}' was published {ver_age_days} days ago "
                f"(< {min_release_age_days}d cooldown). Review it, then list this exact version under 'versions' "
                "in a .mellyn-allowlist.toml exemption."
            ]

    return []


# --------------------------------------------------------------------------- #
# Manifest & lockfile verification
# --------------------------------------------------------------------------- #
def _check_python_specs(
    specs: list[str],
    source: str,
    online: bool,
    min_age_days: int,
    allow_new: frozenset[str],
    min_release_age_days: int = DEFAULT_MIN_RELEASE_AGE_DAYS,
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
        if online and not name_issues and not spec_issues:
            exact_ver = extract_exact_python_version(spec)
            issues.extend(
                verify_registry(
                    name,
                    "pypi",
                    min_age_days,
                    allow_new,
                    pinned_version=exact_ver,
                    min_release_age_days=min_release_age_days,
                )
            )
    return issues


_IGNORED_DISCOVERY_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        ".ruff_cache",
        ".pytest_cache",
        ".mypy_cache",
        ".tox",
        ".nox",
        "dist",
        "build",
        ".next",
    }
)
# With git, its own ignore rules decide what is a repository file, so a tracked or unignored manifest is verified
# wherever it lives (a committed `build/requirements.txt` or `packages/env/requirements.txt` is still installable).
# Only vendored packages are skipped: their versions and hashes are verified through the lockfile.
_GIT_MODE_SKIPPED_DIRS: frozenset[str] = frozenset({"node_modules"})


class DiscoveredManifests(NamedTuple):
    pyproject_toml: tuple[Path, ...] = ()
    requirements_txt: tuple[Path, ...] = ()
    requirements_lock: tuple[Path, ...] = ()
    uv_lock: tuple[Path, ...] = ()
    package_json: tuple[Path, ...] = ()
    package_lock_json: tuple[Path, ...] = ()


def _candidate_manifest_paths(root: Path) -> list[Path]:
    """
    Return repository files under root in deterministic relative-path order: tracked plus untracked-but-unignored
    files from git when available, otherwise a directory walk that skips well-known tool and build directories.
    """
    git = shutil.which("git")
    if git and (root / ".git").exists():
        try:
            proc = subprocess.run(  # noqa: S603 - fixed git argv against repository root
                [git, "ls-files", "-co", "--exclude-standard", "-z"],
                cwd=root,
                capture_output=True,
                check=True,
            )
            paths = [
                root / rel
                for rel in proc.stdout.decode("utf-8").split("\0")
                if rel
                and not any(part in _GIT_MODE_SKIPPED_DIRS for part in Path(rel).parts)
                and (root / rel).is_file()
            ]
            return sorted(paths, key=lambda p: p.relative_to(root).as_posix())
        except (OSError, UnicodeDecodeError, subprocess.SubprocessError):
            pass

    walked: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _IGNORED_DISCOVERY_DIRS)
        base = Path(dirpath)
        for fname in sorted(filenames):
            candidate = base / fname
            if candidate.is_file():
                walked.append(candidate)
    return sorted(walked, key=lambda p: p.relative_to(root).as_posix())


def discover_manifests(root: Path) -> DiscoveredManifests:
    """Discover supported Python and npm manifests and lockfiles at any depth under root."""
    pyproject: list[Path] = []
    reqs_txt: list[Path] = []
    reqs_lock: list[Path] = []
    uv_locks: list[Path] = []
    pkg_json: list[Path] = []
    pkg_lock: list[Path] = []

    for path in _candidate_manifest_paths(root):
        name = path.name
        if name == "pyproject.toml":
            pyproject.append(path)
        elif name.startswith("requirements") and name.endswith(".txt"):
            reqs_txt.append(path)
        elif name.startswith("requirements") and name.endswith(".lock"):
            reqs_lock.append(path)
        elif name == "uv.lock":
            uv_locks.append(path)
        elif name == "package.json":
            pkg_json.append(path)
        elif name == "package-lock.json":
            pkg_lock.append(path)

    return DiscoveredManifests(
        pyproject_toml=tuple(pyproject),
        requirements_txt=tuple(reqs_txt),
        requirements_lock=tuple(reqs_lock),
        uv_lock=tuple(uv_locks),
        package_json=tuple(pkg_json),
        package_lock_json=tuple(pkg_lock),
    )


def _check_locked_packages(
    locked: list[LockedPackage],
    ecosystem: str,
    online: bool,
    min_age_days: int,
    allow_new: frozenset[str],
    min_release_age_days: int,
) -> list[str]:
    issues: list[str] = []
    registry_cache: dict[tuple[str, str], list[str]] = {}
    published_cache: dict[tuple[str, str, str], set[str] | None | Exception] = {}
    for pkg in locked:
        name_issues = check_package_name_hygiene(pkg.name, ecosystem)
        issues.extend(name_issues)
        if online and not name_issues:
            norm_name = normalize_pypi_name(pkg.name) if ecosystem == "pypi" else pkg.name.lower()
            reg_key = (norm_name, pkg.version)
            if reg_key not in registry_cache:
                registry_cache[reg_key] = verify_registry(
                    pkg.name,
                    ecosystem,
                    min_age_days,
                    allow_new,
                    pinned_version=pkg.version,
                    min_release_age_days=min_release_age_days,
                )
            registry_issues = registry_cache[reg_key]
            issues.extend(registry_issues)
            if not registry_issues:
                issues.extend(verify_locked_hashes(pkg, ecosystem, _published_cache=published_cache))
    return issues


def verify_pyproject_toml(
    path: Path,
    check_online: bool = False,
    min_age_days: int = DEFAULT_MIN_AGE_DAYS,
    allow_new: frozenset[str] = _NO_EXEMPTIONS,
    min_release_age_days: int = DEFAULT_MIN_RELEASE_AGE_DAYS,
    *,
    root: Path | None = None,
) -> list[str]:
    if not path.exists():
        return []
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    source = path.relative_to(root).as_posix() if root and path.is_relative_to(root) else path.name
    project = data.get("project", {})
    specs = list(project.get("dependencies", []))
    for group in project.get("optional-dependencies", {}).values():
        specs.extend(group)
    for group in data.get("dependency-groups", {}).values():
        specs.extend(s for s in group if isinstance(s, str))
    build_requires = data.get("build-system", {}).get("requires", [])
    if isinstance(build_requires, list):
        specs.extend(s for s in build_requires if isinstance(s, str))
    return _check_python_specs(specs, source, check_online, min_age_days, allow_new, min_release_age_days)


def verify_requirements_txt(
    path: Path,
    check_online: bool = False,
    min_age_days: int = DEFAULT_MIN_AGE_DAYS,
    allow_new: frozenset[str] = _NO_EXEMPTIONS,
    min_release_age_days: int = DEFAULT_MIN_RELEASE_AGE_DAYS,
    *,
    root: Path | None = None,
    _seen: set[Path] | None = None,
) -> list[str]:
    if not path.exists():
        return []
    seen = _seen if _seen is not None else set()
    resolved = path.resolve()
    if resolved in seen:
        return []
    seen.add(resolved)
    specs, includes, issues = read_requirements_txt(path, (root or path.parent))
    source = path.relative_to(root).as_posix() if root and path.is_relative_to(root) else path.name
    issues.extend(_check_python_specs(specs, source, check_online, min_age_days, allow_new, min_release_age_days))
    for included in includes:
        issues.extend(
            verify_requirements_txt(
                included, check_online, min_age_days, allow_new, min_release_age_days, root=root, _seen=seen
            )
        )
    return issues


def verify_package_json(
    path: Path,
    check_online: bool = False,
    min_age_days: int = DEFAULT_MIN_AGE_DAYS,
    allow_new: frozenset[str] = _NO_EXEMPTIONS,
    min_release_age_days: int = DEFAULT_MIN_RELEASE_AGE_DAYS,
) -> list[str]:
    if not path.exists():
        return []
    issues: list[str] = []
    data = json.loads(path.read_text(encoding="utf-8"))
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for pkg_name, version_spec in data.get(section, {}).items():
            spec_str = str(version_spec).strip()
            spec_issues = check_npm_spec(pkg_name, spec_str, str(path))
            issues.extend(spec_issues)
            name_issues = check_package_name_hygiene(pkg_name, "npm")
            issues.extend(name_issues)
            if check_online and not name_issues and not spec_issues:
                pinned = spec_str if NPM_EXACT_RE.match(spec_str) else None
                issues.extend(
                    verify_registry(
                        pkg_name,
                        "npm",
                        min_age_days,
                        allow_new,
                        pinned_version=pinned,
                        min_release_age_days=min_release_age_days,
                    )
                )
    return issues


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OWASP AI Supply Chain & Slopsquatting Dependency Verifier")
    parser.add_argument("--root", type=Path, default=Path("."), help="Repository root directory")
    parser.add_argument("--online", action="store_true", help="Check PyPI/npm for existence and package/release age")
    parser.add_argument("--min-age-days", type=int, default=DEFAULT_MIN_AGE_DAYS, help="Minimum package age (days)")
    parser.add_argument(
        "--min-release-age-days",
        type=int,
        default=DEFAULT_MIN_RELEASE_AGE_DAYS,
        help="Minimum upload age in days for exact-pinned versions (0 disables version-age cooldown)",
    )
    parser.add_argument(
        "--allow-new", nargs="*", default=[], metavar="PKG", help="Manually vetted packages exempt from age checks"
    )
    parser.add_argument(
        "--allowlist",
        type=Path,
        default=None,
        help="Exemptions file to use instead of <root>/.mellyn-allowlist.toml. CI passes the copy from the PR's "
        "base commit, so a pull request cannot exempt its own dependencies. A missing file means no exemptions.",
    )
    args = parser.parse_args(argv)

    root: Path = args.root.resolve()
    file_exempt, allowlist_issues = load_allowlist_file(args.allowlist or (root / ".mellyn-allowlist.toml"))
    cli_exempt = frozenset(normalize_pypi_name(p) for p in args.allow_new) | frozenset(
        p.lower() for p in args.allow_new
    )
    allow_new = file_exempt | cli_exempt
    opts = {
        "check_online": args.online,
        "min_age_days": args.min_age_days,
        "allow_new": allow_new,
        "min_release_age_days": args.min_release_age_days,
    }

    manifests = discover_manifests(root)
    issues: list[str] = list(allowlist_issues)

    for pyproj in manifests.pyproject_toml:
        issues.extend(verify_pyproject_toml(pyproj, **opts, root=root))

    seen_requirements: set[Path] = set()
    for req in manifests.requirements_txt:
        issues.extend(verify_requirements_txt(req, **opts, root=root, _seen=seen_requirements))

    for lock_path in manifests.requirements_lock:
        locked_py, lock_issues = parse_requirements_lock(lock_path)
        issues.extend(lock_issues)
        issues.extend(
            _check_locked_packages(
                locked_py, "pypi", args.online, args.min_age_days, allow_new, args.min_release_age_days
            )
        )

    for uv_lock in manifests.uv_lock:
        locked_uv, uv_issues = parse_uv_lock(uv_lock)
        issues.extend(uv_issues)
        issues.extend(
            _check_locked_packages(
                locked_uv, "pypi", args.online, args.min_age_days, allow_new, args.min_release_age_days
            )
        )

    for pkg_json in manifests.package_json:
        issues.extend(verify_package_json(pkg_json, **opts))

    for npm_lock in manifests.package_lock_json:
        locked_npm, npm_lock_issues = parse_package_lock_json(npm_lock)
        issues.extend(npm_lock_issues)
        issues.extend(
            _check_locked_packages(
                locked_npm, "npm", args.online, args.min_age_days, allow_new, args.min_release_age_days
            )
        )

    if issues:
        print("OWASP AI Dependency Verification FAILED:")
        for issue in issues:
            print(f"  - {issue}")
        return 1

    mode = (
        f"online, min pkg age {args.min_age_days}d, min release age {args.min_release_age_days}d"
        if args.online
        else "offline; run with --online for registry checks"
    )
    print(f"OWASP AI Dependency Verification PASSED ({mode}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
