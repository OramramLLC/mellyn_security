"""Network egress (SSRF) and workspace path confinement guards."""

from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

# Secret file patterns that must NEVER be read or written by an agent tool.
SENSITIVE_FILENAME_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\.env(?:\..*)?$", re.IGNORECASE),
    re.compile(r"\.(?:pem|key|p12|pfx|jks|kdbx)$", re.IGNORECASE),
    re.compile(r"^credentials\.json$", re.IGNORECASE),
    re.compile(r"^id_(?:rsa|ed25519|ecdsa|dsa)$", re.IGNORECASE),
    # Package-registry, git, and HTTP credential stores
    re.compile(r"^(?:\.git-credentials|\.npmrc|\.pypirc|[._]netrc|\.htpasswd)$", re.IGNORECASE),
)

SENSITIVE_PATH_PARTS: frozenset[str] = frozenset(
    {".ssh", ".aws", ".kube", ".gnupg", ".docker", ".azure", "gcloud", "secrets"}
)

# Exact workspace files that may hold credentials (e.g. a token embedded in a git remote URL).
SENSITIVE_RELATIVE_PATHS: frozenset[str] = frozenset({".git/config"})

# Paths an agent must never modify in ANY workspace: its own steering rules, the CI and scanner gates, and
# .git/ (a written hook or core.hooksPath runs code on the developer's next commit). This list applies to
# every repository the authorizer protects, so it must hold only files that are guardrails everywhere.
# Paths that matter to one repository (its security core, its tests, its deployment) belong in that
# repository's policy `protected_paths` (see config/mellyn-self-policy.toml for this repository's own).
# Entries ending in "/" protect a directory; others protect one file. Matching ignores case so that
# case-insensitive filesystems (Windows, macOS) cannot be used to dodge it.
GUARDRAIL_PATHS: tuple[str, ...] = (
    ".git/",
    ".agent/",
    ".claude/",
    ".cursor/",
    ".semgrep/",
    ".github/",
    ".gitleaks.toml",
    ".gitattributes",
    ".pre-commit-config.yaml",
    ".pre-commit-hooks.yaml",
    ".mellyn-allowlist.toml",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    "CLAUDE.md",
    "AGENTS.md",
    "GEMINI.md",
)

# Suffixes for `owned_file_entries`: "" protects the file itself, ".*" every `<name>.<suffix>` sibling (an audit
# ledger's `.lock` file and the `.v1-*` / `.pre-chain-*` files older ledgers are moved aside to), and "-wal" style
# suffixes the companion files SQLite writes next to a database.
LEDGER_FILE_SUFFIXES: tuple[str, ...] = ("", ".*")
SQLITE_FILE_SUFFIXES: tuple[str, ...] = ("", "-wal", "-shm", "-journal")

# A file a component writes or reads its own enforcement from, with the suffixes that protect it and its companions.
OwnedFile = tuple[Path, tuple[str, ...]]


def owned_file_entries(workspace_root: Path, owned: Iterable[OwnedFile]) -> tuple[str, ...]:
    """
    Workspace-relative protected-path entries for the files a component owns that sit inside the workspace.

    The agent must never be able to edit the files that configure or record its own enforcement: its policy, its
    audit ledger and the ledger's lock, its state database. Each component declares its files, so no entry point
    can forget one. A file outside the workspace needs no entry, since the guard denies every path outside it.
    """
    root = workspace_root.resolve()
    entries: list[str] = []
    for path, suffixes in owned:
        try:
            rel = Path(path).resolve().relative_to(root).as_posix()
        except (OSError, RuntimeError, ValueError):
            continue
        if rel in ("", "."):
            continue
        entries.extend(f"{rel}{suffix}" for suffix in suffixes)
    return tuple(dict.fromkeys(entries))


# NUL and other C0/DEL control characters. They have no business in a path or URL, and they are where
# validators and the programs that later open the path or URL disagree (NUL truncates C strings; CR/LF
# split HTTP headers and log lines).
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
_WINDOWS_DRIVE_RELATIVE_RE = re.compile(r"^[A-Za-z]:(?![\\/])")
_STRICT_HOSTNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")


class EgressValidator:
    """
    Application-layer SSRF and destination allowlist validator.

    Note: Per docs/THREAT_MODEL.md (TM-02), pair this with a network-layer egress
    proxy in production to defeat DNS rebinding and cross-host HTTP redirects.
    """

    def __init__(self, allowed_domains: frozenset[str] | None = None) -> None:
        self.allowed_domains: frozenset[str] = frozenset(
            d.strip().lower().lstrip(".") for d in (allowed_domains or frozenset()) if d.strip()
        )

    def validate_url(self, raw_url: str) -> tuple[bool, str]:
        """Return (is_allowed, reason) for an outbound URL."""
        if not isinstance(raw_url, str) or not raw_url.strip():
            return False, "URL is empty or not a string."
        if _CONTROL_CHARACTERS.search(raw_url):
            return False, "URL contains control characters."

        stripped = raw_url.strip()
        try:
            parsed = urlparse(stripped)
            port = parsed.port
        except ValueError:
            return False, "Malformed URL authority or port."

        if parsed.scheme.lower() != "https":
            return False, "Disallowed URL scheme; only https is permitted."

        # Reject backslashes anywhere in the authority so WHATWG clients (`fetch`, `undici`, modern `curl`)
        # cannot split `evil.com\.allowed.example` into host `evil.com` and path `/.allowed.example`.
        raw_authority = stripped.split("://", 1)[1].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "\\" in parsed.netloc or "\\" in raw_authority:
            return False, "Backslashes are forbidden in URL authorities."

        if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
            return False, "URLs with embedded credentials/userinfo are forbidden."

        hostport = parsed.netloc
        if "]" in hostport:
            _, _, after_bracket = hostport.rpartition("]")
            has_colon_port = ":" in after_bracket
        else:
            has_colon_port = ":" in hostport
        if has_colon_port and (port is None or port <= 0):
            return False, "URL specifies an empty or invalid port."

        hostname = (parsed.hostname or "").strip().lower().rstrip(".")
        if not hostname:
            return False, "URL is missing a valid hostname."

        if hostname == "localhost" or hostname.endswith(".localhost") or hostname.endswith(".local"):
            return False, "Loopback or local hostname is forbidden."

        if self._is_ip_literal(hostname):
            return False, "Direct IP literals are forbidden; use an allowlisted domain."

        if not _STRICT_HOSTNAME_RE.fullmatch(hostname):
            return False, "Destination host is not a valid ASCII domain name."

        if not self.is_domain_allowlisted(hostname):
            return False, "Destination host is not in the egress domain allowlist."

        return True, "Destination host matched egress allowlist."

    def is_domain_allowlisted(self, hostname: str) -> bool:
        """Check exact or subdomain match against the allowlist."""
        host = hostname.strip().lower().rstrip(".")
        for allowed in self.allowed_domains:
            if host == allowed or host.endswith(f".{allowed}"):
                return True
        return False

    @staticmethod
    def _is_ip_literal(hostname: str) -> bool:
        """
        Detect IPv4 and IPv6 literals (including IPv4-mapped IPv6). Every literal is rejected, public or
        private, so no range check is needed here. Numeric forms such as '2130706433' are not parsed as
        IPs, but they also never match a domain in the allowlist, so they are rejected there.
        """
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            return False
        return True


class WorkspaceConfigError(RuntimeError):
    """The workspace root cannot be trusted for path checks. Callers refuse to start (fail closed)."""


def check_workspace_root(workspace_root: Path, *, require_mount: bool) -> None:
    """
    The path guard resolves symlinks against the authorizer's own filesystem. If that is not the filesystem the
    agent's tools use (an authorizer container with no workspace mounted), a link to a secret looks like an
    ordinary file. With `require_mount`, refuse a workspace root that is not a mount point.
    """
    if not workspace_root.is_dir():
        raise WorkspaceConfigError(f"Workspace root '{workspace_root}' is not an existing directory.")
    if require_mount and not os.path.ismount(workspace_root):
        raise WorkspaceConfigError(
            f"Workspace root '{workspace_root}' is not a mount point. Mount the agent's workspace there "
            "(read-only is enough), or the path guard cannot see where symlinks lead."
        )


@dataclass(frozen=True)
class SearchMatch:
    """One permitted line match returned by WorkspacePathGuard.search_content()."""

    path: str
    line_number: int
    line: str


class WorkspacePathGuard:
    """Enforces workspace confinement, secret-file denial, and guardrail protection."""

    def __init__(self, workspace_root: Path, extra_protected_paths: tuple[str, ...] = ()) -> None:
        self.workspace_root = workspace_root.resolve()
        self.protected_paths = tuple(p.casefold() for p in (*GUARDRAIL_PATHS, *extra_protected_paths))

    def is_protected(self, rel_posix: str) -> bool:
        """
        True when a workspace-relative POSIX path is, is inside, or is an ancestor directory of a
        guardrail/protected path (case-insensitive). Denying ancestor directories prevents moving or
        deleting a parent tree (e.g. 'src/') whose subtree contains 'src/mellyn/'.

        An entry ending in `.*` protects every sibling named `<name>.<suffix>` in the same directory, such as an
        audit ledger's `.lock` file and the timestamped `.v1-*` / `.pre-chain-*` files it is moved aside to.
        """
        norm_path = "" if rel_posix == "." else rel_posix.casefold().strip("/")
        if norm_path == "":
            return bool(self.protected_paths)
        for protected in self.protected_paths:
            norm_prot = protected.strip("/")
            if not norm_prot:
                continue
            if norm_path == norm_prot:
                return True
            if norm_prot.endswith(".*"):
                stem = norm_prot[:-1]  # "<name>."
                if norm_path.startswith(stem) and len(norm_path) > len(stem):
                    suffix_part = norm_path[len(stem) :].split("/", 1)[0]
                    if suffix_part:
                        return True
            if norm_path.startswith(f"{norm_prot}/"):
                return True
            if norm_prot.startswith(f"{norm_path}/"):
                return True
        return False

    def validate_path(self, raw_path: str, *, is_write: bool = False) -> tuple[bool, str]:
        """Return (is_allowed, reason) for a workspace file read or write."""
        if not isinstance(raw_path, str) or not raw_path.strip():
            return False, "Path is empty or not a string."
        if _CONTROL_CHARACTERS.search(raw_path):
            return False, "Path contains control characters (for example a NUL byte)."
        if _WINDOWS_DRIVE_RELATIVE_RE.match(raw_path.strip()):
            return False, "Drive-relative Windows path is forbidden."

        candidate = Path(raw_path)
        try:
            resolved = (candidate if candidate.is_absolute() else self.workspace_root / candidate).resolve()
        except (OSError, ValueError, RuntimeError) as exc:  # e.g. invalid names, symlink loops
            return False, f"Workspace path could not be resolved ({type(exc).__name__})."

        try:
            rel_path = resolved.relative_to(self.workspace_root)
        except ValueError:
            return False, "Path escapes workspace root."

        # Reject NTFS alternate data stream / colon syntax inside workspace-relative path segments.
        if any(":" in part for part in rel_path.parts):
            return False, "Path contains forbidden colon or alternate data stream syntax."
        # Windows drops trailing dots and spaces from every path segment, so ".gitleaks.toml." or ".claude./x"
        # would create the protected file itself. Existing targets resolve to their real name, but a file that
        # does not exist yet keeps the trailing character here, so refuse such segments on every platform.
        if any(part != part.rstrip(" .") for part in rel_path.parts):
            return False, "Path segment ends with a dot or space, which Windows silently strips."

        rel_posix = rel_path.as_posix()

        # Check sensitive directory components (e.g., .ssh, .aws, secrets)
        for part in rel_path.parts:
            if part.lower() in SENSITIVE_PATH_PARTS:
                return False, f"Access to sensitive directory '{part.lower()}' is denied."

        # Check sensitive filenames (.env, *.pem, *.key, credentials.json, .npmrc, ...)
        filename = rel_path.name
        if filename.lower() != ".env.example":
            for pattern in SENSITIVE_FILENAME_PATTERNS:
                if pattern.search(filename):
                    return False, "Access to sensitive file is denied."
        if rel_posix.casefold() in SENSITIVE_RELATIVE_PATHS:
            return False, "Access to sensitive file is denied."

        # Block agent self-modification of security guardrails (and ancestor directories containing them)
        if is_write and self.is_protected(rel_posix):
            return False, "Modifying protected guardrail path is denied."

        return True, "Workspace path permitted."

    def search_content(
        self,
        query: str,
        start_path: str = ".",
        *,
        max_matches: int = 200,
        max_file_bytes: int = 1024 * 1024,
    ) -> list[SearchMatch]:
        """
        Recursively search workspace text files while applying `validate_path(..., is_write=False)`
        to every directory and file BEFORE opening it, so secret files (`.env`, `*.pem`, `.ssh/`, ...)
        are never read even when `start_path` is the workspace root.
        """
        if not isinstance(query, str) or not query:
            raise ValueError("Search query must be a non-empty string.")
        ok, reason = self.validate_path(start_path, is_write=False)
        if not ok:
            raise PermissionError(reason)

        candidate = Path(start_path)
        start_resolved = (candidate if candidate.is_absolute() else self.workspace_root / candidate).resolve()
        matches: list[SearchMatch] = []

        def _scan_file(file_path: Path) -> None:
            file_ok, _ = self.validate_path(str(file_path), is_write=False)
            if not file_ok:
                return
            try:
                st = file_path.stat()
                if st.st_size > max_file_bytes:
                    return
                raw = file_path.read_bytes()
            except OSError:
                return
            if b"\x00" in raw:
                return
            rel_posix = file_path.resolve().relative_to(self.workspace_root).as_posix()
            for idx, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), start=1):
                if query in line:
                    matches.append(SearchMatch(path=rel_posix, line_number=idx, line=line))
                    if len(matches) >= max_matches:
                        return

        if start_resolved.is_file():
            _scan_file(start_resolved)
            return matches

        for root, dirs, files in os.walk(start_resolved, followlinks=False):
            root_path = Path(root)
            dirs[:] = sorted(
                d
                for d in dirs
                if d != ".git"
                and not (root_path / d).is_symlink()
                and self.validate_path(str(root_path / d), is_write=False)[0]
            )
            for fname in sorted(files):
                fpath = root_path / fname
                if fpath.is_symlink():
                    continue
                _scan_file(fpath)
                if len(matches) >= max_matches:
                    return matches
        return matches
