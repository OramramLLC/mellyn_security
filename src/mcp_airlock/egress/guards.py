"""Network egress (SSRF) and workspace path confinement guards migrated into mcp_airlock.egress."""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

# Secret file patterns that must NEVER be read or written by an agent tool.
SENSITIVE_FILENAME_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\.env(?:\..*)?$", re.IGNORECASE),
    re.compile(r"\.(?:pem|key|p12|pfx|jks|kdbx)$", re.IGNORECASE),
    re.compile(r"^credentials\.json$", re.IGNORECASE),
    re.compile(r"^id_(?:rsa|ed25519|ecdsa|dsa)$", re.IGNORECASE),
    re.compile(r"^(?:\.git-credentials|\.npmrc|\.pypirc|[._]netrc|\.htpasswd)$", re.IGNORECASE),
)

SENSITIVE_PATH_PARTS: frozenset[str] = frozenset(
    {".ssh", ".aws", ".kube", ".gnupg", ".docker", ".azure", "gcloud", "secrets"}
)

SENSITIVE_RELATIVE_PATHS: frozenset[str] = frozenset({".git/config"})

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

_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


class EgressValidator:
    """Application-layer SSRF and destination allowlist validator."""

    def __init__(self, allowed_domains: frozenset[str] | None = None) -> None:
        self.allowed_domains: frozenset[str] = frozenset(
            d.strip().lower().lstrip(".") for d in (allowed_domains or frozenset()) if d.strip()
        )

    def validate_url(self, raw_url: str) -> tuple[bool, str]:
        """Return (is_allowed, reason) for an outbound URL."""
        if not raw_url.strip():
            return False, "URL is empty."
        if _CONTROL_CHARACTERS.search(raw_url):
            return False, "URL contains control characters."

        try:
            parsed = urlparse(raw_url.strip())
            port = parsed.port
        except ValueError:
            return False, "Malformed URL authority or port."

        if parsed.scheme.lower() != "https":
            return False, "Disallowed URL scheme; only https is permitted."

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
        """Detect IPv4 and IPv6 literals."""
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            return False
        return True


class WorkspaceConfigError(RuntimeError):
    """The workspace root cannot be trusted for path checks (fail closed)."""


def check_workspace_root(workspace_root: Path, *, require_mount: bool) -> None:
    """Verify workspace root exists and is a mount point when `require_mount` is enabled."""
    if not workspace_root.is_dir():
        raise WorkspaceConfigError(f"Workspace root '{workspace_root}' is not an existing directory.")
    if require_mount and not os.path.ismount(workspace_root):
        raise WorkspaceConfigError(f"Workspace root '{workspace_root}' is not a mount point.")


@dataclass(frozen=True)
class SearchMatch:
    """One permitted line match returned by `WorkspacePathGuard.search_content()`."""

    path: str
    line_number: int
    line: str


class WorkspacePathGuard:
    """Enforces workspace confinement, secret-file denial, and guardrail protection."""

    def __init__(self, workspace_root: Path, extra_protected_paths: tuple[str, ...] = ()) -> None:
        self.workspace_root = workspace_root.resolve()
        self.protected_paths = tuple(p.casefold() for p in (*GUARDRAIL_PATHS, *extra_protected_paths))

    def is_protected(self, rel_posix: str) -> bool:
        """True when a workspace-relative POSIX path is, is inside, or is an ancestor of a protected path."""
        norm_path = "" if rel_posix == "." else rel_posix.casefold().strip("/")
        if norm_path == "":
            return bool(self.protected_paths)
        for protected in self.protected_paths:
            norm_prot = protected.strip("/")
            if not norm_prot:
                continue
            if norm_path == norm_prot:
                return True
            if protected.endswith("/") and norm_path.startswith(f"{norm_prot}/"):
                return True
            if norm_prot.startswith(f"{norm_path}/"):
                return True
        return False

    def validate_path(self, raw_path: str, *, is_write: bool = False) -> tuple[bool, str]:
        """Return (is_allowed, reason) for a workspace file read or write."""
        if not raw_path.strip():
            return False, "Path is empty."
        if _CONTROL_CHARACTERS.search(raw_path):
            return False, "Path contains control characters."

        candidate = Path(raw_path)
        try:
            resolved = (candidate if candidate.is_absolute() else self.workspace_root / candidate).resolve()
        except (OSError, ValueError, RuntimeError) as exc:
            return False, f"Workspace path could not be resolved ({type(exc).__name__})."

        try:
            rel_path = resolved.relative_to(self.workspace_root)
        except ValueError:
            return False, "Path escapes workspace root."

        rel_posix = rel_path.as_posix()

        for part in rel_path.parts:
            if part.lower() in SENSITIVE_PATH_PARTS:
                return False, f"Access to sensitive directory '{part.lower()}' is denied."

        filename = rel_path.name
        stripped_name = filename.rstrip(" .")
        if filename.lower() != ".env.example":
            for pattern in SENSITIVE_FILENAME_PATTERNS:
                if pattern.search(filename) or (stripped_name and pattern.search(stripped_name)):
                    return False, "Access to sensitive file is denied."
        if (
            rel_posix.casefold() in SENSITIVE_RELATIVE_PATHS
            or rel_posix.rstrip(" .").casefold() in SENSITIVE_RELATIVE_PATHS
        ):
            return False, "Access to sensitive file is denied."

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
        """Recursively search workspace files while validating each file before reading."""
        if not query:
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
