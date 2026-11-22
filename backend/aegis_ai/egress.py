"""Network egress (SSRF) and workspace path confinement guards."""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from urllib.parse import urlparse

# Secret file patterns that must NEVER be read or written by an agent tool.
SENSITIVE_FILENAME_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\.env(?:\..+)?$", re.IGNORECASE),
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
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    "CLAUDE.md",
    "AGENTS.md",
    "GEMINI.md",
)


# NUL and other C0/DEL control characters. They have no business in a path or URL, and they are where
# validators and the programs that later open the path or URL disagree (NUL truncates C strings; CR/LF
# split HTTP headers and log lines).
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


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

        parsed = urlparse(raw_url.strip())
        if parsed.scheme.lower() != "https":
            return False, f"Disallowed URL scheme '{parsed.scheme}'; only https is permitted."

        if parsed.username or parsed.password:
            return False, "URLs with embedded credentials/userinfo are forbidden."

        hostname = (parsed.hostname or "").strip().lower().rstrip(".")
        if not hostname:
            return False, "URL is missing a valid hostname."

        if hostname == "localhost" or hostname.endswith(".localhost") or hostname.endswith(".local"):
            return False, f"Loopback/local hostname '{hostname}' is forbidden."

        if self._is_ip_literal(hostname):
            return False, f"Direct IP literals ('{hostname}') are forbidden; use an allowlisted domain."

        if not self.is_domain_allowlisted(hostname):
            return False, f"Destination host '{hostname}' is not in the egress domain allowlist."

        return True, f"Destination host '{hostname}' matched egress allowlist."

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


class WorkspacePathGuard:
    """Enforces workspace confinement, secret-file denial, and guardrail protection."""

    def __init__(self, workspace_root: Path, extra_protected_paths: tuple[str, ...] = ()) -> None:
        self.workspace_root = workspace_root.resolve()
        self.protected_paths = tuple(p.casefold() for p in (*GUARDRAIL_PATHS, *extra_protected_paths))

    def is_protected(self, rel_posix: str) -> bool:
        """True when a workspace-relative POSIX path is, or is inside, a guardrail path (case-insensitive)."""
        path = rel_posix.casefold()
        for protected in self.protected_paths:
            if protected.endswith("/"):
                if path.startswith(protected) or f"{path}/" == protected:
                    return True
            elif path == protected:
                return True
        return False

    def validate_path(self, raw_path: str, *, is_write: bool = False) -> tuple[bool, str]:
        """Return (is_allowed, reason) for a workspace file read or write."""
        if not isinstance(raw_path, str) or not raw_path.strip():
            return False, "Path is empty or not a string."
        if _CONTROL_CHARACTERS.search(raw_path):
            return False, "Path contains control characters (for example a NUL byte)."

        candidate = Path(raw_path)
        try:
            resolved = (candidate if candidate.is_absolute() else self.workspace_root / candidate).resolve()
        except (OSError, ValueError, RuntimeError) as exc:  # e.g. invalid names, symlink loops
            return False, f"Path '{raw_path}' could not be resolved ({type(exc).__name__})."

        try:
            rel_path = resolved.relative_to(self.workspace_root)
        except ValueError:
            return False, f"Path '{raw_path}' escapes workspace root."

        rel_posix = rel_path.as_posix()

        # Check sensitive directory components (e.g., .ssh, .aws, secrets)
        for part in rel_path.parts:
            if part.lower() in SENSITIVE_PATH_PARTS:
                return False, f"Access to sensitive directory '{part}' is denied."

        # Check sensitive filenames (.env, *.pem, *.key, credentials.json, .npmrc, ...)
        filename = rel_path.name
        if filename.lower() != ".env.example":
            for pattern in SENSITIVE_FILENAME_PATTERNS:
                if pattern.search(filename):
                    return False, f"Access to sensitive file '{filename}' is denied."
        if rel_posix.casefold() in SENSITIVE_RELATIVE_PATHS:
            return False, f"Access to sensitive file '{rel_posix}' is denied."

        # Block agent self-modification of security guardrails
        if is_write and self.is_protected(rel_posix):
            return False, f"Modifying guardrail path '{rel_posix}' is denied."

        return True, f"Workspace path '{rel_posix}' permitted."
