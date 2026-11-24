"""
API credentials: three roles, stored as HMAC-SHA256 digests with a server-side pepper.

- The AGENT key belongs to the agent harness / MCP gateway. It can create sessions, report taint, and
  ask for authorization decisions. It can never approve anything.
- The APPROVER key belongs to the human approval surface (a person, or an approval UI they sign in to).
  It can only issue grants. It must never be reachable from the agent's runtime or tools.
- The VIEWER key is read-only: it lets the evidence viewer show status, reports and audit logs, and can
  never list, approve or reject held calls. It exists so routine viewing does not need the approver key.

All configured keys must be different from each other.

API keys are high-entropy random values, so they are stored as HMAC-SHA256(pepper, key) rather than
with a password hash, and compared with hmac.compare_digest. Configuration comes from:

    MELLYN_API_KEY_PEPPER        server-side secret, at least 32 characters
    MELLYN_AGENT_KEY_DIGEST      hex HMAC-SHA256 digest of the agent key
    MELLYN_APPROVER_KEY_DIGEST   hex HMAC-SHA256 digest of the approver key
    MELLYN_VIEWER_KEY_DIGEST     hex HMAC-SHA256 digest of the read-only viewer key (viewer server only)

Generate a key and its digest (with MELLYN_API_KEY_PEPPER set in the environment) by running, from backend/:

    python -m mellyn.credentials
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

PEPPER_ENV = "MELLYN_API_KEY_PEPPER"
DIGEST_ENV: dict[str, str] = {
    "agent": "MELLYN_AGENT_KEY_DIGEST",
    "approver": "MELLYN_APPROVER_KEY_DIGEST",
    "viewer": "MELLYN_VIEWER_KEY_DIGEST",
}
MIN_PEPPER_LENGTH = 32
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class Role(StrEnum):
    AGENT = "agent"
    APPROVER = "approver"
    VIEWER = "viewer"


# Roles a CredentialConfig requires unless told otherwise: the HTTP authorization API's two roles. The VIEWER
# role is opt-in (only the evidence viewer asks for it), so adding it does not change existing deployments.
DEFAULT_ROLES: frozenset[Role] = frozenset({Role.AGENT, Role.APPROVER})


def _check_distinct(digests: Mapping[Role, str]) -> None:
    present = [(role, digest) for role, digest in digests.items() if digest]
    for idx, (role_a, digest_a) in enumerate(present):
        for role_b, digest_b in present[idx + 1 :]:
            if digest_a == digest_b:
                raise CredentialConfigError(f"The {role_a} and {role_b} keys must be different keys.")


class CredentialConfigError(ValueError):
    """Credentials are missing or malformed. Callers must fail closed."""


def key_digest(key: str, pepper: str) -> str:
    """Hex HMAC-SHA256 of an API key under the server-side pepper."""
    return hmac.new(pepper.encode("utf-8"), key.encode("utf-8"), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class CredentialConfig:
    """
    Validated key digests. `roles` lists the roles this deployment uses: the HTTP API needs both, the
    MCP gateway (whose agent side is the stdio connection itself) needs only APPROVER. A role outside
    `roles` never verifies.
    """

    pepper: str
    digests: Mapping[Role, str]
    roles: frozenset[Role] = DEFAULT_ROLES

    def __post_init__(self) -> None:
        if not self.roles:
            raise CredentialConfigError("At least one role must be configured.")
        if len(self.pepper) < MIN_PEPPER_LENGTH:
            raise CredentialConfigError(f"{PEPPER_ENV} must be at least {MIN_PEPPER_LENGTH} characters.")
        for role in self.roles:
            digest = self.digests.get(role, "")
            if not _HEX_DIGEST.fullmatch(digest):
                raise CredentialConfigError(f"{DIGEST_ENV[role]} must be a 64-character lowercase hex digest.")
        for role, digest in self.digests.items():
            if digest and not _HEX_DIGEST.fullmatch(digest):
                raise CredentialConfigError(f"{DIGEST_ENV[role]} must be a 64-character lowercase hex digest.")
        _check_distinct(self.digests)

    @classmethod
    def from_env(
        cls, environ: Mapping[str, str] | None = None, roles: frozenset[Role] = DEFAULT_ROLES
    ) -> CredentialConfig:
        env = os.environ if environ is None else environ
        supplied = {role: raw for role in Role if (raw := env.get(DIGEST_ENV[role], "").strip().lower())}
        for role, digest in supplied.items():
            if not _HEX_DIGEST.fullmatch(digest):
                raise CredentialConfigError(f"{DIGEST_ENV[role]} must be a 64-character lowercase hex digest.")
        # Every supplied key must differ, including ones this config does not use: a viewer key equal to the
        # approver key would quietly turn the read-only key into an approval key.
        _check_distinct(supplied)
        return cls(
            pepper=env.get(PEPPER_ENV, "").strip(),
            digests={role: supplied.get(role, "") for role in roles},
            roles=roles,
        )

    def verify(self, provided_key: str | None, role: Role) -> bool:
        """Constant-time check that `provided_key` is the key for `role`."""
        if not provided_key or role not in self.roles:
            return False
        return hmac.compare_digest(key_digest(provided_key, self.pepper), self.digests[role])


def main() -> int:
    """Print a new random API key and the digest to put in one of the MELLYN_*_KEY_DIGEST variables."""
    pepper = os.environ.get(PEPPER_ENV, "").strip()
    if len(pepper) < MIN_PEPPER_LENGTH:
        print(f"Set {PEPPER_ENV} (at least {MIN_PEPPER_LENGTH} characters) first.", file=sys.stderr)
        return 1
    key = secrets.token_urlsafe(32)
    print(f"API key (give to the client; shown once): {key}")
    print(f"Digest (store in the server environment): {key_digest(key, pepper)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
