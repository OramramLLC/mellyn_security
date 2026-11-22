"""
API credentials for the authorizer: two roles, stored as HMAC-SHA256 digests with a server-side pepper.

- The AGENT key belongs to the agent harness / MCP gateway. It can create sessions, report taint, and
  ask for authorization decisions. It can never approve anything.
- The APPROVER key belongs to the human approval surface (a person, or an approval UI they sign in to).
  It can only issue grants. It must never be reachable from the agent's runtime or tools.

API keys are high-entropy random values, so they are stored as HMAC-SHA256(pepper, key) rather than
with a password hash, and compared with hmac.compare_digest. Configuration comes from:

    AEGIS_API_KEY_PEPPER        server-side secret, at least 32 characters
    AEGIS_AGENT_KEY_DIGEST      hex HMAC-SHA256 digest of the agent key
    AEGIS_APPROVER_KEY_DIGEST   hex HMAC-SHA256 digest of the approver key

Generate a key and its digest (with AEGIS_API_KEY_PEPPER set in the environment) by running, from backend/:

    python -m aegis_ai.credentials
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

PEPPER_ENV = "AEGIS_API_KEY_PEPPER"
DIGEST_ENV: dict[str, str] = {"agent": "AEGIS_AGENT_KEY_DIGEST", "approver": "AEGIS_APPROVER_KEY_DIGEST"}
MIN_PEPPER_LENGTH = 32
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class Role(StrEnum):
    AGENT = "agent"
    APPROVER = "approver"


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
    roles: frozenset[Role] = frozenset(Role)

    def __post_init__(self) -> None:
        if not self.roles:
            raise CredentialConfigError("At least one role must be configured.")
        if len(self.pepper) < MIN_PEPPER_LENGTH:
            raise CredentialConfigError(f"{PEPPER_ENV} must be at least {MIN_PEPPER_LENGTH} characters.")
        for role in self.roles:
            digest = self.digests.get(role, "")
            if not _HEX_DIGEST.fullmatch(digest):
                raise CredentialConfigError(f"{DIGEST_ENV[role]} must be a 64-character lowercase hex digest.")
        if set(Role) <= self.roles and self.digests[Role.AGENT] == self.digests[Role.APPROVER]:
            raise CredentialConfigError("The agent and approver keys must be different keys.")

    @classmethod
    def from_env(
        cls, environ: Mapping[str, str] | None = None, roles: frozenset[Role] = frozenset(Role)
    ) -> CredentialConfig:
        env = os.environ if environ is None else environ
        return cls(
            pepper=env.get(PEPPER_ENV, "").strip(),
            digests={role: env.get(DIGEST_ENV[role], "").strip().lower() for role in roles},
            roles=roles,
        )

    def verify(self, provided_key: str | None, role: Role) -> bool:
        """Constant-time check that `provided_key` is the key for `role`."""
        if not provided_key or role not in self.roles:
            return False
        return hmac.compare_digest(key_digest(provided_key, self.pepper), self.digests[role])


def main() -> int:
    """Print a new random API key and the digest to put in AEGIS_AGENT_KEY_DIGEST or AEGIS_APPROVER_KEY_DIGEST."""
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
