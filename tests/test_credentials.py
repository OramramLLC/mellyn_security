"""Tests for the authorizer's two-role HMAC API key verification."""

from __future__ import annotations

import secrets
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from aegis_ai.credentials import (  # noqa: E402
    CredentialConfig,
    CredentialConfigError,
    Role,
    key_digest,
)


def make_config() -> tuple[CredentialConfig, str, str]:
    """Random pepper and keys generated per test run; nothing is hardcoded."""
    pepper = secrets.token_urlsafe(32)
    agent_key, approver_key = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    config = CredentialConfig.from_env(
        {
            "AEGIS_API_KEY_PEPPER": pepper,
            "AEGIS_AGENT_KEY_DIGEST": key_digest(agent_key, pepper),
            "AEGIS_APPROVER_KEY_DIGEST": key_digest(approver_key, pepper),
        }
    )
    return config, agent_key, approver_key


class TestCredentials(unittest.TestCase):
    def test_each_key_only_works_for_its_own_role(self) -> None:
        config, agent_key, approver_key = make_config()
        self.assertTrue(config.verify(agent_key, Role.AGENT))
        self.assertTrue(config.verify(approver_key, Role.APPROVER))
        self.assertFalse(config.verify(agent_key, Role.APPROVER))
        self.assertFalse(config.verify(approver_key, Role.AGENT))

    def test_missing_or_wrong_keys_are_rejected(self) -> None:
        config, agent_key, _ = make_config()
        for provided in (None, "", agent_key + "x", agent_key.upper()):
            with self.subTest(provided=provided):
                self.assertFalse(config.verify(provided, Role.AGENT))

    def test_digest_depends_on_the_pepper(self) -> None:
        key = secrets.token_urlsafe(32)
        self.assertNotEqual(key_digest(key, secrets.token_urlsafe(32)), key_digest(key, secrets.token_urlsafe(32)))

    def test_misconfiguration_fails_closed(self) -> None:
        pepper = secrets.token_urlsafe(32)
        digest_a = key_digest(secrets.token_urlsafe(32), pepper)
        digest_b = key_digest(secrets.token_urlsafe(32), pepper)
        bad_envs = {
            "nothing set": {},
            "short pepper": {
                "AEGIS_API_KEY_PEPPER": "short",
                "AEGIS_AGENT_KEY_DIGEST": digest_a,
                "AEGIS_APPROVER_KEY_DIGEST": digest_b,
            },
            "approver digest missing": {"AEGIS_API_KEY_PEPPER": pepper, "AEGIS_AGENT_KEY_DIGEST": digest_a},
            "malformed digest": {
                "AEGIS_API_KEY_PEPPER": pepper,
                "AEGIS_AGENT_KEY_DIGEST": "abc123",
                "AEGIS_APPROVER_KEY_DIGEST": digest_b,
            },
            "same key for both roles": {
                "AEGIS_API_KEY_PEPPER": pepper,
                "AEGIS_AGENT_KEY_DIGEST": digest_a,
                "AEGIS_APPROVER_KEY_DIGEST": digest_a,
            },
        }
        for name, env in bad_envs.items():
            with self.subTest(name), self.assertRaises(CredentialConfigError):
                CredentialConfig.from_env(env)


if __name__ == "__main__":
    unittest.main()
