"""Tests for session bounds, workspace checks, container supply-chain pins, and the policy-synced Squid config."""

from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from aegis_ai.authorizer import Authorizer, SessionLimitError  # noqa: E402
from aegis_ai.egress import WorkspaceConfigError, check_workspace_root  # noqa: E402
from aegis_ai.egress_proxy import (  # noqa: E402
    BLOCKED_DESTINATION_CIDRS,
    DEFAULT_CLIENT_CIDRS,
    generate_squid_config,
    validate_egress_domain,
)
from aegis_ai.mcp_gateway import downstream_environment  # noqa: E402
from aegis_ai.models import Decision, ToolCallRequest  # noqa: E402
from aegis_ai.policy import PolicyConfig  # noqa: E402
from aegis_ai.policy_loader import load_policy_file  # noqa: E402


class TestSessionBounds(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmpdir.name)
        (self.workspace / "app.py").write_text("print('ok')\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_expired_session_fails_closed_and_purges_grants(self) -> None:
        t0 = datetime(2026, 11, 21, 22, 0, 0, tzinfo=UTC)
        auth = Authorizer(workspace_root=self.workspace, session_ttl_seconds=60)
        sid = auth.create_session(now=t0)
        auth.issue_grant(
            session_id=sid,
            tool_name="git_push",
            arguments={"branch": "feature/ttl"},
            approved_by="nate@mellyn.security",
            now=t0,
        )

        # Still active at +30s
        self.assertTrue(auth.has_session(sid, now=t0 + timedelta(seconds=30)))

        # Expired at +61s -> denied as unknown session (fail closed)
        res = auth.authorize(
            ToolCallRequest(session_id=sid, tool_name="workspace_read", arguments={"path": "app.py"}),
            now=t0 + timedelta(seconds=61),
        )
        self.assertEqual(res.decision, Decision.DENY)
        self.assertFalse(auth.has_session(sid, now=t0 + timedelta(seconds=61)))
        self.assertEqual(len(auth._grants), 0)

    def test_max_sessions_refuses_new_sessions_instead_of_evicting_active_ones(self) -> None:
        t0 = datetime(2026, 11, 21, 22, 0, 0, tzinfo=UTC)
        auth = Authorizer(workspace_root=self.workspace, max_sessions=2, session_ttl_seconds=60)
        s1 = auth.create_session(now=t0)
        auth.create_session(now=t0 + timedelta(seconds=1))
        with self.assertRaises(SessionLimitError):
            auth.create_session(now=t0 + timedelta(seconds=2))

        # The oldest session is still usable: opening sessions cannot be used to end someone else's.
        res = auth.authorize(
            ToolCallRequest(session_id=s1, tool_name="workspace_read", arguments={"path": "app.py"}),
            now=t0 + timedelta(seconds=2),
        )
        self.assertEqual(res.decision, Decision.ALLOW)

        # Once idle sessions expire, there is room again.
        self.assertTrue(auth.create_session(now=t0 + timedelta(seconds=120)))

    def test_sessions_without_ttl_never_expire(self) -> None:
        t0 = datetime(2026, 11, 21, 22, 0, 0, tzinfo=UTC)
        auth = Authorizer(workspace_root=self.workspace, session_ttl_seconds=None)
        sid = auth.create_session(now=t0)
        self.assertTrue(auth.has_session(sid, now=t0 + timedelta(days=30)))
        with self.assertRaises(ValueError):
            Authorizer(workspace_root=self.workspace, session_ttl_seconds=0)


class TestWorkspaceRootCheck(unittest.TestCase):
    def test_missing_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(WorkspaceConfigError):
            check_workspace_root(Path(tmp) / "missing", require_mount=False)

    def test_require_mount_rejects_a_plain_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            check_workspace_root(Path(tmp), require_mount=False)
            with self.assertRaises(WorkspaceConfigError):
                check_workspace_root(Path(tmp), require_mount=True)

    def test_require_mount_accepts_a_mount_point(self) -> None:
        root = Path(Path.cwd().anchor)  # "/" on Linux, "C:\\" on Windows: always a mount point
        check_workspace_root(root, require_mount=True)


class TestDownstreamEnvironment(unittest.TestCase):
    def test_aegis_secrets_are_not_passed_to_mcp_servers(self) -> None:
        env = downstream_environment(
            {
                "AEGIS_API_KEY_PEPPER": "p",
                "aegis_approver_key_digest": "d",
                "MELLYN_API_KEY_PEPPER": "p2",
                "PATH": "/bin",
                "HTTPS_PROXY": "x",
            }
        )
        self.assertEqual(env, {"PATH": "/bin", "HTTPS_PROXY": "x"})


class TestContainerSupplyChain(unittest.TestCase):
    def test_base_images_are_digest_pinned_and_installs_hash_pinned(self) -> None:
        for dockerfile in (REPO_ROOT / "Dockerfile", REPO_ROOT / "deploy" / "egress" / "Dockerfile"):
            with self.subTest(dockerfile=dockerfile.name):
                text = dockerfile.read_text(encoding="utf-8")
                from_lines = [line for line in text.splitlines() if line.startswith("FROM ")]
                self.assertTrue(from_lines)
                for line in from_lines:
                    self.assertRegex(line, r"@sha256:[0-9a-f]{64}$")
        app = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("--require-hashes", app)
        self.assertNotRegex(app, r'pip install[^\n]*"[a-z-]+==')  # no unhashed inline pins

    def test_dockerignore_keeps_secrets_and_venv_out_of_the_build_context(self) -> None:
        lines = [
            line.strip()
            for line in (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        self.assertEqual(lines[0], "*")  # deny everything, then re-include only what the Dockerfile copies
        included = [line[1:] for line in lines if line.startswith("!")]
        self.assertEqual(sorted(included), ["backend/", "deploy/requirements.lock"])

    def test_lockfile_pins_every_package_with_hashes(self) -> None:
        lock = (REPO_ROOT / "deploy" / "requirements.lock").read_text(encoding="utf-8")
        requirements = [line for line in lock.splitlines() if line and not line[0].isspace() and line[0] != "#"]
        self.assertTrue(requirements)
        for line in requirements:
            with self.subTest(line=line):
                self.assertRegex(line, r"^[A-Za-z0-9_.-]+==[0-9][^ ]* \\$")
        self.assertGreaterEqual(lock.count("--hash=sha256:"), len(requirements))


class TestEgressProxyGenerator(unittest.TestCase):
    def test_rejects_invalid_and_injectable_domains(self) -> None:
        bad_domains = [
            "",
            "localhost",
            "app.localhost",
            "printer.local",
            "169.254.169.254",
            "127.0.0.1",
            "*.github.com",
            "docs.python.org\nhttp_access allow all",
            "docs.python.org extra",
            "no-dot",
        ]
        for domain in bad_domains:
            with self.subTest(domain=domain):
                with self.assertRaises(ValueError):
                    validate_egress_domain(domain)

    def test_generated_squid_config_enforces_https_only_and_blocks_private_cidrs(self) -> None:
        policy = PolicyConfig(allowed_egress_domains=frozenset({"docs.python.org", "api.github.com"}))
        cfg = generate_squid_config(policy)

        self.assertIn("acl SSL_ports port 443", cfg)
        self.assertIn("http_access deny !CONNECT", cfg)
        self.assertIn("http_access deny !SSL_ports", cfg)
        self.assertIn("http_access deny raw_ip_host", cfg)
        for cidr in BLOCKED_DESTINATION_CIDRS:
            self.assertIn(f"acl blocked_dst dst {cidr}", cfg)
        self.assertIn("http_access deny blocked_dst", cfg)
        self.assertIn("acl allowed_domains dstdomain .api.github.com", cfg)
        self.assertIn("acl allowed_domains dstdomain .docs.python.org", cfg)
        self.assertIn("http_access allow CONNECT SSL_ports allowed_domains", cfg)
        self.assertTrue(cfg.rstrip().endswith("http_access deny all"))

    def test_only_the_internal_network_may_use_the_proxy(self) -> None:
        cfg = generate_squid_config(PolicyConfig(allowed_egress_domains=frozenset({"docs.python.org"})))
        self.assertIn("acl mellyn_clients src 172.30.250.0/24", cfg)
        lines = cfg.splitlines()
        self.assertLess(lines.index("http_access deny !mellyn_clients"), lines.index("http_access deny !CONNECT"))
        for bad in ((), ("not-a-cidr",), ("172.30.250.1/24",)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                generate_squid_config(PolicyConfig(), client_cidrs=bad)

    def test_compose_internal_subnet_matches_squid_client_cidr(self) -> None:
        compose = (REPO_ROOT / "deploy" / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn(f"subnet: {DEFAULT_CLIENT_CIDRS[0]}", compose)

    def test_empty_allowlist_fails_closed_with_no_allow_rules(self) -> None:
        cfg = generate_squid_config(PolicyConfig(allowed_egress_domains=frozenset()))
        self.assertNotIn("http_access allow", cfg)
        self.assertTrue(cfg.rstrip().endswith("http_access deny all"))

    def test_committed_squid_conf_matches_example_policy(self) -> None:
        policy = load_policy_file(REPO_ROOT / "config" / "mellyn-policy.example.toml")
        expected = generate_squid_config(policy)
        actual = (REPO_ROOT / "deploy" / "egress" / "squid.conf").read_text(encoding="utf-8").replace("\r\n", "\n")
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
