"""Regression tests for the containerized Plane 4 viewer (`deploy/viewer/Dockerfile` & `docker-compose.yml`)."""

from __future__ import annotations

import re
import secrets
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VIEWER_DOCKERFILE = REPO_ROOT / "deploy" / "viewer" / "Dockerfile"
VIEWER_DOCKERIGNORE = REPO_ROOT / "deploy" / "viewer" / "Dockerfile.dockerignore"
COMPOSE_FILE = REPO_ROOT / "deploy" / "docker-compose.yml"
DEPLOY_README = REPO_ROOT / "deploy" / "README.md"
ENV_EXAMPLE = REPO_ROOT / ".env.example"

if str(REPO_ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "backend"))

from mellyn.credentials import CredentialConfig, Role, key_digest  # noqa: E402


def _compose_service(name: str) -> str:
    """Text of one top-level service block in docker-compose.yml."""
    compose = COMPOSE_FILE.read_text(encoding="utf-8")
    services = compose.split("\nservices:\n", 1)[1].split("\nnetworks:", 1)[0]
    blocks = re.split(r"\n(?=  [a-z][a-z0-9-]*:\n)", "\n" + services)
    for block in blocks:
        if block.startswith(f"  {name}:\n"):
            return block
    raise AssertionError(f"service {name} not found in {COMPOSE_FILE}")


def _env_example_values() -> dict[str, str]:
    """Active (uncommented) assignments in .env.example, as an env_file would load them."""
    values: dict[str, str] = {}
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key, value = stripped.split("=", 1)
            values[key.strip()] = value.strip()
    return values


class TestViewerContainerConfiguration(unittest.TestCase):
    def test_viewer_dockerfile_is_digest_hash_pinned_and_non_root(self) -> None:
        text = VIEWER_DOCKERFILE.read_text(encoding="utf-8")
        from_lines = [line.strip() for line in text.splitlines() if line.strip().startswith("FROM ")]
        self.assertEqual(len(from_lines), 2)
        for line in from_lines:
            self.assertRegex(line, r"@sha256:[0-9a-f]{64}(?:\s+AS\s+[A-Za-z0-9_-]+)?$")

        self.assertIn("npm ci --ignore-scripts", text)
        self.assertIn("--require-hashes --no-deps", text)
        self.assertIn("useradd --uid 10001", text)
        self.assertIn("\nUSER mellyn\n", text)
        self.assertIn("\nEXPOSE 8080\n", text)
        self.assertIn("HEALTHCHECK ", text)
        self.assertIn("--allow-non-loopback", text)

    def test_viewer_dockerignore_uses_deny_all_minimal_allowlist(self) -> None:
        lines = [
            line.strip()
            for line in VIEWER_DOCKERIGNORE.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        self.assertEqual(lines[0], "*")
        included = sorted(line[1:] for line in lines if line.startswith("!"))
        self.assertEqual(
            included,
            [
                "backend/",
                "deploy/requirements.lock",
                "frontend/index.html",
                "frontend/package-lock.json",
                "frontend/package.json",
                "frontend/src/",
                "frontend/tsconfig.json",
                "frontend/vite.config.ts",
                "src/",
            ],
        )

    def test_compose_hardens_viewer_loopback_mounts_and_network_isolation(self) -> None:
        viewer_section = _compose_service("mellyn-viewer")

        self.assertIn("<<: *hardening", viewer_section)
        self.assertIn('profiles: ["viewer"]', viewer_section)
        self.assertIn('"127.0.0.1:8080:8080"', viewer_section)
        self.assertIn("MELLYN_APPROVAL_HOST: mellyn-approval-relay", viewer_section)
        self.assertIn("mellyn-frontend", viewer_section)
        self.assertNotIn("mellyn-internal", viewer_section)
        self.assertNotIn("mellyn-egress-net", viewer_section)

    def test_viewer_mounts_only_what_it_reads_all_read_only(self) -> None:
        viewer_section = _compose_service("mellyn-viewer")
        mounts = [
            line.strip()[2:]
            for line in viewer_section.splitlines()
            if line.strip().startswith("- ") and ":/var/" in line
        ]
        # The gateway audit log, and a host evidence folder for the Airlock ledger and assurance report. The
        # authorizer's audit volume is not mounted: no viewer route reads it.
        self.assertEqual(
            mounts,
            [
                "mellyn-gateway-audit-logs:/var/log/mellyn/gateway:ro",
                "${MELLYN_EVIDENCE_DIR:-../evidence}:/var/lib/mellyn/evidence:ro",
            ],
        )
        for env_path in ("/var/lib/mellyn/evidence/audit.jsonl", "/var/lib/mellyn/evidence/control-assurance.json"):
            self.assertIn(env_path, viewer_section)
        # A named volume that no service writes to would leave the viewer reporting a missing ledger forever.
        compose = COMPOSE_FILE.read_text(encoding="utf-8")
        self.assertNotIn("mellyn-evidence-artifacts", compose)
        self.assertIn("\nevidence/\n", (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").replace("\r\n", "\n"))

    def test_viewer_profile_brings_the_relay_but_never_a_detached_gateway(self) -> None:
        self.assertIn('profiles: ["gateway", "viewer"]', _compose_service("mellyn-approval-relay"))
        self.assertIn('profiles: ["gateway"]', _compose_service("mellyn-gateway"))
        self.assertIn("mellyn-frontend", _compose_service("mellyn-approval-relay"))

        # `up` with the gateway profile would start a second gateway sharing the `mellyn-gateway` alias with the one
        # the MCP client runs, so the relay could deliver approvals to the wrong one.
        for line in DEPLOY_README.read_text(encoding="utf-8").splitlines():
            if "docker compose" in line and " up" in line:
                with self.subTest(command=line.strip()):
                    self.assertNotIn("--profile gateway", line)
        self.assertIn(
            "docker compose -f deploy/docker-compose.yml --profile viewer up -d --build",
            DEPLOY_README.read_text(encoding="utf-8"),
        )

    def test_env_example_keeps_the_optional_viewer_digest_commented_out(self) -> None:
        env_text = ENV_EXAMPLE.read_text(encoding="utf-8")
        self.assertRegex(env_text, r"(?m)^# MELLYN_VIEWER_KEY_DIGEST=replace_with_")
        self.assertNotIn("MELLYN_VIEWER_KEY_DIGEST", _env_example_values())

    def test_env_example_with_required_digests_filled_loads_without_the_viewer(self) -> None:
        # Exactly what the setup steps ask for: the pepper plus the agent and approver digests, nothing else edited.
        # The authorizer (agent + approver) and the gateway (approver) must start; before the fix the active viewer
        # placeholder made both raise CredentialConfigError.
        env = _env_example_values()
        pepper = secrets.token_urlsafe(32)
        env["MELLYN_API_KEY_PEPPER"] = pepper
        env["MELLYN_AGENT_KEY_DIGEST"] = key_digest(secrets.token_urlsafe(32), pepper)
        env["MELLYN_APPROVER_KEY_DIGEST"] = key_digest(secrets.token_urlsafe(32), pepper)
        for roles in (frozenset({Role.AGENT, Role.APPROVER}), frozenset({Role.APPROVER})):
            with self.subTest(roles=sorted(r.value for r in roles)):
                CredentialConfig.from_env(env, roles=roles)

        # Once the viewer digest is uncommented with a real value, all three roles load together.
        env["MELLYN_VIEWER_KEY_DIGEST"] = key_digest(secrets.token_urlsafe(32), pepper)
        CredentialConfig.from_env(env, roles=frozenset(Role))
