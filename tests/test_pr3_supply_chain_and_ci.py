"""Regression tests for PR 3 runtime wiring: pyproject runtime dependencies and CI container egress harness."""

from __future__ import annotations

import re
import sys
import tomllib
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
SCRIPTS_DIR = REPO_ROOT / "scripts"
for p in (SRC_DIR, SCRIPTS_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import verify_container_stack as vcs  # noqa: E402

from mellyn.egress_proxy import generate_squid_config  # noqa: E402
from mellyn.policy_loader import load_policy_file  # noqa: E402


class TestPyprojectAndContainerCiWiring(unittest.TestCase):
    def test_pyproject_declares_no_unused_runtime_dependencies(self) -> None:
        data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        deps = [re.split(r"[<>=!~\[\s]", d)[0] for d in data["project"]["dependencies"]]
        self.assertNotIn("pydantic-settings", deps)
        codebase = "\n".join(
            p.read_text(encoding="utf-8")
            for folder in ("src", "tests", "scripts")
            for p in (REPO_ROOT / folder).rglob("*.py")
        )
        # uvicorn is invoked as the container ASGI server in Dockerfile
        dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        combined = codebase + "\n" + dockerfile
        for pkg in deps:
            mod = pkg.replace("-", "_")
            self.assertIn(mod, combined, f"Declared dependency '{pkg}' is not referenced anywhere!")

    def test_ci_workflow_runs_container_and_egress_harness(self) -> None:
        ci_yaml = (REPO_ROOT / ".github" / "workflows" / "ai-security-gate.yml").read_text(encoding="utf-8")
        self.assertIn("container-and-egress:", ci_yaml)
        self.assertIn("python scripts/verify_container_stack.py", ci_yaml)

        # Confirm the harness renders a valid Squid config for its isolated CI subnet
        policy = load_policy_file(REPO_ROOT / "config" / "mellyn-policy.example.toml")
        rendered = generate_squid_config(policy, client_cidrs=(vcs.INTERNAL_SUBNET,))
        self.assertIn(f"acl mellyn_clients src {vcs.INTERNAL_SUBNET}", rendered)
        harness_src = (REPO_ROOT / "scripts" / "verify_container_stack.py").read_text(encoding="utf-8")
        self.assertIn("private.docs.python.org:127.0.0.1", harness_src)

    def test_deploy_requirements_lock_pins_every_package_with_hashes(self) -> None:
        """
        The container image installs deploy/requirements.lock with --require-hashes. The guardrails CI verifier checks
        the lock against PyPI; this keeps a fast local check that it still pins the runtime stack exactly.
        """
        text = (REPO_ROOT / "deploy" / "requirements.lock").read_text(encoding="utf-8")
        entries = re.split(r"\n(?=[A-Za-z0-9])", re.sub(r"(?m)^\s*#.*\n", "", text).strip())
        names = set()
        for entry in entries:
            with self.subTest(entry=entry.split()[0]):
                self.assertNotRegex(entry, r"^--|--(index-url|extra-index-url|find-links|trusted-host)\b")
                self.assertRegex(entry, r"^[A-Za-z0-9][A-Za-z0-9._-]*==[0-9][^\s\\;]*")
                self.assertRegex(entry, r"--hash=sha256:[0-9a-f]{64}")
                names.add(entry.split("==", 1)[0].lower().replace("-", "_"))
        for required in ("fastapi", "starlette", "uvicorn", "pydantic", "pydantic_core"):
            self.assertIn(required, names)


if __name__ == "__main__":
    unittest.main()
