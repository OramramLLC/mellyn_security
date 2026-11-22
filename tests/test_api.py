"""
HTTP-layer tests for the authorizer API. Skipped when FastAPI (and httpx, for TestClient) is not installed,
unless MELLYN_REQUIRE_API_TESTS=1 is set (as in CI), in which case missing dependencies fail the run.
"""

from __future__ import annotations

import importlib.util
import os
import secrets
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

HAS_FASTAPI = all(importlib.util.find_spec(name) is not None for name in ("fastapi", "httpx"))
REQUIRE_API_TESTS = os.environ.get("MELLYN_REQUIRE_API_TESTS") == "1"


class TestApiDependenciesPresent(unittest.TestCase):
    @unittest.skipUnless(REQUIRE_API_TESTS, "MELLYN_REQUIRE_API_TESTS is not set")
    def test_api_dependencies_are_installed(self) -> None:
        self.assertTrue(HAS_FASTAPI, "MELLYN_REQUIRE_API_TESTS=1 but fastapi/httpx are missing; API tests would skip.")


@unittest.skipUnless(HAS_FASTAPI, "fastapi and httpx are not installed")
class TestAuthorizerApi(unittest.TestCase):
    def setUp(self) -> None:
        from fastapi.testclient import TestClient
        from mellyn.api import create_app
        from mellyn.credentials import CredentialConfig, key_digest

        self._tmpdir = tempfile.TemporaryDirectory()
        pepper = secrets.token_urlsafe(32)
        self.agent_key, self.approver_key = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        credentials = CredentialConfig.from_env(
            {
                "MELLYN_API_KEY_PEPPER": pepper,
                "MELLYN_AGENT_KEY_DIGEST": key_digest(self.agent_key, pepper),
                "MELLYN_APPROVER_KEY_DIGEST": key_digest(self.approver_key, pepper),
            }
        )
        self.client = TestClient(create_app(Path(self._tmpdir.name), credentials=credentials))
        self.agent = {"X-Mellyn-API-Key": self.agent_key}
        self.approver = {"X-Mellyn-API-Key": self.approver_key}

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def new_session(self) -> str:
        response = self.client.post("/v1/sessions", headers=self.agent)
        self.assertEqual(response.status_code, 201)
        return response.json()["session_id"]

    def authorize(self, body: dict) -> dict:
        response = self.client.post("/v1/agent/authorize", headers=self.agent, json=body)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_healthz_is_public(self) -> None:
        self.assertEqual(self.client.get("/healthz").status_code, 200)

    def test_routes_require_a_key(self) -> None:
        self.assertEqual(self.client.post("/v1/sessions").status_code, 401)
        self.assertEqual(self.client.post("/v1/sessions", headers={"X-Mellyn-API-Key": "wrong"}).status_code, 403)

    def test_agent_key_cannot_approve_its_own_calls(self) -> None:
        session = self.new_session()
        grant = {"tool_name": "git_push", "arguments": {"branch": "main"}, "approved_by": "agent"}
        response = self.client.post(f"/v1/sessions/{session}/grants", headers=self.agent, json=grant)
        self.assertEqual(response.status_code, 403)

    def test_approver_key_cannot_call_agent_routes(self) -> None:
        self.assertEqual(self.client.post("/v1/sessions", headers=self.approver).status_code, 403)

    def test_approval_flow(self) -> None:
        session = self.new_session()
        call = {"session_id": session, "tool_name": "git_push", "arguments": {"branch": "feature/x"}}
        self.assertEqual(self.authorize(call)["decision"], "require_approval")
        grant = {"tool_name": "git_push", "arguments": {"branch": "feature/x"}, "approved_by": "reviewer@example.com"}
        response = self.client.post(f"/v1/sessions/{session}/grants", headers=self.approver, json=grant)
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(self.authorize(call)["decision"], "allow")
        self.assertEqual(self.authorize(call)["decision"], "require_approval")

    def test_invented_session_is_denied_and_unknown_session_routes_404(self) -> None:
        result = self.authorize({"session_id": "sess-made-up", "tool_name": "workspace_read", "arguments": {}})
        self.assertEqual(result["decision"], "deny")
        taint = {"source_type": "web_page", "origin": "https://example.com"}
        self.assertEqual(
            self.client.post("/v1/sessions/sess-made-up/taint", headers=self.agent, json=taint).status_code, 404
        )

    def test_payloads_are_strict(self) -> None:
        session = self.new_session()
        for body in (
            {"session_id": session, "tool_name": "workspace_read", "unexpected": True},
            {"session_id": session, "tool_name": 7},
        ):
            with self.subTest(body=body):
                response = self.client.post("/v1/agent/authorize", headers=self.agent, json=body)
                self.assertEqual(response.status_code, 422)

    def test_oversized_arguments_are_rejected(self) -> None:
        session = self.new_session()
        body = {"session_id": session, "tool_name": "workspace_write", "arguments": {"content": "x" * 70000}}
        response = self.client.post("/v1/agent/authorize", headers=self.agent, json=body)
        self.assertEqual(response.status_code, 413)

    def test_empty_policy_denies_mcp_server_even_with_grant_while_allowing_local(self) -> None:
        session = self.new_session()
        grant = {
            "tool_name": "git_status",
            "mcp_server": "dummy-mcp",
            "arguments": {},
            "approved_by": "reviewer@example.com",
        }
        grant_resp = self.client.post(f"/v1/sessions/{session}/grants", headers=self.approver, json=grant)
        self.assertEqual(grant_resp.status_code, 201, grant_resp.text)

        mcp_call = {"session_id": session, "tool_name": "git_status", "mcp_server": "dummy-mcp", "arguments": {}}
        self.assertEqual(self.authorize(mcp_call)["decision"], "deny")

        local_call = {"session_id": session, "tool_name": "git_status", "arguments": {}}
        self.assertEqual(self.authorize(local_call)["decision"], "allow")


@unittest.skipUnless(HAS_FASTAPI, "fastapi and httpx are not installed")
class TestApiFailsClosedWithoutCredentials(unittest.TestCase):
    def test_every_protected_route_answers_503(self) -> None:
        from fastapi.testclient import TestClient
        from mellyn.api import create_app

        with tempfile.TemporaryDirectory() as tmp, unittest.mock.patch.dict("os.environ", {}, clear=True):
            client = TestClient(create_app(Path(tmp)))
            self.assertEqual(client.post("/v1/sessions", headers={"X-Mellyn-API-Key": "anything"}).status_code, 503)
            self.assertEqual(client.get("/healthz").status_code, 200)


@unittest.skipUnless(HAS_FASTAPI, "fastapi and httpx are not installed")
class TestCreateAppFromEnv(unittest.TestCase):
    def test_fails_closed_on_invalid_policy_path(self) -> None:
        from mellyn.api import create_app_from_env
        from mellyn.policy_loader import PolicyLoadError

        with tempfile.TemporaryDirectory() as tmp:
            env = {
                "MELLYN_POLICY_PATH": str(Path(tmp) / "missing.toml"),
                "MELLYN_WORKSPACE_ROOT": tmp,
                "MELLYN_REQUIRE_WORKSPACE_MOUNT": "0",
            }
            with unittest.mock.patch.dict("os.environ", env, clear=True), self.assertRaises(PolicyLoadError):
                create_app_from_env()

    def test_writes_audit_log_and_closes_sink_on_lifespan_shutdown(self) -> None:
        from fastapi.testclient import TestClient
        from mellyn.api import create_app_from_env
        from mellyn.credentials import key_digest

        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "ws"
            workspace.mkdir()
            audit_file = Path(tmp) / "logs" / "audit.jsonl"
            pepper = secrets.token_urlsafe(32)
            agent_key = secrets.token_urlsafe(32)
            approver_key = secrets.token_urlsafe(32)
            env = {
                "MELLYN_WORKSPACE_ROOT": str(workspace),
                "MELLYN_REQUIRE_WORKSPACE_MOUNT": "0",
                "MELLYN_AUDIT_LOG_PATH": str(audit_file),
                "MELLYN_API_KEY_PEPPER": pepper,
                "MELLYN_AGENT_KEY_DIGEST": key_digest(agent_key, pepper),
                "MELLYN_APPROVER_KEY_DIGEST": key_digest(approver_key, pepper),
            }
            with unittest.mock.patch.dict("os.environ", env, clear=True):
                app = create_app_from_env()
                with TestClient(app) as client:
                    sid = client.post("/v1/sessions", headers={"X-Mellyn-API-Key": agent_key}).json()["session_id"]
                    res = client.post(
                        "/v1/agent/authorize",
                        headers={"X-Mellyn-API-Key": agent_key},
                        json={"session_id": sid, "tool_name": "git_status", "arguments": {}},
                    )
                    self.assertEqual(res.status_code, 200)

            lines = audit_file.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            self.assertIn("git_status", lines[0])


@unittest.skipUnless(HAS_FASTAPI, "fastapi and httpx are not installed")
class TestApiRefusesHalfMigratedEnvironment(unittest.TestCase):
    def test_create_app_from_env_refuses_old_prefixed_variables(self) -> None:
        from mellyn.api import create_app_from_env
        from mellyn.legacy_env import LEGACY_ENV_PREFIX, LegacyConfigError

        with unittest.mock.patch.dict("os.environ", {LEGACY_ENV_PREFIX + "API_KEY_PEPPER": "x" * 40}, clear=True):
            with self.assertRaises(LegacyConfigError):
                create_app_from_env()


if __name__ == "__main__":
    unittest.main()
