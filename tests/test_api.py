"""
HTTP-layer tests for the authorizer API. Skipped when FastAPI (and httpx, for TestClient) is not installed,
unless AEGIS_REQUIRE_API_TESTS=1 is set (as in CI), in which case missing dependencies fail the run.
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
REQUIRE_API_TESTS = os.environ.get("AEGIS_REQUIRE_API_TESTS") == "1"


class TestApiDependenciesPresent(unittest.TestCase):
    @unittest.skipUnless(REQUIRE_API_TESTS, "AEGIS_REQUIRE_API_TESTS is not set")
    def test_api_dependencies_are_installed(self) -> None:
        self.assertTrue(HAS_FASTAPI, "AEGIS_REQUIRE_API_TESTS=1 but fastapi/httpx are missing; API tests would skip.")


@unittest.skipUnless(HAS_FASTAPI, "fastapi and httpx are not installed")
class TestAuthorizerApi(unittest.TestCase):
    def setUp(self) -> None:
        from aegis_ai.api import create_app
        from aegis_ai.credentials import CredentialConfig, key_digest
        from fastapi.testclient import TestClient

        self._tmpdir = tempfile.TemporaryDirectory()
        pepper = secrets.token_urlsafe(32)
        self.agent_key, self.approver_key = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        credentials = CredentialConfig.from_env(
            {
                "AEGIS_API_KEY_PEPPER": pepper,
                "AEGIS_AGENT_KEY_DIGEST": key_digest(self.agent_key, pepper),
                "AEGIS_APPROVER_KEY_DIGEST": key_digest(self.approver_key, pepper),
            }
        )
        self.client = TestClient(create_app(Path(self._tmpdir.name), credentials=credentials))
        self.agent = {"X-Aegis-API-Key": self.agent_key}
        self.approver = {"X-Aegis-API-Key": self.approver_key}

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
        self.assertEqual(self.client.post("/v1/sessions", headers={"X-Aegis-API-Key": "wrong"}).status_code, 403)

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


@unittest.skipUnless(HAS_FASTAPI, "fastapi and httpx are not installed")
class TestApiFailsClosedWithoutCredentials(unittest.TestCase):
    def test_every_protected_route_answers_503(self) -> None:
        from aegis_ai.api import create_app
        from fastapi.testclient import TestClient

        with tempfile.TemporaryDirectory() as tmp, unittest.mock.patch.dict("os.environ", {}, clear=True):
            client = TestClient(create_app(Path(tmp)))
            self.assertEqual(client.post("/v1/sessions", headers={"X-Aegis-API-Key": "anything"}).status_code, 503)
            self.assertEqual(client.get("/healthz").status_code, 200)


if __name__ == "__main__":
    unittest.main()
