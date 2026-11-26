"""Regression tests: remote MCP server and OAuth hosts are gateway-only, and secret env vars stay out of servers.

- Remote `streamable-http` server URLs and their OAuth authorization servers and token endpoints never join the tool
  egress policy: a shared host such as github.com there would let any tool reach an attacker's account on it.
- The gateway's own remote-server clients still reach them, and Squid lists them in their own section.
- OAuth secret variables the config names (`client_secret_env`, `bearer_token_env`) are withheld from downstream
  MCP servers, which are untrusted.
"""

from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
for _import_dir in (REPO_ROOT, REPO_ROOT / "src"):
    if str(_import_dir) not in sys.path:
        sys.path.insert(0, str(_import_dir))

from mellyn import mcp_gateway  # noqa: E402
from mellyn.egress import EgressValidator  # noqa: E402
from mellyn.egress_proxy import generate_squid_config  # noqa: E402
from mellyn.egress_proxy import main as egress_main  # noqa: E402
from mellyn.mcp_gateway import downstream_environment  # noqa: E402
from mellyn.unified_config import parse_unified_dict  # noqa: E402

CLIENT_SECRET_ENV = "REMOTE_" + "CLIENT_SECRET"
BEARER_ENV = "OTHER_" + "BEARER_TOKEN"

CONFIG = f"""
schema_version = 2

[[servers]]
name = "web"
transport = "stdio"
preset = "mcp-fetch"
command = ["mcp-fetch"]

[[servers]]
name = "remote"
transport = "streamable-http"
url = "https://mcp.remote.example/mcp"
oauth = {{ flow = "client_credentials", allowed_authorization_servers = ["https://auth.remote.example"], \
client_id = "mellyn", client_secret_env = "{CLIENT_SECRET_ENV}", \
token_endpoint = "https://token.remote.example/token" }}

[[servers]]
name = "other"
transport = "streamable-http"
url = "https://mcp.other.example/mcp"
oauth = {{ flow = "bearer_env", bearer_token_env = "{BEARER_ENV}" }}
"""
GATEWAY_ONLY = {"mcp.remote.example", "auth.remote.example", "token.remote.example", "mcp.other.example"}


class _ConfigCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "ws"
        self.workspace.mkdir()
        self.config = self.root / "mellyn.toml"
        self.config.write_text(CONFIG, encoding="utf-8")

    def load(self) -> Any:
        return parse_unified_dict(tomllib.loads(CONFIG), base_dir=self.root, config_path=self.config)

    def argv(self) -> list[str]:
        return [
            "--config",
            str(self.config),
            "--workspace",
            str(self.workspace),
            "--audit-log",
            str(self.root / "audit.jsonl"),
        ]


class TestRemoteHostsAreGatewayOnly(_ConfigCase):
    def test_tools_cannot_reach_remote_server_or_oauth_hosts(self) -> None:
        unified = self.load()
        self.assertEqual(unified.gateway_egress_domains, frozenset(GATEWAY_ONLY))
        # Before the fix every one of these was in the tool policy, so any tool could send data there.
        self.assertEqual(unified.policy.allowed_egress_domains & GATEWAY_ONLY, frozenset())
        for url in ("https://auth.remote.example/anything", "https://mcp.other.example/x"):
            with self.subTest(url=url):
                allowed, _ = EgressValidator(unified.policy.allowed_egress_domains).validate_url(url)
                self.assertFalse(allowed)

    def test_squid_still_allows_them_in_their_own_exact_host_section(self) -> None:
        unified = self.load()
        squid = generate_squid_config(unified.policy, gateway_domains=unified.gateway_egress_domains)
        for host in sorted(GATEWAY_ONLY):
            with self.subTest(host=host):
                self.assertIn(f"acl gateway_domains dstdomain {host}", squid)
                self.assertNotIn(f"dstdomain .{host}", squid)  # exact host, not every subdomain

        out = self.root / "squid.conf"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(egress_main(["--policy", str(self.config), "--output", str(out)]), 0)
        self.assertIn("acl gateway_domains dstdomain mcp.remote.example", out.read_text(encoding="utf-8"))

    def test_the_gateway_gives_remote_clients_the_gateway_hosts(self) -> None:
        seen: dict[str, Any] = {}

        def record(*_args: Any, **kwargs: Any) -> Any:
            seen.update(kwargs)
            raise RuntimeError("stop after recording the remote client's allowlist")

        with (
            mock.patch.object(mcp_gateway, "StdioDownstream", return_value=mock.MagicMock()),
            mock.patch.object(mcp_gateway, "StreamableHttpDownstream", side_effect=record),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            mcp_gateway.main(self.argv())
        allowed = seen.get("allowed_domains") or frozenset()
        # Without the gateway hosts here, remote servers would stop working after the move.
        self.assertIn("mcp.remote.example", allowed)
        self.assertIn("auth.remote.example", allowed)


class TestSecretEnvIsWithheldFromServers(_ConfigCase):
    def test_named_secrets_are_dropped_from_the_child_environment(self) -> None:
        unified = self.load()
        self.assertEqual(set(unified.secret_env_names), {CLIENT_SECRET_ENV, BEARER_ENV})
        parent = {CLIENT_SECRET_ENV: "s", BEARER_ENV.lower(): "t", "PATH": "/bin"}
        child = downstream_environment(parent, secret_names=unified.secret_env_names)
        self.assertEqual(child, {"PATH": "/bin"})  # matched case-insensitively, as Windows treats names

    def test_the_gateway_passes_the_secret_names_to_its_servers(self) -> None:
        seen: dict[str, Any] = {}

        def record(*_args: Any, **kwargs: Any) -> Any:
            seen.update(kwargs)
            raise RuntimeError("stop after recording the downstream environment")

        with (
            mock.patch.object(mcp_gateway, "StdioDownstream", side_effect=record),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            mcp_gateway.main(self.argv())
        # Before the fix nothing was withheld: stdio servers inherited the OAuth secrets.
        self.assertEqual(set(seen.get("secret_env_names") or ()), {CLIENT_SECRET_ENV, BEARER_ENV})


if __name__ == "__main__":
    unittest.main()
