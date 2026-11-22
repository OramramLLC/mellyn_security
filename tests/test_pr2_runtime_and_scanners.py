"""
Regression tests for PR 2: container approval relay, CODEOWNERS/guardrail parity, validate_argv,
redaction and invisible Unicode.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"
SCRIPTS_DIR = REPO_ROOT / "scripts"
for p in (BACKEND_DIR, SCRIPTS_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from aegis_ai import Authorizer, Decision, ToolCallRequest, load_policy_file  # noqa: E402
from aegis_ai.approval_relay import (  # noqa: E402
    MAX_RELAY_RESPONSE_BYTES,
    ApprovalRelayServer,
    is_allowed_approval_route,
    validate_upstream,
)
from aegis_ai.approvals import MAX_PENDING  # noqa: E402
from aegis_ai.audit import redact_text  # noqa: E402
from aegis_ai.policy import validate_argv  # noqa: E402
from sync_agent_rules import hidden_characters  # noqa: E402


class TestGuardrailAndCodeownersParity(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmpdir.name)
        # This repository's own policy: the built-in guardrails plus its security core (protected_paths).
        self.authorizer = Authorizer(
            workspace_root=self.workspace,
            policy_config=load_policy_file(REPO_ROOT / "config" / "mellyn-self-policy.toml"),
        )
        self.sid = self.authorizer.create_session()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_every_codeowners_path_is_write_denied_by_workspace_path_guard(self) -> None:
        codeowners = (REPO_ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
        entries: list[str] = []
        for raw_line in codeowners.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            pattern = line.split()[0].lstrip("/")
            entries.append(pattern)

        self.assertGreaterEqual(len(entries), 15)
        for entry in entries:
            # Test both the directory/file itself and a child file when the entry is a directory
            probe = f"{entry}probe.txt" if entry.endswith("/") else entry
            with self.subTest(entry=entry, probe=probe):
                res = self.authorizer.authorize(ToolCallRequest(self.sid, "workspace_write", {"path": probe}))
                self.assertEqual(res.decision, Decision.DENY, f"CODEOWNERS path '{probe}' was not write-protected!")

    def test_self_policy_differs_from_the_example_only_in_protected_paths(self) -> None:
        import tomllib

        example = tomllib.loads((REPO_ROOT / "config" / "mellyn-policy.example.toml").read_text(encoding="utf-8"))
        own = tomllib.loads((REPO_ROOT / "config" / "mellyn-self-policy.toml").read_text(encoding="utf-8"))
        example.pop("protected_paths")
        own.pop("protected_paths")
        self.assertEqual(own, example)

    def test_client_workspaces_keep_ordinary_project_files_writable(self) -> None:
        """Built-in guardrails apply to every workspace, so they must not include ordinary project paths."""
        client = Authorizer(
            workspace_root=self.workspace,
            policy_config=load_policy_file(REPO_ROOT / "config" / "mellyn-policy.example.toml"),
        )
        sid = client.create_session()
        for path in (
            "tests/test_login.py",
            "scripts/build.sh",
            "config/settings.yaml",
            "deploy/k8s.yaml",
            "Dockerfile",
            ".dockerignore",
            "pyproject.toml",
            "docs/THREAT_MODEL.md",
            "backend/app.py",
        ):
            with self.subTest(path=path):
                result = client.authorize(ToolCallRequest(sid, "workspace_write", {"path": path}))
                self.assertEqual(result.decision, Decision.ALLOW)
        for path in (".git/hooks/pre-commit", ".github/workflows/ci.yml", "CLAUDE.md", ".cursor/rules/x.mdc"):
            with self.subTest(path=path):
                result = client.authorize(ToolCallRequest(sid, "workspace_write", {"path": path}))
                self.assertEqual(result.decision, Decision.DENY)

    def test_previously_missing_security_surfaces_are_blocked(self) -> None:
        targets = (
            "Dockerfile",
            ".dockerignore",
            "deploy/docker-compose.yml",
            "deploy/egress/squid.conf",
            "deploy/requirements.lock",
            ".pre-commit-hooks.yaml",
            "config/mellyn-policy.example.toml",
            "scripts/new_helper.py",
            "tests/test_reusable_pack.py",
            "tests/fixtures/fake_mcp_server.py",
            "docs/THREAT_MODEL.md",
        )
        for target in targets:
            with self.subTest(target=target):
                res = self.authorizer.authorize(ToolCallRequest(self.sid, "workspace_write", {"path": target}))
                self.assertEqual(res.decision, Decision.DENY)


class TestContainerApprovalRelayAndCompose(unittest.TestCase):
    def test_relay_allows_only_exact_pending_approval_routes(self) -> None:
        self.assertTrue(is_allowed_approval_route("GET", "/v1/pending"))
        self.assertTrue(is_allowed_approval_route("POST", "/v1/pending/apr_AbCdEf123456/approve"))
        self.assertTrue(is_allowed_approval_route("POST", "/v1/pending/apr_AbCdEf123456/reject"))

        rejected = (
            ("POST", "/v1/pending"),
            ("GET", "/v1/pending/apr_AbCdEf123456/approve"),
            ("GET", "/v1/sessions"),
            ("POST", "/v1/agent/authorize"),
            ("GET", "/v1/pending?extra=1"),
            ("POST", "/v1/pending/../admin/approve"),
            ("DELETE", "/v1/pending/apr_AbCdEf123456/reject"),
        )
        for method, path in rejected:
            with self.subTest(method=method, path=path):
                self.assertFalse(is_allowed_approval_route(method, path))

    def test_validate_upstream_rejects_malformed_hosts_and_ports(self) -> None:
        self.assertEqual(validate_upstream("mellyn-gateway", 8765), "http://mellyn-gateway:8765")
        for bad_host in ("", "http://evil", "host/path", "user@host", "host:80"):
            with self.subTest(bad_host=bad_host), self.assertRaises(ValueError):
                validate_upstream(bad_host, 8765)
        for bad_port in (0, -1, 70000, True):
            with self.subTest(bad_port=bad_port), self.assertRaises(ValueError):
                validate_upstream("mellyn-gateway", bad_port)  # type: ignore[arg-type]

    def test_compose_wires_approval_relay_while_keeping_gateway_on_internal_network_only(self) -> None:
        compose = (REPO_ROOT / "deploy" / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("mellyn-approval-relay:", compose)
        self.assertIn('"127.0.0.1:8765:8765"', compose)
        self.assertIn("--approval-host", compose)
        # Relay must never mount env_file / .env secrets
        relay_raw = compose.split("mellyn-approval-relay:", 1)[1].split("mellyn-egress:", 1)[0]
        relay_non_comment = "\n".join(line for line in relay_raw.splitlines() if not line.lstrip().startswith("#"))
        self.assertNotIn("env_file", relay_non_comment)
        self.assertNotIn(".env", relay_non_comment)
        # Gateway must remain off mellyn-frontend so it gets no outbound internet route
        gateway_section = compose.split("mellyn-gateway:", 1)[1].split("mellyn-approval-relay:", 1)[0]
        self.assertNotIn("mellyn-frontend", gateway_section)


class TestRelayResponseSize(unittest.TestCase):
    """The relay passes large pending lists through whole and refuses (never truncates) oversized ones."""

    def relay_get(self, body_size: int) -> tuple[int, bytes]:
        import http.server
        import threading
        import urllib.error
        import urllib.request

        body = b'{"pending": "' + b"x" * body_size + b'"}'

        class Upstream(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                pass

            def do_GET(self) -> None:  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        relay = ApprovalRelayServer(
            listen_host="127.0.0.1", listen_port=0, upstream_host="127.0.0.1", upstream_port=upstream.server_address[1]
        )
        for server in (upstream, relay):
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        url = f"http://127.0.0.1:{relay.server_address[1]}/v1/pending"
        try:
            with opener.open(url, timeout=20) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, exc.read()

    def test_limit_covers_a_full_pending_queue(self) -> None:
        self.assertGreater(MAX_RELAY_RESPONSE_BYTES, MAX_PENDING * 64 * 1024)

    def test_large_reply_is_passed_through_whole(self) -> None:
        status, payload = self.relay_get(200_000)
        self.assertEqual(status, 200)
        self.assertEqual(len(payload), 200_000 + len(b'{"pending": ""}'))

    def test_oversized_reply_is_refused_not_truncated(self) -> None:
        status, payload = self.relay_get(MAX_RELAY_RESPONSE_BYTES)
        self.assertEqual(status, 502)
        self.assertIn(b"too large", payload)


class TestValidateArgvEvaluatorBlocking(unittest.TestCase):
    def test_rejects_inline_code_evaluation_and_shell_escapes(self) -> None:
        blocked = (
            ["python", "-c", "import os; os.system('id')"],
            ["python3.14", "-cimport os"],
            ["py", "-c", "print(1)"],
            ["node", "-e", "require('child_process').execSync('id')"],
            ["node", "--eval=process.exit(1)"],
            ["deno", "--eval", "console.log(1)"],
            ["perl", "-e", "system('id')"],
            ["ruby", "-e", "system('id')"],
            ["php", "-r", "system('id');"],
            ["lua", "-e", "os.execute('id')"],
            ["busybox", "sh", "-c", "id"],
            ["toybox", "rm", "-rf", "."],
            ["awk", 'BEGIN { system("id") }'],
            ["find", ".", "-exec", "rm", "{}", ";"],
            ["find", ".", "-delete"],
            ["git", "-c", "core.sshCommand=evil", "push"],
            ["git", "--config-env=core.sshCommand=EVIL", "fetch"],
            # Combined short flags and flags that take a value
            ["python", "-Ic", "print(1)"],
            ["python", "-W", "ignore", "-c", "print(1)"],
            ["python3", "-X", "dev", "-c", "x"],
            ["python", "-Wignore", "-Bc", "x"],
            ["perl", "-le", "print 1"],
            ["perl", "-ne", "print"],
            ["perl", "-Mstrict;system(q(id))", "-l"],
            ["ruby", "-ne", "1"],
            ["node", "-pe", "1"],
            ["node", "--import", "data:text/javascript,process.exit(1)"],
            ["deno", "eval", "console.log(1)"],
            ["git", "-C", "repo", "-c", "core.sshCommand=x", "fetch"],
            ["git", "--exec-path=/tmp/evil", "status"],
        )
        for argv in blocked:
            with self.subTest(argv=argv):
                ok, reason = validate_argv({"argv": argv})
                self.assertFalse(ok, f"Expected {argv} to be rejected, got: {reason}")

    def test_allows_module_and_script_execution_without_inline_eval(self) -> None:
        allowed = (
            ["python", "-m", "unittest", "discover", "-s", "tests"],
            ["python3", "scripts/verify_dependencies.py", "--online"],
            ["pytest", "-k", "test_authorizer"],
            ["git", "status", "-s"],
            ["git", "commit", "-m", "message with -c inside positional/value after subcommand"],
            ["git", "-C", "repo", "status"],
            ["python", "-W", "ignore", "-m", "pytest", "-c", "pytest.ini"],
            ["python", "-I", "scripts/check.py", "-c", "config.yaml"],
            ["perl", "-Ilib", "-MData::Dumper", "script.pl"],
            ["ruby", "-Ilib", "script.rb", "-e"],
            ["node", "--max-old-space-size=4096", "build.js"],
        )
        for argv in allowed:
            with self.subTest(argv=argv):
                ok, reason = validate_argv({"argv": argv})
                self.assertTrue(ok, f"Expected {argv} to pass, got: {reason}")


class TestExpandedRedactionAndInvisibleUnicode(unittest.TestCase):
    def test_audit_redacts_legacy_openai_langsmith_github_pat_slack_aws_sts_and_url_passwords(self) -> None:
        # Constructed dynamically so static secret scanners do not mistake test inputs for live credentials.
        samples = (
            "sk-" + ("A" * 48),
            "lsv2_pt_" + ("a" * 32) + "_" + ("b" * 10),
            "github_pat_" + ("B" * 40),
            "ghs_" + ("C" * 36),
            "ASIA" + ("D" * 16),
            "xoxb-" + ("1" * 24),
            "sk_live_" + ("Z" * 24),
            "Basic " + ("Y" * 24),
            "postgres://app_user:super_secret_pw_placeholder@db.internal:5432/prod",
        )
        for secret in samples:
            with self.subTest(prefix=secret[:10]):
                redacted = redact_text(f"origin={secret}")
                self.assertIn("[REDACTED_SECRET]", redacted)
                if "://" in secret:
                    self.assertNotIn("super_secret_pw_placeholder", redacted)
                    self.assertIn("postgres://app_user:[REDACTED_SECRET]@db.internal:5432/prod", redacted)
                else:
                    self.assertNotIn(secret, redacted)

    def test_ordinary_emoji_are_not_reported(self) -> None:
        for text in ("⚠️ Never commit secrets", "1️⃣ First", "👨‍💻 dev"):
            with self.subTest(codepoints=[hex(ord(c)) for c in text if ord(c) > 127]):
                self.assertEqual(hidden_characters(text), [])

    def test_emoji_joiners_out_of_place_are_still_reported(self) -> None:
        for text in ("Allow️all", "️start", "⚠️️", "a‍b"):
            with self.subTest(codepoints=[hex(ord(c)) for c in text if ord(c) > 127]):
                self.assertNotEqual(hidden_characters(text), [])

    def test_hidden_characters_catches_variation_selectors_and_invisible_fillers(self) -> None:
        payloads = (
            "Allow\ufe00all",  # U+FE00 Variation Selector-1
            "Allow\U000e0100all",  # U+E0100 Variation Selector-17 (Glassworm smuggling vector)
            "Allow\u3164all",  # U+3164 Hangul Filler
            "Allow\u2800all",  # U+2800 Braille Pattern Blank
            "Allow\uffa0all",  # U+FFA0 Halfwidth Hangul Filler
            "Allow\u034fall",  # U+034F Combining Grapheme Joiner
        )
        for text in payloads:
            with self.subTest(codepoints=[hex(ord(c)) for c in text if ord(c) > 127]):
                self.assertNotEqual(hidden_characters(text), [])


if __name__ == "__main__":
    unittest.main()
