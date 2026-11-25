"""Tests for unified package/CLI (`mellyn`), curated SMB presets, `mellyn init`/`up`, and guard parity."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"
SRC_DIR = REPO_ROOT / "src"
for _p in (BACKEND_DIR, SRC_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

if importlib.util.find_spec("pydantic") is None and os.environ.get("MELLYN_REQUIRE_API_TESTS") != "1":
    raise unittest.SkipTest("pydantic is not installed; unified CLI tests skipped")

from mellyn import (  # noqa: E402
    MCP_CAPABILITY_PRESETS,
    SMB_SERVER_PRESETS,
    Authorizer,
    CredentialConfig,
    CredentialConfigError,
    Decision,
    Role,
    ToolCallRequest,
    load_policy_file,
)
from mellyn.cli import MELLYN_VERSION  # noqa: E402
from mellyn.cli import main as mellyn_cli_main  # noqa: E402
from mellyn.egress import EgressValidator as GatewayEgressValidator  # noqa: E402
from mellyn.egress import WorkspacePathGuard as GatewayPathGuard  # noqa: E402
from mellyn.egress_proxy import generate_squid_config  # noqa: E402
from mellyn.gateway_config import SERVER_NAME, load_gateway_config  # noqa: E402
from mellyn.init_cmd import (  # noqa: E402
    InitError,
    init_workspace,
    parse_dotenv,
    render_starter_policy,
    resolve_stack_config,
    run_up,
)
from mellyn.legacy_env import LEGACY_ENV_PREFIX, LegacyConfigError  # noqa: E402
from mellyn.policy import validate_argv  # noqa: E402

from mcp_airlock.egress.guards import EgressValidator as AirlockEgressValidator  # noqa: E402
from mcp_airlock.egress.guards import WorkspacePathGuard as AirlockPathGuard  # noqa: E402


class TestSmbPresets(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmpdir.name)
        (self.workspace / "notes.md").write_text("hello\n", encoding="utf-8")
        (self.workspace / ".env").write_text("TOP_SECRET=placeholder\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_smb_presets_align_with_capability_presets_and_argv_rules(self) -> None:
        self.assertEqual(set(SMB_SERVER_PRESETS), set(MCP_CAPABILITY_PRESETS))
        for name, profile in SMB_SERVER_PRESETS.items():
            with self.subTest(preset=name):
                self.assertEqual(profile.preset_name, name)
                self.assertIsNotNone(SERVER_NAME.fullmatch(profile.default_server_name))
                self.assertLessEqual(set(profile.default_tool_risk_tiers), set(MCP_CAPABILITY_PRESETS[name]))
                ok, reason = validate_argv({"argv": list(profile.example_command)})
                self.assertTrue(ok, f"Preset '{name}' example_command rejected: {reason}")

    def test_multi_preset_policy_enforces_untrusted_taint_and_jail_boundaries(self) -> None:
        policy_toml = render_starter_policy(tuple(SMB_SERVER_PRESETS))
        policy_file = self.workspace / "starter-policy.toml"
        policy_file.write_text(policy_toml, encoding="utf-8")
        policy = load_policy_file(policy_file)

        with Authorizer(workspace_root=self.workspace, policy_config=policy) as auth:
            sid = auth.create_session()

            # Read tool from untrusted SaaS presets is LOW (allowed) and automatically taints the session
            for server, tool in (
                ("github", "get_issue"),
                ("linear", "list_issues"),
                ("slack", "list_channels"),
                ("postgres", "list_tables"),
            ):
                with self.subTest(server=server, tool=tool):
                    local_sid = auth.create_session()
                    res = auth.authorize(ToolCallRequest(local_sid, tool, {}, mcp_server=server))
                    self.assertEqual(res.decision, Decision.ALLOW)
                    self.assertTrue(auth.is_tainted(local_sid))

            # Untrusted read taints shared session -> filesystem write & mutating SaaS tools require approval
            auth.authorize(ToolCallRequest(sid, "get_issue", {"issue_number": 1}, mcp_server="github"))
            self.assertTrue(auth.is_tainted(sid))

            fs_write = auth.authorize(
                ToolCallRequest(
                    sid,
                    "write_file",
                    {"path": "notes.md", "content": "updated"},
                    mcp_server="local-workspace",
                )
            )
            self.assertEqual(fs_write.decision, Decision.REQUIRE_APPROVAL)

            for server, mutating_tool, args in (
                ("github", "push_files", {"branch": "main"}),
                ("github", "merge_pull_request", {"pullNumber": 42}),
                ("slack", "post_message", {"channel": "C1", "text": "hi"}),
                ("postgres", "drop_table", {"table": "users"}),
            ):
                mut = auth.authorize(ToolCallRequest(sid, mutating_tool, args, mcp_server=server))
                self.assertEqual(mut.decision, Decision.REQUIRE_APPROVAL)

            # On real Postgres MCP servers every statement, DROP and COPY ... TO PROGRAM included, goes through
            # `query`. Once the session is tainted, injected instructions must not be able to run SQL unattended.
            for sql in ("SELECT email FROM customers", "DROP TABLE customers", "COPY t TO PROGRAM 'id'"):
                with self.subTest(sql=sql):
                    q = auth.authorize(ToolCallRequest(sid, "query", {"sql": sql}, mcp_server="postgres"))
                    self.assertEqual(q.decision, Decision.REQUIRE_APPROVAL)
            clean_sid = auth.create_session()
            clean = auth.authorize(ToolCallRequest(clean_sid, "query", {"sql": "SELECT 1"}, mcp_server="postgres"))
            self.assertEqual(clean.decision, Decision.ALLOW)

            # Filesystem preset keeps workspace secret & guardrail denials hard-blocked
            secret_read = auth.authorize(
                ToolCallRequest(sid, "read_file", {"path": ".env"}, mcp_server="local-workspace")
            )
            self.assertEqual(secret_read.decision, Decision.DENY)
            guardrail_write = auth.authorize(
                ToolCallRequest(sid, "write_file", {"path": ".github/workflows/ci.yml"}, mcp_server="local-workspace")
            )
            self.assertEqual(guardrail_write.decision, Decision.DENY)


class TestMellynInitAndUp(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_init_writes_digests_only_valid_configs_and_team_squid_conf(self) -> None:
        out_dir = self.root / "deploy_cfg"
        ws = self.root / "agent_ws"
        ws.mkdir()

        res = init_workspace(
            out_dir,
            presets=("mcp-filesystem", "github", "linear"),
            team=True,
            workspace_root=ws,
            extra_domains=("custom.example.com",),
        )
        self.assertTrue(res.env_path.is_file())
        self.assertTrue(res.policy_path.is_file())
        self.assertTrue(res.gateway_path.is_file())
        self.assertIsNotNone(res.squid_path)
        self.assertTrue(res.squid_path is not None and res.squid_path.is_file())

        env_raw = res.env_path.read_text(encoding="utf-8")
        for raw_key in (
            res.credentials.agent_key,
            res.credentials.approver_key,
        ):
            self.assertNotIn(raw_key, env_raw)
        self.assertNotIn("MELLYN_VIEWER_KEY_DIGEST", env_raw)

        parsed = parse_dotenv(res.env_path)
        self.assertEqual(parsed["MELLYN_ENV"], "production")
        self.assertEqual(parsed["MELLYN_WORKSPACE"], str(ws.resolve()))
        self.assertNotIn("MELLYN_VIEWER_KEY_DIGEST", parsed)

        creds = CredentialConfig.from_env(parsed, roles=frozenset({Role.AGENT, Role.APPROVER}))
        self.assertTrue(creds.verify(res.credentials.agent_key, Role.AGENT))
        self.assertTrue(creds.verify(res.credentials.approver_key, Role.APPROVER))
        self.assertFalse(creds.verify(res.credentials.agent_key, Role.APPROVER))

        policy = load_policy_file(res.policy_path)
        self.assertEqual(policy.allowed_mcp_servers, frozenset({"local-workspace", "github", "linear"}))
        self.assertEqual(policy.trusted_mcp_servers, frozenset({"local-workspace"}))
        self.assertEqual(
            policy.allowed_egress_domains,
            frozenset({"api.github.com", "api.linear.app", "custom.example.com"}),
        )

        gw = load_gateway_config(res.gateway_path)
        self.assertEqual([s.name for s in gw.servers], ["local-workspace", "github", "linear"])

        if res.squid_path is None:
            self.fail("Expected team init_workspace to generate squid.conf")
        self.assertEqual(res.squid_path.read_text(encoding="utf-8"), generate_squid_config(policy))

        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(res.env_path.stat().st_mode), 0o600)

    def test_init_refuses_overwrite_without_force_and_rejects_bad_inputs(self) -> None:
        out_dir = self.root / "cfg"
        first = init_workspace(out_dir, presets=("mcp-filesystem",))
        sentinel = first.env_path.read_text(encoding="utf-8")

        with self.assertRaises(InitError):
            init_workspace(out_dir, presets=("github",), force=False)
        self.assertEqual(first.env_path.read_text(encoding="utf-8"), sentinel)

        second = init_workspace(out_dir, presets=("github",), force=True)
        self.assertNotEqual(second.env_path.read_text(encoding="utf-8"), sentinel)

        for bad_presets, bad_domains in (
            ((), ()),
            (("nonexistent-preset",), ()),
            (("mcp-filesystem",), ("169.254.169.254",)),
            (("mcp-filesystem",), ("localhost",)),
        ):
            with self.subTest(bad_presets=bad_presets, bad_domains=bad_domains), self.assertRaises(InitError):
                render_starter_policy(bad_presets, extra_domains=bad_domains)

    def test_init_and_up_refuse_symlink_targets(self) -> None:
        link_dir = self.root / "sym_cfg"
        link_dir.mkdir()
        target = self.root / "real_target.txt"
        link_env = link_dir / ".env"
        try:
            os.symlink(target, link_env)
        except OSError as exc:
            self.skipTest(f"OS environment does not allow symlink creation: {exc}")

        with self.assertRaises(InitError):
            init_workspace(link_dir, force=True)

    def test_run_up_dry_run_writes_nothing_and_fails_closed_on_bad_env(self) -> None:
        out_dir = self.root / "stack"
        init_res = init_workspace(out_dir, presets=("mcp-filesystem", "github"), team=True)
        compose = self.root / "docker-compose.yml"
        compose.write_text("services: {}\n", encoding="utf-8")
        squid_out = self.root / "egress" / "squid.conf"

        with mock.patch.dict("os.environ", {}, clear=True):
            rc, argv = run_up(
                policy_path=init_res.policy_path,
                compose_file=compose,
                squid_output=squid_out,
                env_file=init_res.env_path,
                profiles=("relay",),
                dry_run=True,
            )
            self.assertEqual(rc, 0)
            self.assertEqual(
                argv,
                [
                    "docker",
                    "compose",
                    "--env-file",
                    str(init_res.env_path.resolve()),
                    "-f",
                    str(compose),
                    "--profile",
                    "relay",
                    "up",
                    "-d",
                    "--build",
                ],
            )
            # A dry run checks everything but writes nothing, including squid.conf.
            self.assertFalse(squid_out.exists())

            # Missing .env fails closed
            with self.assertRaises(InitError):
                run_up(
                    policy_path=init_res.policy_path,
                    compose_file=compose,
                    squid_output=squid_out,
                    env_file=self.root / "missing.env",
                    dry_run=True,
                )

            # Placeholder .env fails closed
            placeholder_env = self.root / "placeholder.env"
            placeholder_env.write_text(
                "MELLYN_API_KEY_PEPPER=replace\nMELLYN_AGENT_KEY_DIGEST=replace\nMELLYN_APPROVER_KEY_DIGEST=replace\n",
                encoding="utf-8",
            )
            with self.assertRaises(CredentialConfigError):
                run_up(
                    policy_path=init_res.policy_path,
                    compose_file=compose,
                    squid_output=squid_out,
                    env_file=placeholder_env,
                    dry_run=True,
                )

            # Legacy prefix in env fails closed
            legacy_env = self.root / "legacy.env"
            legacy_env.write_text(f"{LEGACY_ENV_PREFIX}PEPPER=old\n", encoding="utf-8")
            with self.assertRaises(LegacyConfigError):
                run_up(
                    policy_path=init_res.policy_path,
                    compose_file=compose,
                    squid_output=squid_out,
                    env_file=legacy_env,
                    dry_run=True,
                )


class TestUnifiedCli(unittest.TestCase):
    def test_cli_version_presets_init_up_sync_and_passthrough_help(self) -> None:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = mellyn_cli_main(["version"])
        self.assertEqual(rc, 0)
        self.assertIn(MELLYN_VERSION, out.getvalue())

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = mellyn_cli_main(["presets"])
        self.assertEqual(rc, 0)
        for preset in SMB_SERVER_PRESETS:
            self.assertIn(preset, out.getvalue())

        with tempfile.TemporaryDirectory() as tmp:
            cfg_dir = Path(tmp) / "work"
            compose = Path(tmp) / "docker-compose.yml"
            compose.write_text("services: {}\n", encoding="utf-8")
            squid_out = Path(tmp) / "squid.conf"

            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc_init = mellyn_cli_main(["init", "--dir", str(cfg_dir), "--preset", "github", "--quiet-keys"])
            self.assertEqual(rc_init, 0)
            self.assertNotIn("MELLYN_AGENT_KEY    =", out.getvalue())

            with mock.patch.dict("os.environ", {}, clear=True), contextlib.redirect_stdout(io.StringIO()):
                rc_up = mellyn_cli_main(
                    [
                        "up",
                        "--policy",
                        str(cfg_dir / "config" / "mellyn-policy.toml"),
                        "--compose",
                        str(compose),
                        "--squid-output",
                        str(squid_out),
                        "--env-file",
                        str(cfg_dir / ".env"),
                        "--dry-run",
                    ]
                )
            self.assertEqual(rc_up, 0)

            sync_out = Path(tmp) / "synced.conf"
            with contextlib.redirect_stdout(io.StringIO()):
                rc_sync = mellyn_cli_main(
                    [
                        "sync-egress",
                        "--policy",
                        str(cfg_dir / "config" / "mellyn-policy.toml"),
                        "--output",
                        str(sync_out),
                    ]
                )
            self.assertEqual(rc_sync, 0)
            self.assertTrue(sync_out.is_file())

        for subcmd in ("proxy", "verify", "pin", "bench"):
            with self.subTest(subcmd=subcmd), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(mellyn_cli_main([subcmd, "--help"]), 0)

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(mellyn_cli_main(["nonexistent-subcommand"]), 2)
        self.assertIn("Unknown mellyn subcommand", err.getvalue())

    def test_optional_airlock_commands_fail_cleanly_when_package_absent(self) -> None:
        with mock.patch("mellyn.cli.importlib.import_module", side_effect=ModuleNotFoundError("mcp_airlock")):
            for subcmd in ("airlock", "pin", "verify", "bench"):
                err = io.StringIO()
                with self.subTest(subcmd=subcmd), contextlib.redirect_stderr(err):
                    self.assertEqual(mellyn_cli_main([subcmd, "--help"]), 2)
                self.assertIn("mcp_airlock", err.getvalue())


class TestGuardParity(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmpdir.name)
        (self.workspace / "src").mkdir()
        (self.workspace / "src" / "main.py").write_text("x = 1\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_gateway_and_airlock_path_and_egress_guards_agree(self) -> None:
        gw_path = GatewayPathGuard(self.workspace)
        al_path = AirlockPathGuard(self.workspace)

        path_cases = (
            ("src/main.py", False, True),
            ("src/main.py", True, True),
            ("../escape.txt", False, False),
            (".env", False, False),
            (".env.", False, False),
            (".env.local", False, False),
            (".env.example", False, True),
            (".ssh/id_rsa", False, False),
            ("secrets/key.json", False, False),
            (".github/workflows/ci.yml", True, False),
            ("CLAUDE.md", True, False),
            (".agent/rules/x.md", True, False),
            ("src/main.py:ads_stream", False, False),
            ("src/ads:stream/file.txt", True, False),
            ("src/new.py.", True, False),
            ("src/new.py ", True, False),
            ("", False, False),
            ("bad\x00path", False, False),
        )
        for raw, is_write, expected_ok in path_cases:
            with self.subTest(path=raw, is_write=is_write):
                ok_gw, reason_gw = gw_path.validate_path(raw, is_write=is_write)
                ok_al, reason_al = al_path.validate_path(raw, is_write=is_write)
                self.assertEqual(ok_gw, expected_ok, reason_gw)
                self.assertEqual(ok_al, expected_ok, reason_al)

        gw_egress = GatewayEgressValidator(frozenset({"api.github.com"}))
        al_egress = AirlockEgressValidator(frozenset({"api.github.com"}))
        url_cases = (
            ("https://api.github.com/repos", True),
            ("https://sub.api.github.com/v1", True),
            ("http://api.github.com/repos", False),
            ("https://169.254.169.254/latest", False),
            ("https://localhost/healthz", False),
            ("https://evil.example/data", False),
            ("https://user:pw@api.github.com/repos", False),
            ("https://api.github.com/ok\r\nHost: evil", False),
        )
        for url, expected_ok in url_cases:
            with self.subTest(url=url):
                self.assertEqual(gw_egress.validate_url(url)[0], expected_ok)
                self.assertEqual(al_egress.validate_url(url)[0], expected_ok)


if __name__ == "__main__":
    unittest.main()


class TestInitUpWiring(unittest.TestCase):
    """`mellyn up` must run the containers on what `mellyn init` generated, with .env kept out of their reach."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self._tmpdir.name)
        self.compose = self.root / "deploy" / "docker-compose.yml"
        self.compose.parent.mkdir()
        self.compose.write_text("services: {}\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_init_points_compose_at_generated_config_and_keeps_env_out_of_it(self) -> None:
        res = init_workspace(self.root / "site", presets=("github",), workspace_root=self.root)
        env = parse_dotenv(res.env_path)
        config_dir = res.policy_path.parent

        self.assertEqual(res.gateway_path.parent, config_dir)
        self.assertNotEqual(res.env_path.parent.resolve(), config_dir.resolve())
        self.assertFalse((config_dir / ".env").exists())
        self.assertEqual(
            resolve_stack_config(self.compose, env),
            (config_dir.resolve(), res.policy_path.resolve(), res.gateway_path.resolve()),
        )

    def test_without_init_variables_compose_falls_back_to_the_examples(self) -> None:
        config_dir, policy, gateway = resolve_stack_config(self.compose, {})
        self.assertEqual(config_dir, (self.root / "config").resolve())
        self.assertEqual(policy.name, "mellyn-policy.example.toml")
        self.assertEqual(gateway.name, "mellyn-gateway.example.toml")
        for bad in ("../secrets.toml", "sub/policy.toml", "..", " "):
            with self.subTest(policy_file=bad), self.assertRaises(InitError):
                resolve_stack_config(self.compose, {"MELLYN_POLICY_FILE": bad})

    def test_up_uses_the_generated_policy_and_refuses_a_different_one(self) -> None:
        res = init_workspace(self.root / "site", presets=("github",), workspace_root=self.root)
        squid_out = self.root / "squid.conf"
        with mock.patch.dict("os.environ", {}, clear=True):
            # No --policy: the containers' policy is found from .env.
            rc, _ = run_up(compose_file=self.compose, squid_output=squid_out, env_file=res.env_path, dry_run=True)
            self.assertEqual(rc, 0)

            other = self.root / "other-policy.toml"
            other.write_text(res.policy_path.read_text(encoding="utf-8"), encoding="utf-8")
            with self.assertRaises(InitError):
                run_up(
                    compose_file=self.compose,
                    squid_output=squid_out,
                    policy_path=other,
                    env_file=res.env_path,
                    dry_run=True,
                )

            # An env file inside the mounted config folder would be readable in the containers.
            exposed_env = res.policy_path.parent / "exposed.env"
            exposed_env.write_text(res.env_path.read_text(encoding="utf-8"), encoding="utf-8")
            with self.assertRaises(InitError):
                run_up(compose_file=self.compose, squid_output=squid_out, env_file=exposed_env, dry_run=True)

    def test_up_passes_env_file_to_compose_and_containers(self) -> None:
        res = init_workspace(self.root / "site", presets=("github",), workspace_root=self.root)
        squid_out = self.root / "squid.conf"
        completed = mock.Mock(returncode=0)
        with (
            mock.patch.dict("os.environ", {}, clear=True),
            mock.patch("mellyn.init_cmd.shutil.which", return_value="docker"),
            mock.patch("mellyn.init_cmd.subprocess.run", return_value=completed) as run,
        ):
            rc, argv = run_up(compose_file=self.compose, squid_output=squid_out, env_file=res.env_path)
        self.assertEqual(rc, 0)
        self.assertEqual(argv[:4], ["docker", "compose", "--env-file", str(res.env_path.resolve())])
        self.assertEqual(run.call_args.kwargs["env"]["MELLYN_ENV_FILE"], str(res.env_path.resolve()))
        self.assertEqual(
            squid_out.read_text(encoding="utf-8"), generate_squid_config(load_policy_file(res.policy_path))
        )

    def test_compose_reads_config_location_and_env_file_from_variables(self) -> None:
        compose = (REPO_ROOT / "deploy" / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertEqual(compose.count("- ${MELLYN_CONFIG_DIR:-../config}:/etc/mellyn:ro"), 2)
        self.assertEqual(compose.count("- ${MELLYN_ENV_FILE:-../.env}"), 2)
        self.assertIn("MELLYN_POLICY_PATH: /etc/mellyn/${MELLYN_POLICY_FILE:-mellyn-policy.example.toml}", compose)
        self.assertIn("- /etc/mellyn/${MELLYN_GATEWAY_CONFIG_FILE:-mellyn-gateway.example.toml}", compose)
        self.assertNotIn("- ../config:/etc/mellyn", compose)
        self.assertNotIn("      - ../.env\n", compose.replace("\r\n", "\n"))
