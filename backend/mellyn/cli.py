"""Unified `mellyn` CLI dispatching turn-key workspace setup, gateway runtime, and Airlock tools."""

from __future__ import annotations

import argparse
import importlib
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from mellyn.credentials import CredentialConfigError
from mellyn.init_cmd import InitError, init_workspace, run_up
from mellyn.legacy_env import LegacyConfigError
from mellyn.policy import SMB_SERVER_PRESETS
from mellyn.policy_loader import PolicyLoadError

MELLYN_VERSION = "1.0.0"

_PASSTHROUGH_MODULES: dict[str, tuple[str, str | None]] = {
    "proxy": ("mellyn.mcp_gateway", None),
    "approve": ("mellyn.approve", None),
    "viewer": ("mellyn.viewer_server", None),
    "sync-egress": ("mellyn.egress_proxy", None),
    "airlock": (
        "mcp_airlock.airlock.proxy",
        "The `airlock` command requires the `mcp_airlock` package (not installed in gateway-only containers).",
    ),
    "pin": (
        "mcp_airlock.airlock.pin_cli",
        "The `pin` command requires the `mcp_airlock` package (not installed in gateway-only containers).",
    ),
    "verify": (
        "mcp_airlock.ir_lab.reconstruct",
        "The `verify` command requires the `mcp_airlock` package (not installed in gateway-only containers).",
    ),
    "bench": (
        "mcp_airlock.egress.bench",
        "The `bench` command requires the `mcp_airlock` package (not installed in gateway-only containers).",
    ),
}

_HELP_TEXT = """\
usage: mellyn <command> [args...]

Mellyn Security — Turn-Key MCP Security & Airlock CLI

Setup & Control Plane:
  init         Generate starter .env (digests only), mellyn-policy.toml & mellyn-gateway.toml
  presets      List curated SMB MCP server presets (filesystem, fetch, github, linear, slack, postgres)
  up           Validate .env + the containers' policy, sync squid.conf from it, and run docker compose up
  proxy        Run the multi-server MCP stdio security gateway
  approve      List, approve, or reject held gateway calls (Role.APPROVER)
  viewer       Launch the Plane 4 Posture, Audit & Approvals console backend
  sync-egress  Regenerate deploy/egress/squid.conf from a policy TOML/JSON file
  version      Print the Mellyn Security version

Containment & Forensics (Airlock):
  airlock      Run the fail-closed stdio Airlock proxy with AAD kill switch
  pin          Inspect & pin a downstream MCP server's AgBOM tools/list manifest
  verify       Verify audit.jsonl cryptographic hash chain & reconstruct timeline
  bench        Run the obfuscated canary & secret scanner benchmark
"""


def _run_main(fn: Callable[[list[str]], int | None], rest: list[str]) -> int:
    try:
        result = fn(rest)
    except SystemExit as exc:
        if isinstance(exc.code, int):
            return exc.code
        return 0 if exc.code is None else 1
    return 0 if result is None else int(result)


def _dispatch_module(module_name: str, rest: list[str], *, optional_hint: str | None = None) -> int:
    try:
        mod = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if optional_hint is not None:
            print(f"{optional_hint} ({exc})", file=sys.stderr)
            return 2
        raise
    fn = mod.main
    return _run_main(fn, rest)


def _cmd_init(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="mellyn init",
        description="Scaffold .env (digests only), mellyn-policy.toml, mellyn-gateway.toml, and optional squid.conf.",
    )
    parser.add_argument("--dir", type=Path, default=Path("."), help="Target directory (default: current directory)")
    parser.add_argument(
        "--preset",
        action="append",
        dest="presets",
        help="Curated server preset to include (repeatable; default: mcp-filesystem)",
    )
    parser.add_argument(
        "--domain",
        action="append",
        dest="domains",
        default=[],
        help="Additional outbound HTTPS domain to allowlist (repeatable)",
    )
    parser.add_argument("--workspace", type=Path, default=None, help="Workspace path to record as MELLYN_WORKSPACE")
    parser.add_argument(
        "--team",
        action="store_true",
        help="Generate production .env settings and write squid.conf alongside configs",
    )
    parser.add_argument("--squid-output", type=Path, default=None, help="Explicit output path for squid.conf")
    parser.add_argument("--force", action="store_true", help="Overwrite existing generated files")
    parser.add_argument(
        "--quiet-keys",
        action="store_true",
        help="Do not print the newly generated raw role API keys to stdout",
    )
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0

    presets = tuple(args.presets) if args.presets else ("mcp-filesystem",)
    try:
        res = init_workspace(
            args.dir,
            presets=presets,
            team=args.team,
            workspace_root=args.workspace,
            extra_domains=args.domains,
            force=args.force,
            squid_output=args.squid_output,
        )
    except (InitError, PolicyLoadError, CredentialConfigError, ValueError, OSError) as exc:
        print(f"mellyn init failed: {exc}", file=sys.stderr)
        return 2

    print(f"Initialized Mellyn workspace in {res.env_path.parent} (presets: {', '.join(res.presets)}):")
    print(f"  env:     {res.env_path} (pepper + digests only; no raw role keys stored)")
    print(f"  policy:  {res.policy_path} (folder mounted read-only into the containers; .env stays outside it)")
    print(f"  gateway: {res.gateway_path}")
    if res.squid_path is not None:
        print(f"  squid:   {res.squid_path}")

    if not args.quiet_keys:
        print("\nOne-time API keys (store safely; only their HMAC-SHA256 digests were saved in .env):")
        print(f"  MELLYN_AGENT_KEY    = {res.credentials.agent_key}")
        print(f"  MELLYN_APPROVER_KEY = {res.credentials.approver_key}")
        print(f"  MELLYN_VIEWER_KEY   = {res.credentials.viewer_key}")

    print("\nNext steps (replace the placeholder server commands in the gateway config first):")
    print(f"  Local:      mellyn proxy --config {res.gateway_path} --workspace . --audit-log mellyn-audit.jsonl")
    print(f"  Containers: mellyn up --env-file {res.env_path}   (uses the generated policy and gateway config)")
    return 0


def _cmd_presets(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="mellyn presets", description="List curated SMB MCP server presets.")
    try:
        parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0

    print("Curated SMB MCP Server Presets:")
    for name in sorted(SMB_SERVER_PRESETS):
        prof = SMB_SERVER_PRESETS[name]
        domains = ", ".join(prof.egress_domains) if prof.egress_domains else "(none)"
        trust = "trusted" if prof.trusted else "untrusted (auto-taints session)"
        tool_count = len(prof.default_tool_risk_tiers)
        print(f"  - {prof.preset_name:<15} [{trust}] tools={tool_count:<2} domains={domains}")
        print(f"    {prof.description}")
    return 0


def _cmd_up(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="mellyn up",
        description="Validate .env + policy, regenerate squid.conf, and launch Docker Compose.",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=None,
        help=(
            "Optional check: refuse to start unless this is the policy the containers will load. By default the "
            "policy comes from MELLYN_CONFIG_DIR/MELLYN_POLICY_FILE in --env-file (set by `mellyn init`), "
            "falling back to config/mellyn-policy.example.toml"
        ),
    )
    parser.add_argument(
        "--compose",
        type=Path,
        default=Path("deploy/docker-compose.yml"),
        help="Docker Compose file (default: deploy/docker-compose.yml)",
    )
    parser.add_argument(
        "--squid-output",
        type=Path,
        default=Path("deploy/egress/squid.conf"),
        help="Target squid.conf path (default: deploy/egress/squid.conf)",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        default=Path(".env"),
        help="Environment file containing pepper & digests (default: .env)",
    )
    parser.add_argument("--no-env-check", action="store_true", help="Skip reading/validating --env-file")
    parser.add_argument(
        "--profile",
        action="append",
        dest="profiles",
        default=[],
        help="Compose profile to enable (repeatable, e.g. --profile viewer)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate everything and print the docker compose command, without writing squid.conf or starting it",
    )
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0

    try:
        rc, cmd = run_up(
            policy_path=args.policy,
            compose_file=args.compose,
            squid_output=args.squid_output,
            env_file=None if args.no_env_check else args.env_file,
            profiles=args.profiles,
            dry_run=args.dry_run,
        )
    except (InitError, PolicyLoadError, CredentialConfigError, LegacyConfigError, ValueError, OSError) as exc:
        print(f"mellyn up pre-flight failed (fail-closed): {exc}", file=sys.stderr)
        return 2

    if args.dry_run:
        print(f"Dry run: checks passed; nothing was written. A real run regenerates {args.squid_output} and runs:")
        print("  " + " ".join(cmd))
    return int(rc)


def main(argv: Sequence[str] | None = None) -> int:
    """Entrypoint for the unified `mellyn` CLI."""
    raw = sys.argv[1:] if argv is None else list(argv)
    if not raw or raw[0] in ("-h", "--help", "help"):
        sys.stdout.write(_HELP_TEXT)
        return 0

    cmd, rest = raw[0], raw[1:]
    if cmd == "version" or cmd == "--version":
        print(f"mellyn-security {MELLYN_VERSION}")
        return 0
    if cmd == "init":
        return _cmd_init(rest)
    if cmd == "presets":
        return _cmd_presets(rest)
    if cmd == "up":
        return _cmd_up(rest)
    if cmd in _PASSTHROUGH_MODULES:
        mod_name, hint = _PASSTHROUGH_MODULES[cmd]
        return _dispatch_module(mod_name, rest, optional_hint=hint)

    print(f"Unknown mellyn subcommand '{cmd}'. Run `mellyn --help` for usage.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
