#!/usr/bin/env python3
"""
End-to-end empirical container & network-egress verification harness for Mellyn Security.

Proves in CI (on real Docker Engine + Linux namespaces) that:
  1. Both container images (`Dockerfile` and `deploy/egress/Dockerfile`) build cleanly from their
     SHA-256 digest-pinned base images and `--require-hashes` Python lockfile.
  2. `mellyn-authorizer` refuses to start when `AEGIS_REQUIRE_WORKSPACE_MOUNT=1` and `/workspace`
     is unmounted, and serves `/healthz` + role-separated `/v1/sessions` when mounted.
  3. On a Docker `internal: true` network (`172.30.252.0/24`):
     - Direct outbound internet access bypassing Squid fails (no route to host/network).
     - Plaintext HTTP (`http://docs.python.org`) via Squid is denied (403).
     - Raw IP literal (`https://169.254.169.254`) via Squid is denied (403).
     - Non-allowlisted domain (`https://example.com`) via Squid is denied (403).
     - Allowlisted domain (`https://docs.python.org`) via Squid CONNECT :443 succeeds (200).
     - An allowlisted name that resolves to a private address (`https://private.docs.python.org`, pinned
       to `127.0.0.1` with a hosts entry) is denied (403) by Squid's post-DNS `blocked_dst` ACL. This is the
       defense DNS rebinding runs into; it does not exercise an answer that changes between lookups.
  Every "denied" check requires Squid's own 403, so a proxy that is down or misconfigured fails the run
  instead of passing it.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from aegis_ai.credentials import key_digest  # noqa: E402
from aegis_ai.egress_proxy import generate_squid_config  # noqa: E402
from aegis_ai.policy_loader import load_policy_file  # noqa: E402

AUTH_IMAGE = "mellyn-security:ci-verify"
EGRESS_IMAGE = "mellyn-egress:ci-verify"
INTERNAL_SUBNET = "172.30.252.0/24"
INTERNAL_NET = "mellyn-ci-internal"
EXT_NET = "mellyn-ci-egress"
SQUID_CONTAINER = "mellyn-ci-squid"
AUTH_CONTAINER = "mellyn-ci-authorizer"


def run_cmd(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, text=True, capture_output=True, check=check)  # noqa: S603


def wait_for_healthz(url: str, timeout: float = 25.0) -> None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + timeout
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with opener.open(url, timeout=2) as resp:
                if resp.status == 200:
                    return
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            time.sleep(0.5)
    raise RuntimeError(f"Timed out waiting for {url}: {last_err}")


_FETCH_REPORT = """
import sys, urllib.error, urllib.request
try:
    urllib.request.urlopen(sys.argv[1], timeout=float(sys.argv[2]))
    print("OUTCOME ALLOWED")
except urllib.error.HTTPError as exc:
    print(f"OUTCOME HTTP {exc.code}")
except urllib.error.URLError as exc:
    print(f"OUTCOME URLERROR {exc.reason}")
except OSError as exc:
    print(f"OUTCOME OSERROR {type(exc).__name__}")
"""


def fetch_outcome(url: str, *, use_proxy: bool, timeout: float = 8.0) -> str:
    """Fetch `url` from a container on the internal network and report what happened ('ALLOWED', 'HTTP 403')."""
    env_args = (
        ["-e", f"HTTPS_PROXY=http://{SQUID_CONTAINER}:3128", "-e", f"HTTP_PROXY=http://{SQUID_CONTAINER}:3128"]
        if use_proxy
        else ["-e", "HTTPS_PROXY=", "-e", "HTTP_PROXY="]
    )
    result = run_cmd(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            INTERNAL_NET,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            *env_args,
            "--entrypoint",
            "python",
            AUTH_IMAGE,
            "-c",
            _FETCH_REPORT,
            url,
            str(timeout),
        ],
        check=False,
    )
    for line in result.stdout.splitlines():
        if line.startswith("OUTCOME "):
            return line[len("OUTCOME ") :]
    return f"NO OUTCOME (exit {result.returncode}): {result.stderr.strip()[-300:]}"


def denied_by_squid(outcome: str) -> bool:
    """Squid's own refusal: a 403 on plain HTTP, or 'Tunnel connection failed: 403' on CONNECT."""
    return outcome == "HTTP 403" or ("Tunnel connection failed" in outcome and "403" in outcome)


def cleanup() -> None:
    for name in (AUTH_CONTAINER, SQUID_CONTAINER):
        run_cmd(["docker", "rm", "-f", name], check=False)
    for net in (INTERNAL_NET, EXT_NET):
        run_cmd(["docker", "network", "rm", net], check=False)


def main() -> int:
    cleanup()
    try:
        print("[1/5] Building digest- and hash-pinned container images...")
        run_cmd(["docker", "build", "-t", AUTH_IMAGE, "-f", str(REPO_ROOT / "Dockerfile"), str(REPO_ROOT)])
        run_cmd(
            [
                "docker",
                "build",
                "-t",
                EGRESS_IMAGE,
                "-f",
                str(REPO_ROOT / "deploy" / "egress" / "Dockerfile"),
                str(REPO_ROOT / "deploy" / "egress"),
            ]
        )

        print("[2/5] Verifying mellyn-authorizer fails closed without a mounted workspace...")
        unmounted = run_cmd(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{REPO_ROOT / 'config' / 'mellyn-policy.example.toml'}:/etc/mellyn/policy.toml:ro",
                AUTH_IMAGE,
            ],
            check=False,
        )
        if unmounted.returncode == 0 or "is not a mount point" not in unmounted.stderr:
            raise RuntimeError(
                "Expected the authorizer to refuse to start because /workspace is not mounted; got exit "
                f"{unmounted.returncode}: {unmounted.stderr.strip()[-400:]}"
            )

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            ws_dir = tmp_dir / "workspace"
            ws_dir.mkdir()
            (ws_dir / "hello.py").write_text("x = 1\n", encoding="utf-8")

            policy = load_policy_file(REPO_ROOT / "config" / "mellyn-policy.example.toml")
            squid_conf = tmp_dir / "squid.conf"
            squid_conf.write_text(
                generate_squid_config(policy, client_cidrs=(INTERNAL_SUBNET,)),
                encoding="utf-8",
                newline="\n",
            )
            os.chmod(squid_conf, 0o644)

            print("[3/5] Verifying mellyn-authorizer healthz and role-separated credentials...")
            pepper = secrets.token_urlsafe(32)
            agent_key = secrets.token_urlsafe(32)
            approver_key = secrets.token_urlsafe(32)

            run_cmd(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    AUTH_CONTAINER,
                    "--read-only",
                    "--tmpfs",
                    "/tmp:noexec,nosuid,size=32m",  # noqa: S108 - a tmpfs mount inside the container
                    "--tmpfs",
                    "/var/log/mellyn:noexec,nosuid,size=32m,uid=10001,gid=10001",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges:true",
                    "-p",
                    "127.0.0.1:18000:8000",
                    "-v",
                    f"{ws_dir}:/workspace:ro",
                    "-v",
                    f"{REPO_ROOT / 'config' / 'mellyn-policy.example.toml'}:/etc/mellyn/policy.toml:ro",
                    "-e",
                    f"AEGIS_API_KEY_PEPPER={pepper}",
                    "-e",
                    f"AEGIS_AGENT_KEY_DIGEST={key_digest(agent_key, pepper)}",
                    "-e",
                    f"AEGIS_APPROVER_KEY_DIGEST={key_digest(approver_key, pepper)}",
                    AUTH_IMAGE,
                ]
            )
            wait_for_healthz("http://127.0.0.1:18000/healthz")

            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            req_ok = urllib.request.Request(
                "http://127.0.0.1:18000/v1/sessions",
                method="POST",
                headers={"X-Aegis-API-Key": agent_key},
            )
            with opener.open(req_ok, timeout=5) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                if resp.status != 201 or not str(body.get("session_id", "")).startswith("ses_"):
                    raise RuntimeError(f"Agent key did not create a session: {resp.status} {body}")

            req_forbidden = urllib.request.Request(
                "http://127.0.0.1:18000/v1/sessions",
                method="POST",
                headers={"X-Aegis-API-Key": approver_key},
            )
            try:
                opener.open(req_forbidden, timeout=5)
                raise RuntimeError("Approver key unexpectedly allowed on /v1/sessions!")
            except urllib.error.HTTPError as exc:
                if exc.code != 403:
                    raise RuntimeError(f"Expected 403 for approver key on /v1/sessions, got {exc.code}") from exc

            print("[4/5] Starting isolated internal network + Squid egress proxy...")
            run_cmd(["docker", "network", "create", "--internal", "--subnet", INTERNAL_SUBNET, INTERNAL_NET])
            run_cmd(["docker", "network", "create", EXT_NET])
            run_cmd(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    SQUID_CONTAINER,
                    "--network",
                    INTERNAL_NET,
                    "--read-only",
                    "--tmpfs",
                    "/tmp:noexec,nosuid,size=32m,uid=13,gid=13",  # noqa: S108 - tmpfs inside the container
                    "--tmpfs",
                    "/var/spool/squid:noexec,nosuid,size=32m,uid=13,gid=13",
                    "--tmpfs",
                    "/var/log/squid:noexec,nosuid,size=32m,uid=13,gid=13",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges:true",
                    # An allowlisted subdomain resolving to loopback (a fixed hosts entry, not rebinding).
                    "--add-host",
                    "private.docs.python.org:127.0.0.1",
                    "-v",
                    f"{squid_conf}:/etc/squid/squid.conf:ro",
                    EGRESS_IMAGE,
                ]
            )
            run_cmd(["docker", "network", "connect", EXT_NET, SQUID_CONTAINER])
            time.sleep(3)

            print("[5/5] Probing internal-network isolation, the allowlist, and private-address blocking...")
            # 1. Without the proxy there is no route out: the request fails before any HTTP exchange.
            direct = fetch_outcome("https://docs.python.org/", use_proxy=False, timeout=4)
            if direct == "ALLOWED" or direct.startswith("HTTP "):
                raise RuntimeError(f"Direct internet connection from the internal network got through: {direct}")

            # 2. Through Squid, each of these must be refused by Squid itself (a 403), not merely fail somehow.
            for url in (
                "http://docs.python.org/",  # plaintext HTTP
                "https://169.254.169.254/latest/meta-data/",  # IP literal / cloud metadata
                "https://example.com/",  # not on the allowlist
                "https://private.docs.python.org/",  # allowlisted name resolving to 127.0.0.1
            ):
                outcome = fetch_outcome(url, use_proxy=True)
                if not denied_by_squid(outcome):
                    raise RuntimeError(f"Expected Squid to refuse {url} with 403, got: {outcome}")

            # 3. An allowlisted HTTPS domain through Squid must succeed.
            allowed = fetch_outcome("https://docs.python.org/3/", use_proxy=True, timeout=15)
            if allowed != "ALLOWED":
                squid_logs = run_cmd(["docker", "logs", SQUID_CONTAINER], check=False).stderr
                raise RuntimeError(
                    f"Allowlisted HTTPS fetch through Squid failed: {allowed}\nSquid logs:\n{squid_logs}"
                )

        print("Container build, workspace mount check, role isolation, and Squid egress checks PASSED.")
        return 0
    finally:
        cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
