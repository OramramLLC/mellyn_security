#!/usr/bin/env python3
"""
End-to-end empirical container & network-egress verification harness for Mellyn Security.

Proves in CI (on real Docker Engine + Linux namespaces) that:
  1. Both container images (`Dockerfile` and `deploy/egress/Dockerfile`) build cleanly from their
     SHA-256 digest-pinned base images and `--require-hashes` Python lockfile.
  2. `mellyn-authorizer` refuses to start when `MELLYN_REQUIRE_WORKSPACE_MOUNT=1` and `/workspace`
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

from mellyn.credentials import key_digest  # noqa: E402
from mellyn.egress_proxy import generate_squid_config  # noqa: E402
from mellyn.policy_loader import load_policy_file  # noqa: E402

AUTH_IMAGE = "mellyn-security:ci-verify"
EGRESS_IMAGE = "mellyn-egress:ci-verify"
INTERNAL_SUBNET = "172.30.252.0/24"
INTERNAL_NET = "mellyn-ci-internal"
EXT_NET = "mellyn-ci-egress"
SQUID_CONTAINER = "mellyn-ci-squid"
AUTH_CONTAINER = "mellyn-ci-authorizer"
OUTSIDE_TARGET_CONTAINER = "mellyn-ci-outside-target"
GW_AUDIT_VOLUME = "mellyn-ci-gw-audit"

ROUTING_DENIAL_ERRNOS: frozenset[str] = frozenset({"ENETUNREACH", "EHOSTUNREACH"})
_PROBE_REQUIRED_KEYS: frozenset[str] = frozenset({"phase", "status", "http_status", "errno_name", "exc_type"})


_AUDIT_ISOLATION_FIXTURE = """
import json, os, sys
from pathlib import Path

def denied(fn):
    try:
        fn()
    except PermissionError:
        return True
    except OSError:
        return True
    return False

for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method")
    if "id" not in msg:
        continue
    if method == "initialize":
        res = {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "probe", "version": "1"},
        }
    elif method == "tools/call":
        tmp_probe = Path("/tmp/probe-sentinel")
        tmp_probe.write_text("forged", encoding="utf-8")
        report = {
            "uid": os.geteuid(),
            "gid": os.getegid(),
            "cwd": os.getcwd(),
            "marker": Path("marker.txt").read_text(encoding="utf-8").strip(),
            "list_dir_denied": denied(lambda: os.listdir("/var/log/mellyn")),
            "write_audit_denied": denied(
                lambda: Path("/var/log/mellyn/gateway-audit.jsonl").open("a", encoding="utf-8").close()
            ),
            "write_sentinel_denied": denied(
                lambda: Path("/var/log/mellyn/sentinel.txt").write_text("tampered", encoding="utf-8")
            ),
            "unlink_sentinel_denied": denied(lambda: os.unlink("/var/log/mellyn/sentinel.txt")),
            "replace_sentinel_denied": denied(
                lambda: os.replace(tmp_probe, "/var/log/mellyn/sentinel.txt")
            ),
            # The point of the separate user: the gateway's environment holds the pepper and approver digest.
            "read_gateway_environ_denied": denied(lambda: open(f"/proc/{os.getppid()}/environ", "rb").read()),
            "read_gateway_mem_denied": denied(lambda: open(f"/proc/{os.getppid()}/mem", "rb").read(1)),
            "parent_is_gateway": b"mellyn.mcp_gateway" in open(f"/proc/{os.getppid()}/cmdline", "rb").read(),
            # The gateway cannot signal this process after its drop; only PID 1's exit ending the namespace stops it.
            "gateway_is_pid1": os.getppid() == 1,
        }
        res = {"content": [{"type": "text", "text": json.dumps(report)}]}
    else:
        res = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": res}) + "\\n")
    sys.stdout.flush()
"""


def run_cmd(argv: list[str], *, check: bool = True, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, input=input_text, text=True, capture_output=True, check=check)  # noqa: S603


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


_OUTSIDE_LISTENER_SCRIPT = """
import http.server

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_GET(self):
        body = b"OUTSIDE_TARGET_OK\\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

http.server.HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
"""

_DIRECT_PROBE_SCRIPT = """
import errno, json, socket, ssl, sys, urllib.error, urllib.request

def emit(**fields):
    print("PROBE_JSON " + json.dumps(fields, sort_keys=True))

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
    with opener.open(sys.argv[1], timeout=float(sys.argv[2])) as resp:
        emit(phase="http", status="allowed", http_status=resp.status, errno_name=None, exc_type=None)
except urllib.error.HTTPError as exc:
    emit(phase="http", status="http_error", http_status=exc.code, errno_name=None, exc_type="HTTPError")
except ssl.SSLError as exc:
    emit(phase="tls", status="error", http_status=None, errno_name=None, exc_type=type(exc).__name__)
except socket.gaierror as exc:
    ename = errno.errorcode.get(exc.errno) if isinstance(exc.errno, int) else None
    emit(phase="dns", status="error", http_status=None, errno_name=ename, exc_type="gaierror")
except urllib.error.URLError as exc:
    reason = exc.reason
    if isinstance(reason, ssl.SSLError):
        emit(phase="tls", status="error", http_status=None, errno_name=None, exc_type=type(reason).__name__)
    elif isinstance(reason, socket.gaierror):
        ename = errno.errorcode.get(reason.errno) if isinstance(reason.errno, int) else None
        emit(phase="dns", status="error", http_status=None, errno_name=ename, exc_type="gaierror")
    elif isinstance(reason, TimeoutError):
        emit(phase="connect", status="error", http_status=None, errno_name="ETIMEDOUT", exc_type=type(reason).__name__)
    elif isinstance(reason, OSError):
        ename = errno.errorcode.get(reason.errno) if isinstance(reason.errno, int) else None
        emit(phase="connect", status="error", http_status=None, errno_name=ename, exc_type=type(reason).__name__)
    else:
        emit(phase="unknown", status="error", http_status=None, errno_name=None, exc_type=type(reason).__name__)
except TimeoutError as exc:
    emit(phase="connect", status="error", http_status=None, errno_name="ETIMEDOUT", exc_type=type(exc).__name__)
except OSError as exc:
    ename = errno.errorcode.get(exc.errno) if isinstance(exc.errno, int) else None
    emit(phase="connect", status="error", http_status=None, errno_name=ename, exc_type=type(exc).__name__)
"""

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


def parse_probe_json(stdout: str, returncode: int) -> dict[str, object] | None:
    """Parse structured `PROBE_JSON {...}` output from `_DIRECT_PROBE_SCRIPT`; `None` if missing or malformed."""
    if returncode != 0:
        return None
    marker_lines = [line[len("PROBE_JSON ") :] for line in stdout.splitlines() if line.startswith("PROBE_JSON ")]
    if len(marker_lines) != 1:
        return None
    try:
        parsed = json.loads(marker_lines[0])
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict) or not (_PROBE_REQUIRED_KEYS <= parsed.keys()):
        return None
    return parsed


def classify_direct_egress_probe(stdout: str, returncode: int) -> tuple[bool, str]:
    """
    Validate that a direct-egress probe from the internal network failed specifically due to kernel
    network/host routing denial (`ENETUNREACH` or `EHOSTUNREACH`), rejecting missing, malformed, DNS,
    TLS, HTTP, or non-routing socket outcomes.
    """
    if returncode != 0:
        return False, f"probe container failed to execute cleanly (exit {returncode})"
    payload = parse_probe_json(stdout, returncode)
    if payload is None:
        return False, "probe output was missing or malformed JSON"

    phase = payload.get("phase")
    status = payload.get("status")
    errno_name = payload.get("errno_name")
    exc_type = payload.get("exc_type")
    http_status = payload.get("http_status")

    if status == "allowed" or phase == "http":
        return False, f"direct egress reached HTTP layer (status={http_status})"
    if phase == "dns":
        return False, f"probe failed during DNS lookup ({exc_type}/{errno_name}), not routing isolation"
    if phase == "tls":
        return False, f"probe reached TLS handshake ({exc_type}), indicating TCP route leaked"
    if phase == "connect" and status == "error" and isinstance(errno_name, str) and errno_name in ROUTING_DENIAL_ERRNOS:
        return True, f"kernel routing denial confirmed ({errno_name})"
    return (
        False,
        f"unexpected connection outcome (phase={phase!r}, status={status!r}, errno={errno_name!r}, exc={exc_type!r})",
    )


def run_direct_probe(url: str, *, network: str, timeout: float = 4.0) -> subprocess.CompletedProcess[str]:
    """Run `_DIRECT_PROBE_SCRIPT` with proxies disabled from `network` against `url`."""
    return run_cmd(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            network,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "-e",
            "HTTPS_PROXY=",
            "-e",
            "HTTP_PROXY=",
            "--entrypoint",
            "python",
            AUTH_IMAGE,
            "-c",
            _DIRECT_PROBE_SCRIPT,
            url,
            str(timeout),
        ],
        check=False,
    )


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
    for name in (AUTH_CONTAINER, SQUID_CONTAINER, OUTSIDE_TARGET_CONTAINER):
        run_cmd(["docker", "rm", "-f", name], check=False)
    for net in (INTERNAL_NET, EXT_NET):
        run_cmd(["docker", "network", "rm", net], check=False)
    run_cmd(["docker", "volume", "rm", "-f", GW_AUDIT_VOLUME], check=False)


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
                    f"MELLYN_API_KEY_PEPPER={pepper}",
                    "-e",
                    f"MELLYN_AGENT_KEY_DIGEST={key_digest(agent_key, pepper)}",
                    "-e",
                    f"MELLYN_APPROVER_KEY_DIGEST={key_digest(approver_key, pepper)}",
                    AUTH_IMAGE,
                ]
            )
            wait_for_healthz("http://127.0.0.1:18000/healthz")

            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            req_ok = urllib.request.Request(
                "http://127.0.0.1:18000/v1/sessions",
                method="POST",
                headers={"X-Mellyn-API-Key": agent_key},
            )
            with opener.open(req_ok, timeout=5) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                if resp.status != 201 or not str(body.get("session_id", "")).startswith("ses_"):
                    raise RuntimeError(f"Agent key did not create a session: {resp.status} {body}")

            req_forbidden = urllib.request.Request(
                "http://127.0.0.1:18000/v1/sessions",
                method="POST",
                headers={"X-Mellyn-API-Key": approver_key},
            )
            try:
                opener.open(req_forbidden, timeout=5)
                raise RuntimeError("Approver key unexpectedly allowed on /v1/sessions!")
            except urllib.error.HTTPError as exc:
                if exc.code != 403:
                    raise RuntimeError(f"Expected 403 for approver key on /v1/sessions, got {exc.code}") from exc

            print("[3b/5] Verifying downstream MCP UID isolation from /var/log/mellyn and workspace cwd...")
            marker_file = ws_dir / "marker.txt"
            marker_file.write_text("WORKSPACE_MARKER\n", encoding="utf-8")
            os.chmod(marker_file, 0o644)

            cfg_dir = tmp_dir / "gw-cfg"
            cfg_dir.mkdir()
            fixture_py = cfg_dir / "fixture_mcp.py"
            fixture_py.write_text(_AUDIT_ISOLATION_FIXTURE, encoding="utf-8", newline="\n")
            gw_policy = cfg_dir / "policy.toml"
            gw_policy.write_text(
                'schema_version = 1\nallowed_mcp_servers = ["probe"]\ntrusted_mcp_servers = ["probe"]\n'
                '[tool_risk_tiers]\n"probe/inspect_access" = "low"\n'
                '[tool_capabilities."probe/inspect_access"]\npure = true\n',
                encoding="utf-8",
                newline="\n",
            )
            gw_toml = cfg_dir / "gateway.toml"
            gw_toml.write_text(
                'schema_version = 1\npolicy = "policy.toml"\n'
                '[[servers]]\nname = "probe"\ncommand = ["python", "/etc/mellyn/fixture_mcp.py"]\n',
                encoding="utf-8",
                newline="\n",
            )
            for f in (fixture_py, gw_policy, gw_toml):
                os.chmod(f, 0o644)

            run_cmd(["docker", "volume", "create", GW_AUDIT_VOLUME])
            run_cmd(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--user",
                    "10001:10001",
                    "-v",
                    f"{GW_AUDIT_VOLUME}:/var/log/mellyn",
                    "--entrypoint",
                    "python",
                    AUTH_IMAGE,
                    "-c",
                    "from pathlib import Path; Path('/var/log/mellyn/sentinel.txt').write_text('sentinel-intact\\n')",
                ]
            )
            gw_input = "".join(
                json.dumps(m) + "\n"
                for m in (
                    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "probe__inspect_access"}},
                    {"jsonrpc": "2.0", "id": 3, "method": "ping"},
                )
            )
            gw_run = run_cmd(
                [
                    "docker",
                    "run",
                    "--rm",
                    "-i",
                    "--read-only",
                    "--tmpfs",
                    "/tmp:noexec,nosuid,size=32m,mode=1777",  # noqa: S108
                    "--user",
                    "0:0",
                    "--cap-drop",
                    "ALL",
                    "--cap-add",
                    "SETUID",
                    "--cap-add",
                    "SETGID",
                    "--security-opt",
                    "no-new-privileges:true",
                    "-v",
                    f"{ws_dir}:/workspace:ro",
                    "-v",
                    f"{cfg_dir}:/etc/mellyn:ro",
                    "-v",
                    f"{GW_AUDIT_VOLUME}:/var/log/mellyn",
                    "--entrypoint",
                    "python",
                    AUTH_IMAGE,
                    "-m",
                    "mellyn.mcp_gateway",
                    "--config",
                    "/etc/mellyn/gateway.toml",
                    "--workspace",
                    "/workspace",
                    "--audit-log",
                    "/var/log/mellyn/gateway-audit.jsonl",
                    "--gateway-user",
                    "mellyn",
                    "--downstream-user",
                    "mellyn-mcp",
                ],
                input_text=gw_input,
                check=False,
            )
            if gw_run.returncode != 0:
                raise RuntimeError(f"Isolated gateway run failed ({gw_run.returncode}): {gw_run.stderr}")
            gw_replies = {r["id"]: r for r in map(json.loads, gw_run.stdout.splitlines()) if "id" in r}
            probe_report = json.loads(gw_replies[2]["result"]["content"][0]["text"])
            if probe_report["uid"] != 10002 or probe_report["gid"] != 10002:
                raise RuntimeError(f"Expected downstream UID/GID 10002, got: {probe_report}")
            if probe_report["cwd"] != "/workspace" or probe_report["marker"] != "WORKSPACE_MARKER":
                raise RuntimeError(f"Expected downstream cwd /workspace and WORKSPACE_MARKER, got: {probe_report}")
            for check_key in (
                "list_dir_denied",
                "write_audit_denied",
                "write_sentinel_denied",
                "unlink_sentinel_denied",
                "replace_sentinel_denied",
                "read_gateway_environ_denied",
                "read_gateway_mem_denied",
                "parent_is_gateway",
                "gateway_is_pid1",
            ):
                if not probe_report.get(check_key):
                    raise RuntimeError(f"Downstream process was not blocked on {check_key}: {probe_report}")

            audit_verify = run_cmd(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--user",
                    "10001:10001",
                    "-v",
                    f"{GW_AUDIT_VOLUME}:/var/log/mellyn:ro",
                    "--entrypoint",
                    "python",
                    AUTH_IMAGE,
                    "-c",
                    (
                        "import json; from pathlib import Path; "
                        "print(json.dumps({"
                        "'sentinel': Path('/var/log/mellyn/sentinel.txt').read_text(), "
                        "'audit': Path('/var/log/mellyn/gateway-audit.jsonl').read_text().splitlines()"
                        "}))"
                    ),
                ]
            )
            verified_data = json.loads(audit_verify.stdout)
            if verified_data["sentinel"] != "sentinel-intact\n":
                raise RuntimeError(f"Audit sentinel was modified: {verified_data['sentinel']!r}")
            if len(verified_data["audit"]) != 1 or json.loads(verified_data["audit"][0])["decision"] != "allow":
                raise RuntimeError(f"Expected 1 appended allow audit event, got: {verified_data['audit']}")

            print("[4/5] Starting isolated internal network, outside target listener, and Squid egress proxy...")
            run_cmd(["docker", "network", "create", "--internal", "--subnet", INTERNAL_SUBNET, INTERNAL_NET])
            run_cmd(["docker", "network", "create", EXT_NET])
            run_cmd(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    OUTSIDE_TARGET_CONTAINER,
                    "--network",
                    EXT_NET,
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges:true",
                    "--entrypoint",
                    "python",
                    AUTH_IMAGE,
                    "-c",
                    _OUTSIDE_LISTENER_SCRIPT,
                ]
            )
            outside_ip = run_cmd(
                [
                    "docker",
                    "inspect",
                    "-f",
                    "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                    OUTSIDE_TARGET_CONTAINER,
                ]
            ).stdout.strip()
            if not outside_ip:
                raise RuntimeError("Could not determine IPv4 address of controlled outside listener container.")
            outside_url = f"http://{outside_ip}:8080/healthz"

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
            # 1a. Positive control: confirm the controlled outside listener is live on EXT_NET.
            ext_probe = run_direct_probe(outside_url, network=EXT_NET, timeout=4.0)
            ext_parsed = parse_probe_json(ext_probe.stdout, ext_probe.returncode)
            if not ext_parsed or ext_parsed.get("status") != "allowed" or ext_parsed.get("http_status") != 200:
                raise RuntimeError(
                    f"Controlled outside target {outside_url} was not reachable on {EXT_NET}: "
                    f"rc={ext_probe.returncode} stdout={ext_probe.stdout!r} stderr={ext_probe.stderr!r}"
                )

            # 1b. Isolation check: from INTERNAL_NET without Squid, kernel routing must reject direct egress.
            direct_probe = run_direct_probe(outside_url, network=INTERNAL_NET, timeout=4.0)
            isolated_ok, isolated_reason = classify_direct_egress_probe(direct_probe.stdout, direct_probe.returncode)
            if not isolated_ok:
                raise RuntimeError(
                    f"Direct egress check from {INTERNAL_NET} to {outside_url} failed ({isolated_reason}): "
                    f"stdout={direct_probe.stdout!r} stderr={direct_probe.stderr!r}"
                )

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
