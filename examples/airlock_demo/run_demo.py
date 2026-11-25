"""
Runnable 5-minute end-to-end Mellyn Airlock + Forensic Flight Recorder walkthrough.

Executes a real `mellyn-airlock` stdio proxy session over `examples/airlock_demo/sample_mcp_server.py`
using `examples/airlock_demo/reviewed_policy.toml`:
  1. Verifies pinned `tools/list` AgBOM SHA-256 digests.
  2. Executes one ALLOWED tool call (`read_status_note`).
  3. Blocks one disallowed tool call (`export_diagnostics`) with JSON-RPC `-32000`.
  4. Verifies the hash-chained `audit.jsonl` ledger with `mellyn-ir` (`reconstruct_incident`)
     and prints the reconstructed incident timeline (`render_markdown`) to stdout.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEMO_DIR = Path(__file__).resolve().parent
REPO_ROOT = DEMO_DIR.parents[1]
SRC_DIR = REPO_ROOT / "src"
BACKEND_DIR = REPO_ROOT / "backend"

for _import_dir in (SRC_DIR, BACKEND_DIR):
    if str(_import_dir) not in sys.path:
        sys.path.insert(0, str(_import_dir))

from mellyn.legacy_env import check_no_legacy_env  # noqa: E402

from mcp_airlock.ir_lab.reconstruct import IncidentReport, reconstruct_incident, render_markdown  # noqa: E402

POLICY_PATH = DEMO_DIR / "reviewed_policy.toml"
SERVER_PATH = DEMO_DIR / "sample_mcp_server.py"
DEMO_SESSION_ID = "demo-session-01"


@dataclass(frozen=True)
class DemoResult:
    """Artifacts and structured JSON-RPC outcomes from one demo session."""

    output_dir: Path
    audit_path: Path
    report_path: Path
    policy_path: Path
    proxy_exit_code: int
    initialize_response: dict[str, Any]
    tools_list_response: dict[str, Any]
    allowed_call_response: dict[str, Any]
    blocked_call_response: dict[str, Any]
    incident_report: IncidentReport


def _send_and_read_response(
    proc: subprocess.Popen[str],
    payload: dict[str, Any],
    *,
    expect_reply: bool = True,
) -> dict[str, Any] | None:
    if proc.stdin is None or proc.stdout is None:
        raise RuntimeError("Proxy stdin/stdout pipes are unavailable.")
    proc.stdin.write(json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n")
    proc.stdin.flush()
    if not expect_reply:
        return None

    expected_id = payload["id"]
    while True:
        line = proc.stdout.readline()
        if not line:
            stderr_tail = proc.stderr.read() if proc.stderr is not None else ""
            raise RuntimeError(f"Airlock proxy closed stdout while awaiting id={expected_id!r}. stderr={stderr_tail!r}")
        stripped = line.strip()
        if not stripped:
            continue
        frame = json.loads(stripped)
        if not isinstance(frame, dict):
            raise RuntimeError(f"Unexpected non-object frame from proxy: {frame!r}")
        if frame.get("id") == expected_id:
            return frame


def run_demo_session(
    output_dir: Path,
    *,
    python_executable: str = sys.executable,
) -> DemoResult:
    """
    Spawn `mellyn-airlock` fronting `sample_mcp_server.py`, run one allowed call and one
    blocked call, and return the `mellyn-ir` verified incident report plus artifact paths.
    """
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    audit_path = output_dir / "audit.jsonl"
    report_path = output_dir / "incident_report.json"
    # Remove any pre-existing ledger in a reused output directory so seq=0 starts cleanly.
    audit_path.unlink(missing_ok=True)

    proxy_env = os.environ.copy()
    existing_py_path = proxy_env.get("PYTHONPATH", "").strip()
    proxy_env["PYTHONPATH"] = f"{SRC_DIR}{os.pathsep}{existing_py_path}" if existing_py_path else str(SRC_DIR)

    cmd = [
        python_executable,
        "-m",
        "mcp_airlock.airlock.proxy",
        "--policy",
        str(POLICY_PATH),
        "--audit-log",
        str(audit_path),
        "--session-id",
        DEMO_SESSION_ID,
        "--",
        python_executable,
        str(SERVER_PATH),
    ]
    with subprocess.Popen(  # noqa: S603 - fixed local demo python subprocess
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        env=proxy_env,
    ) as proc:
        try:
            init_resp = _send_and_read_response(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "mellyn-demo-client", "version": "1.0.0"},
                    },
                },
            )
            _send_and_read_response(
                proc,
                {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                expect_reply=False,
            )
            list_resp = _send_and_read_response(
                proc,
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            )
            allowed_resp = _send_and_read_response(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "read_status_note",
                        "arguments": {"note_id": "release-readiness"},
                    },
                },
            )
            blocked_resp = _send_and_read_response(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "export_diagnostics",
                        "arguments": {"destination": "https://example.invalid/drop"},
                    },
                },
            )
            if proc.stdin is not None:
                proc.stdin.close()
            exit_code = proc.wait(timeout=15)
            if proc.stderr is not None:
                proc.stderr.read()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)

    if init_resp is None or list_resp is None or allowed_resp is None or blocked_resp is None:
        raise RuntimeError("Demo session failed to collect all expected JSON-RPC responses.")
    if exit_code != 0:
        raise RuntimeError(f"mellyn-airlock exited unexpectedly with code {exit_code}.")

    report = reconstruct_incident(audit_path)
    report_path.write_text(
        json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    return DemoResult(
        output_dir=output_dir,
        audit_path=audit_path,
        report_path=report_path,
        policy_path=POLICY_PATH,
        proxy_exit_code=exit_code,
        initialize_response=init_resp,
        tools_list_response=list_resp,
        allowed_call_response=allowed_resp,
        blocked_call_response=blocked_resp,
        incident_report=report,
    )


def _extract_note_text(response: dict[str, Any]) -> str:
    result = response.get("result")
    if not isinstance(result, dict):
        return json.dumps(response, ensure_ascii=False)
    content = result.get("content")
    if isinstance(content, list) and content and isinstance(content[0], dict):
        return str(content[0].get("text", ""))
    return json.dumps(result, ensure_ascii=False)


def _print_walkthrough(result: DemoResult) -> None:
    report = result.incident_report
    error_obj = result.blocked_call_response.get("error", {})
    print("=== Mellyn Airlock 5-Minute Walkthrough ===")
    print(f"Policy : {result.policy_path}")
    print(f"Server : {SERVER_PATH}")
    print(f"Ledger : {result.audit_path}")
    print()
    print("[1/3] AgBOM Tool Manifest Pin Verification (tools/list)")
    tools = result.tools_list_response.get("result", {}).get("tools", [])
    print(f"  Verified {len(tools)} pinned tool(s) against manifest_sha256 before any tool call ran.")
    print()
    print("[2/3] Policy Enforcement (1 Allowed Call + 1 Blocked Call)")
    print("  ALLOW -> read_status_note(note_id='release-readiness')")
    print(f"           Result: {_extract_note_text(result.allowed_call_response)}")
    print("  BLOCK -> export_diagnostics(destination='https://example.invalid/drop')")
    print(f"           JSON-RPC {error_obj.get('code')}: {error_obj.get('message')}")
    print()
    print("[3/3] Cryptographic Hash-Chain Verification (mellyn-ir)")
    print(f"  Chain Valid  : {report.chain_valid}")
    print(f"  Report Status: {report.status}")
    print(f"  Entries      : {report.total_events} (tail seq={report.verification.last_seq})")
    print(f"  Tail Hash    : {report.verification.last_hash}")
    print(f"  Saved Report : {result.report_path}")
    print()
    print("=== Reconstructed Incident Timeline (mellyn-ir) ===")
    print(render_markdown(report))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the 5-minute Mellyn Airlock demo and print the verified mellyn-ir timeline.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory for generated audit.jsonl and incident_report.json (default: fresh temp dir).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    check_no_legacy_env()
    args = _build_parser().parse_args(argv)
    output_dir = args.output_dir if args.output_dir is not None else Path(tempfile.mkdtemp(prefix="mellyn-demo-"))

    result = run_demo_session(output_dir)
    _print_walkthrough(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
