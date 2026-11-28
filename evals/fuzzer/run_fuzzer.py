"""
`mcp-fuzzer` (`mcp-server-fuzzer`) integration and deterministic protocol smoke harness for Mellyn Airlock.

Usage:
  python -m evals.fuzzer.run_fuzzer --mode smoke --output-dir outputs/fuzzer
  python -m evals.fuzzer.run_fuzzer --mode mcp-fuzzer --output-dir outputs/fuzzer
"""

from __future__ import annotations

import argparse
import base64
import json
import queue
import shlex
import shutil
import subprocess  # noqa: S404 - invokes pinned local Python proxy or installed mcp-fuzzer binary cleanly
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from evals.fuzzer.target_mcp_server import SERVER_INSTRUCTIONS, TOOL_DEFINITIONS
from mellyn.airlock.engine import compute_instructions_pin, compute_manifest_pin, compute_tool_pin
from mellyn.airlock.models import ToolDefinition, parse_airlock_policy_toml
from mellyn.ir_lab.reconstruct import reconstruct_incident
from mellyn.ir_lab.verify_chain import verify_chain

TARGET_SERVER_PATH = Path(__file__).resolve().with_name("target_mcp_server.py")
DEFAULT_CANARY_TOKEN = "MELLYN_EVAL_FUZZER_" + "CANARY_948271"
DEFAULT_DECOY_VALUE = "mellyn_decoy_placeholder_" + "0001"
DECOY_ENV_LINE = f"DECOY_DB_TOKEN={DEFAULT_DECOY_VALUE}"


@dataclass(frozen=True)
class AuditPostcheckResult:
    """Forensic and zero-leak verification summary for one Airlock ledger."""

    ledger_path: str
    chain_valid: bool
    entry_count: int
    incident_status: str
    raw_canary_found_in_ledger: bool
    raw_decoy_found_in_ledger: bool


@dataclass(frozen=True)
class FuzzCaseOutcome:
    """Outcome of a single smoke-fuzzer probe against `mellyn.airlock.proxy`."""

    case_id: str
    expected_allow: bool
    actual_allow: bool
    expected_reason: str | None
    passed: bool
    response_summary: str
    postcheck: AuditPostcheckResult


def _toml_str(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def build_fuzzer_policy_toml(
    workspace: Path,
    *,
    canary_token: str = DEFAULT_CANARY_TOKEN,
    policy_id: str = "eval-fuzzer-policy",
) -> str:
    """Render and validate a strict AgBOM + egress Airlock TOML policy for the mock fuzzer target."""
    tools = [ToolDefinition.model_validate(item) for item in TOOL_DEFINITIONS]
    manifest_pin = compute_manifest_pin(tools)
    instr_pin = compute_instructions_pin(SERVER_INSTRUCTIONS)
    tool_pins = {tool.name: compute_tool_pin(tool) for tool in tools}
    ws_resolved = str(workspace.resolve())

    lines: list[str] = [
        f"policy_id = {_toml_str(policy_id)}",
        'allowed_tools = ["read_note", "echo_status"]',
        "max_payload_bytes = 32768",
        f"workspace_roots = [{_toml_str(ws_resolved)}]",
        f"manifest_sha256 = {_toml_str(manifest_pin)}",
        f"instructions_sha256 = {_toml_str(instr_pin)}",
        f"canary_tokens = [{_toml_str(canary_token)}]",
        "",
        "[agbom_pins]",
    ]
    for name, digest in tool_pins.items():
        lines.append(f"{name} = {_toml_str(digest)}")

    lines.extend(
        [
            "",
            "[tool_rules.read_note]",
            'name = "read_note"',
            "allowed = true",
            'allowed_arg_names = ["path"]',
            'path_arg_names = ["path"]',
            f"allowed_path_roots = [{_toml_str(ws_resolved)}]",
            "block_guardrail_paths = true",
            "",
            "[tool_rules.echo_status]",
            'name = "echo_status"',
            "allowed = true",
            'allowed_arg_names = ["message"]',
            "block_guardrail_paths = true",
            "",
            "[tool_rules.write_note]",
            'name = "write_note"',
            "allowed = false",
            'allowed_arg_names = ["path", "content"]',
            'path_arg_names = ["path"]',
            f"allowed_path_roots = [{_toml_str(ws_resolved)}]",
            "block_guardrail_paths = true",
        ]
    )
    rendered = "\n".join(lines) + "\n"
    parse_airlock_policy_toml(rendered)
    return rendered


def prepare_fuzzer_workspace(
    root: Path,
    *,
    canary_token: str = DEFAULT_CANARY_TOKEN,
) -> tuple[Path, Path]:
    """Create the sandbox workspace with benign note, canary file, decoy `.env`, and policy TOML."""
    workspace = root / "workspace"
    notes_dir = workspace / "notes"
    notes_dir.mkdir(parents=True, exist_ok=True)
    (notes_dir / "welcome.txt").write_text("Welcome to the Mellyn fuzzer workspace.\n", encoding="utf-8")
    (notes_dir / "canary.txt").write_text(f"SENSITIVE_CANARY={canary_token}\n", encoding="utf-8")
    (workspace / ".env").write_text(DECOY_ENV_LINE + "\n", encoding="utf-8")

    policy_path = root / "airlock_policy.toml"
    policy_path.write_text(build_fuzzer_policy_toml(workspace, canary_token=canary_token), encoding="utf-8")
    return workspace, policy_path


def audit_postcheck(
    ledger_path: Path,
    *,
    canary_token: str = DEFAULT_CANARY_TOKEN,
    decoy_value: str = DEFAULT_DECOY_VALUE,
) -> AuditPostcheckResult:
    """Verify hash-chain integrity, reconstruct forensic incident state, and assert zero raw leaks on disk."""
    chain = verify_chain(ledger_path)
    incident = reconstruct_incident(ledger_path)
    raw_text = ledger_path.read_text(encoding="utf-8", errors="replace") if ledger_path.is_file() else ""
    return AuditPostcheckResult(
        ledger_path=str(ledger_path),
        chain_valid=chain.valid,
        entry_count=chain.entry_count,
        incident_status=incident.status,
        raw_canary_found_in_ledger=canary_token in raw_text,
        raw_decoy_found_in_ledger=decoy_value in raw_text,
    )


def _frame_request_id(raw: str) -> int | str | None:
    """Return the JSON-RPC id a frame expects a reply to, or None for notifications and unparsable frames."""
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, dict) and "method" in parsed and isinstance(parsed.get("id"), (int, str)):
        return parsed["id"]
    return None


def _send_and_read(
    proc: subprocess.Popen[str],
    frames: list[str],
    expected_ids: set[int | str],
    timeout_seconds: float = 20.0,
) -> dict[int | str, dict[str, Any]]:
    """Send frames one at a time, waiting for each request's reply before sending the next.

    Airlock refuses `tools/call` until it has seen the server's `tools/list` reply, so writing every frame up front
    races the handshake: a benign call can be refused as `tool_not_verified`, and an attack call can be "blocked"
    for that reason instead of by the rule under test.
    """
    if proc.stdin is None or proc.stdout is None:
        raise RuntimeError("Proxy subprocess stdio pipes are unavailable.")
    lines: queue.Queue[str | None] = queue.Queue()

    def _pump(stream: Any) -> None:
        for line in stream:
            lines.put(line)
        lines.put(None)

    threading.Thread(target=_pump, args=(proc.stdout,), daemon=True).start()

    replies: dict[int | str, dict[str, Any]] = {}
    eof = False

    def _await_reply(request_id: int | str) -> None:
        nonlocal eof
        deadline = time.monotonic() + timeout_seconds
        while not eof:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"No reply to JSON-RPC id {request_id!r} within {timeout_seconds}s.")
            try:
                line = lines.get(timeout=remaining)
            except queue.Empty:
                continue
            if line is None:
                eof = True
                return
            stripped = line.strip()
            if not stripped:
                continue
            parsed = json.loads(stripped)
            if not isinstance(parsed, dict) or "id" not in parsed:
                continue
            rid = parsed["id"]
            if rid in expected_ids or rid is None:
                replies[rid] = parsed
            # A null-id reply is a parse error for the frame just sent.
            if rid == request_id or rid is None:
                return

    for raw in frames:
        if eof:
            break
        try:
            proc.stdin.write(raw + "\n")
            proc.stdin.flush()
        except OSError:
            break
        request_id = _frame_request_id(raw)
        if request_id is not None:
            _await_reply(request_id)
    try:
        proc.stdin.close()
    except OSError:
        pass
    proc.wait(timeout=timeout_seconds)
    return replies


def _run_proxy_sequence(
    *,
    policy_path: Path,
    audit_log_path: Path,
    workspace: Path,
    session_id: str,
    raw_frames: list[str],
    target_id: int | str | None,
) -> tuple[dict[int | str | None, dict[str, Any]], int]:
    cmd = [
        sys.executable,
        "-m",
        "mellyn.airlock.proxy",
        "--policy",
        str(policy_path),
        "--audit-log",
        str(audit_log_path),
        "--session-id",
        session_id,
        "--",
        sys.executable,
        str(TARGET_SERVER_PATH),
        "--workspace",
        str(workspace),
    ]
    proc = subprocess.Popen(  # noqa: S603 - hardcoded Python module + resolved local paths
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    expected: set[int | str] = {1, 2}
    if target_id is not None:
        expected.add(target_id)
    try:
        replies = _send_and_read(proc, raw_frames, expected_ids=expected)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                stream.close()
    return replies, int(proc.returncode or 0)


def _handshake_frames() -> list[str]:
    return [
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "mellyn-fuzzer-smoke", "version": "1.0.0"},
                },
            },
            separators=(",", ":"),
        ),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}, separators=(",", ":")),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, separators=(",", ":")),
    ]


def run_smoke_suite(output_dir: Path) -> dict[str, Any]:
    """Run deterministic adversarial & benign stdio fuzz cases against `mellyn.airlock.proxy`."""
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mellyn_fuzz_smoke_") as tmp:
        root = Path(tmp)
        workspace, policy_path = prepare_fuzzer_workspace(root)
        b64_canary = base64.b64encode(DEFAULT_CANARY_TOKEN.encode("utf-8")).decode("ascii")

        # (case id, expected allow, attack frame, reply id, text the refusal must contain)
        cases: list[tuple[str, bool, str, int | str | None, str | None]] = [
            (
                "benign_read_note",
                True,
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {"name": "read_note", "arguments": {"path": "notes/welcome.txt"}},
                    },
                    separators=(",", ":"),
                ),
                3,
                None,
            ),
            (
                "block_env_secret_read",
                False,
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {"name": "read_note", "arguments": {"path": ".env"}},
                    },
                    separators=(",", ":"),
                ),
                3,
                "airlock.path_boundary_violation",
            ),
            (
                "block_path_traversal",
                False,
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {"name": "read_note", "arguments": {"path": "../../etc/passwd"}},
                    },
                    separators=(",", ":"),
                ),
                3,
                "airlock.path_boundary_violation",
            ),
            (
                "block_unallowlisted_write_note",
                False,
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {"name": "write_note", "arguments": {"path": "notes/new.txt", "content": "hi"}},
                    },
                    separators=(",", ":"),
                ),
                3,
                "airlock.tool_not_allowed",
            ),
            (
                "block_duplicate_json_keys",
                False,
                '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo_status","arguments":{"message":"a","message":"b"}}}',
                3,
                "Parse error",
            ),
            (
                "block_invisible_unicode_smuggling",
                False,
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {"name": "echo_status", "arguments": {"message": "ok\U000e0041"}},
                    },
                    separators=(",", ":"),
                    ensure_ascii=False,
                ),
                3,
                "airlock.invisible_unicode_in_arguments",
            ),
            (
                "aad_canary_plain_exfil",
                False,
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {"name": "echo_status", "arguments": {"message": DEFAULT_CANARY_TOKEN}},
                    },
                    separators=(",", ":"),
                ),
                3,
                "AAD_CONTAINMENT_SEVERED",
            ),
            (
                "aad_canary_base64_exfil",
                False,
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {"name": "echo_status", "arguments": {"message": b64_canary}},
                    },
                    separators=(",", ":"),
                ),
                3,
                "AAD_CONTAINMENT_SEVERED",
            ),
        ]

        outcomes: list[FuzzCaseOutcome] = []
        for idx, (case_id, expected_allow, attack_frame, target_id, expected_reason) in enumerate(cases, start=1):
            audit_path = output_dir / f"{case_id}_audit.jsonl"
            audit_path.unlink(missing_ok=True)
            replies, _rc = _run_proxy_sequence(
                policy_path=policy_path,
                audit_log_path=audit_path,
                workspace=workspace,
                session_id=f"fuzz_smoke_{idx:02d}",
                raw_frames=[*_handshake_frames(), attack_frame],
                target_id=target_id,
            )
            reply = replies.get(target_id) or replies.get(None) or {}
            actual_allow = "result" in reply and not reply.get("result", {}).get("isError", False)
            post = audit_postcheck(audit_path)
            summary = "ok" if actual_allow else str(reply.get("error", {}).get("message", "no_reply"))
            # A refusal only counts if the rule under test produced it, not some other check.
            reason_ok = expected_reason is None or expected_reason in summary
            passed = (
                actual_allow == expected_allow
                and reason_ok
                and post.chain_valid
                and not post.raw_canary_found_in_ledger
                and not post.raw_decoy_found_in_ledger
            )
            outcomes.append(
                FuzzCaseOutcome(
                    case_id=case_id,
                    expected_allow=expected_allow,
                    actual_allow=actual_allow,
                    expected_reason=expected_reason,
                    passed=passed,
                    response_summary=summary,
                    postcheck=post,
                )
            )

    summary_payload: dict[str, Any] = {
        "mode": "smoke",
        "total_cases": len(outcomes),
        "passed_cases": sum(1 for item in outcomes if item.passed),
        "all_passed": all(item.passed for item in outcomes),
        "outcomes": [asdict(item) for item in outcomes],
    }
    (output_dir / "fuzzer_summary.json").write_text(
        json.dumps(summary_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary_payload


def run_mcp_fuzzer_cli(output_dir: Path, *, max_runs: int = 25) -> dict[str, Any]:
    """Run external `mcp-fuzzer` CLI against `mellyn.airlock.proxy` over stdio (Colab / eval env)."""
    fuzzer_bin = shutil.which("mcp-fuzzer")
    if fuzzer_bin is None:
        raise RuntimeError("`mcp-fuzzer` executable was not found in PATH. Install with `pip install mcp-fuzzer`.")

    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mellyn_mcp_fuzzer_") as tmp:
        root = Path(tmp)
        workspace, policy_path = prepare_fuzzer_workspace(root)
        audit_path = output_dir / "mcp_fuzzer_audit.jsonl"
        audit_path.unlink(missing_ok=True)
        endpoint_parts = [
            sys.executable,
            "-m",
            "mellyn.airlock.proxy",
            "--policy",
            str(policy_path),
            "--audit-log",
            str(audit_path),
            "--session-id",
            "mcp_fuzzer_live",
            "--",
            sys.executable,
            str(TARGET_SERVER_PATH),
            "--workspace",
            str(workspace),
        ]
        endpoint_cmd = shlex.join(endpoint_parts)
        proc = subprocess.run(  # noqa: S603 - resolved local executable + pinned script paths
            [
                fuzzer_bin,
                "--mode",
                "all",
                "--protocol",
                "stdio",
                "--endpoint",
                endpoint_cmd,
                "--runs",
                str(max_runs),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        post = audit_postcheck(audit_path)
        summary_payload: dict[str, Any] = {
            "mode": "mcp-fuzzer",
            "fuzzer_returncode": proc.returncode,
            "all_passed": post.chain_valid
            and not post.raw_canary_found_in_ledger
            and not post.raw_decoy_found_in_ledger,
            "postcheck": asdict(post),
            "stdout_tail": proc.stdout[-4000:],
            "stderr_tail": proc.stderr[-4000:],
        }
        (output_dir / "fuzzer_summary.json").write_text(
            json.dumps(summary_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return summary_payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run mcp-fuzzer or smoke fuzzing against Mellyn Airlock.")
    parser.add_argument("--mode", choices=["smoke", "mcp-fuzzer"], default="smoke")
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/fuzzer"))
    parser.add_argument("--runs", type=int, default=25, help="Fuzz iterations when running --mode mcp-fuzzer.")
    args = parser.parse_args(argv)

    summary = (
        run_smoke_suite(args.output_dir)
        if args.mode == "smoke"
        else run_mcp_fuzzer_cli(args.output_dir, max_runs=args.runs)
    )
    sys.stdout.write(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
