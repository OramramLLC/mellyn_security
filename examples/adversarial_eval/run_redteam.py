"""
Adversarial Red-Team Evaluation Harness across all Mellyn Security Planes.

Runs 28 adversarial scenarios across 6 attack families:
  1. Supply Chain & AgBOM Tampering (real AirlockProxy subprocess sessions)
  2. Protocol & Framing Attacks (duplicate JSON keys, spoofed IDs, NaN, oversized frames)
  3. Workspace & Path Confinement (traversal, trailing dot/space, Windows NTFS ADS streams)
  4. Egress & Canary Exfiltration (obfuscated, chunked, escaped, nested, split-field, encoded secrets)
  5. Forensic Ledger Tampering (mid-chain 1-byte tamper, zero canary leakage on disk)
  6. Plane 4 Viewer BFF Security (DNS rebinding Host header, RBAC isolation, traversal, redirect refusal)

This is a regression suite for known techniques, not proof of coverage: see README.md for what it does not test.

Usage:
  python examples/adversarial_eval/run_redteam.py
  python examples/adversarial_eval/run_redteam.py --json
  python examples/adversarial_eval/run_redteam.py --audit-out redteam-audit.jsonl
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import io
import json
import secrets
import shutil
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

EVAL_DIR = Path(__file__).resolve().parent
REPO_ROOT = EVAL_DIR.parents[1]
SRC_DIR = REPO_ROOT / "src"
BACKEND_DIR = REPO_ROOT / "backend"
HOSTILE_SERVER = REPO_ROOT / "tests" / "fixtures" / "hostile_mcp_server.py"

for _path in (SRC_DIR, BACKEND_DIR):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from mellyn.approvals import API_KEY_HEADER, build_approval_opener  # noqa: E402
from mellyn.credentials import CredentialConfig, Role, key_digest  # noqa: E402
from mellyn.egress import WorkspacePathGuard as BackendWorkspacePathGuard  # noqa: E402
from mellyn.viewer_server import ViewerHTTPServer  # noqa: E402

from mcp_airlock.airlock.engine import compute_tool_pin, evaluate_tool_call  # noqa: E402
from mcp_airlock.airlock.models import (  # noqa: E402
    AirlockPolicy,
    JsonRpcRequest,
    ToolDefinition,
    ToolPolicyRule,
    parse_jsonrpc_bytes,
)
from mcp_airlock.airlock.proxy import (  # noqa: E402
    AAD_EXIT_CODE,
    JSONRPC_AAD_CONTAINMENT_SEVERED,
    JSONRPC_POLICY_VIOLATION,
    AirlockProxy,
)
from mcp_airlock.core.audit import AuditLedger  # noqa: E402
from mcp_airlock.core.schemas import ZoneEvent  # noqa: E402
from mcp_airlock.egress.guards import WorkspacePathGuard as AirlockWorkspacePathGuard  # noqa: E402
from mcp_airlock.egress.scanner import scan_payload  # noqa: E402
from mcp_airlock.ir_lab.reconstruct import reconstruct_incident  # noqa: E402

CANARY = "MELLYN_CANARY_ALPHA_9472"
# Documentation-style sample credentials, assembled at runtime so no secret-shaped literal sits in the source.
SAMPLE_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
SAMPLE_AWS_KEY_PCT = SAMPLE_AWS_KEY[:4] + "%49" + SAMPLE_AWS_KEY[5:]
SAMPLE_OPENAI_KEY = "sk-" + "proj-" + "exampleDummy1234567890"

PINNED_TOOLS: tuple[ToolDefinition, ...] = (
    ToolDefinition(
        name="read_file",
        description="Read a text file inside the workspace.",
        inputSchema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    ),
    ToolDefinition(
        name="get_env",
        description="Inspect process environment variables inside the MCP server.",
        inputSchema={"type": "object", "properties": {}},
    ),
)


@dataclass(frozen=True)
class AttackOutcome:
    """Result for a single adversarial red-team scenario."""

    case_id: str
    family: str
    expected: str
    observed: str
    passed: bool


class _QueueClientWriter:
    def __init__(self) -> None:
        self.lines: asyncio.Queue[bytes] = asyncio.Queue()
        self._buf = bytearray()

    def write(self, data: bytes) -> None:
        self._buf.extend(data)
        while b"\n" in self._buf:
            nl = self._buf.index(b"\n")
            line = bytes(self._buf[:nl])
            del self._buf[: nl + 1]
            self.lines.put_nowait(line)

    async def drain(self) -> None:
        await asyncio.sleep(0)


async def _drive_proxy(
    *,
    work_dir: Path,
    mode: str,
    policy: AirlockPolicy,
    requests: list[dict[str, Any] | bytes],
    max_replies: int,
    send_eof_after_first: bool = False,
) -> tuple[int, list[dict[str, Any]], Path]:
    ws = work_dir / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    audit_path = work_dir / "audit.jsonl"
    exec_log = work_dir / "exec.jsonl"
    ledger = AuditLedger(audit_path, canary_tokens=tuple(policy.canary_tokens))
    reader = asyncio.StreamReader()
    writer = _QueueClientWriter()
    err_stream = io.StringIO()
    cmd = [
        sys.executable,
        str(HOSTILE_SERVER),
        "--mode",
        mode,
        "--exec-log",
        str(exec_log),
    ]
    proxy = AirlockProxy(
        command=cmd,
        policy=policy,
        ledger=ledger,
        client_reader=reader,
        client_writer=writer,
        request_timeout_seconds=10.0,
        err_stream=err_stream,
    )
    task = asyncio.create_task(proxy.run())
    replies: list[dict[str, Any]] = []

    def _feed(frame: dict[str, Any] | bytes) -> None:
        raw = frame if isinstance(frame, bytes) else (json.dumps(frame, separators=(",", ":")) + "\n").encode("utf-8")
        reader.feed_data(raw)

    if send_eof_after_first:
        for req in requests:
            _feed(req)
        reader.feed_eof()
    else:
        for idx, req in enumerate(requests):
            _feed(req)
            if idx < max_replies:
                try:
                    raw_line = await asyncio.wait_for(writer.lines.get(), timeout=5.0)
                    replies.append(json.loads(raw_line.decode("utf-8")))
                except TimeoutError:
                    break
        reader.feed_eof()

    exit_code = await asyncio.wait_for(task, timeout=10.0)
    while not writer.lines.empty():
        replies.append(json.loads(writer.lines.get_nowait().decode("utf-8")))
    return exit_code, replies, audit_path


def _default_pin_policy(work_dir: Path, *, max_payload_bytes: int = 8192) -> AirlockPolicy:
    return AirlockPolicy(
        policy_id="redteam-eval",
        allowed_tools=["read_file", "get_env"],
        agbom_pins={tool.name: compute_tool_pin(tool) for tool in PINNED_TOOLS},
        max_payload_bytes=max_payload_bytes,
        workspace_roots=[str((work_dir / "ws").resolve())],
        canary_tokens=[CANARY],
        tool_rules={
            "read_file": ToolPolicyRule(name="read_file", path_arg_names=["path"], allowed_arg_names=["path"]),
            "get_env": ToolPolicyRule(name="get_env", allowed_arg_names=[]),
        },
    )


def _check_agbom_rug_pull(work_dir: Path, *, audit_out: Path | None = None) -> AttackOutcome:
    pol = _default_pin_policy(work_dir)
    exit_code, replies, audit_path = asyncio.run(
        _drive_proxy(
            work_dir=work_dir,
            mode="rug_pull_char",
            policy=pol,
            requests=[
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            ],
            max_replies=2,
        )
    )
    if audit_out is not None and audit_path.is_file():
        audit_out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(audit_path, audit_out)
    report = reconstruct_incident(audit_path)
    has_aad_frame = any(r.get("error", {}).get("code") == JSONRPC_AAD_CONTAINMENT_SEVERED for r in replies)
    passed = exit_code == AAD_EXIT_CODE and report.status == "AAD_CONTAINED" and has_aad_frame
    return AttackOutcome(
        case_id="agbom-rug-pull-description",
        family="1. Supply Chain & AgBOM",
        expected="AAD_FIRE (exit=78, -32099)",
        observed=f"exit={exit_code}, status={report.status}, aad_frame={has_aad_frame}",
        passed=passed,
    )


def _check_agbom_unpinned_tool(work_dir: Path) -> AttackOutcome:
    pol = AirlockPolicy(
        policy_id="redteam-unpinned",
        allowed_tools=["read_file"],
        agbom_pins={"read_file": compute_tool_pin(PINNED_TOOLS[0])},
        workspace_roots=[str((work_dir / "ws").resolve())],
        tool_rules={"read_file": ToolPolicyRule(name="read_file", path_arg_names=["path"], allowed_arg_names=["path"])},
    )
    exit_code, _, audit_path = asyncio.run(
        _drive_proxy(
            work_dir=work_dir,
            mode="benign",
            policy=pol,
            requests=[{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}],
            max_replies=1,
        )
    )
    report = reconstruct_incident(audit_path)
    passed = exit_code == AAD_EXIT_CODE and report.status == "AAD_CONTAINED"
    return AttackOutcome(
        case_id="agbom-unpinned-tool-injection",
        family="1. Supply Chain & AgBOM",
        expected="AAD_FIRE (exit=78, AAD_CONTAINED)",
        observed=f"exit={exit_code}, status={report.status}",
        passed=passed,
    )


def _check_agbom_unicode_tag_smuggling(work_dir: Path) -> AttackOutcome:
    pol = _default_pin_policy(work_dir)
    exit_code, _, audit_path = asyncio.run(
        _drive_proxy(
            work_dir=work_dir,
            mode="rug_pull_tag",
            policy=pol,
            requests=[
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            ],
            max_replies=2,
        )
    )
    report = reconstruct_incident(audit_path)
    passed = exit_code == AAD_EXIT_CODE and report.status == "AAD_CONTAINED"
    return AttackOutcome(
        case_id="agbom-invisible-unicode-tag-smuggling",
        family="1. Supply Chain & AgBOM",
        expected="AAD_FIRE (exit=78, AAD_CONTAINED)",
        observed=f"exit={exit_code}, status={report.status}",
        passed=passed,
    )


def _check_initialize_instructions_stripped(work_dir: Path) -> AttackOutcome:
    pol = _default_pin_policy(work_dir)
    exit_code, replies, audit_path = asyncio.run(
        _drive_proxy(
            work_dir=work_dir,
            mode="instructions",
            policy=pol,
            requests=[
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            ],
            max_replies=2,
        )
    )
    init_res = replies[0].get("result", {}) if len(replies) >= 1 else {}
    list_res = replies[1].get("result", {}) if len(replies) >= 2 else {}
    report = reconstruct_incident(audit_path)
    has_strip_event = any(ev.rule_id == "airlock.instructions_stripped" for s in report.sessions for ev in s.events)
    passed = exit_code == 0 and "instructions" not in init_res and "note" not in list_res and has_strip_event
    return AttackOutcome(
        case_id="initialize-unpinned-instructions-strip",
        family="1. Supply Chain & AgBOM",
        expected="instructions & extra keys stripped",
        observed=f"exit={exit_code}, has_instr={'instructions' in init_res}, strip_event={has_strip_event}",
        passed=passed,
    )


def _check_duplicate_json_keys() -> AttackOutcome:
    payload = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","name":"b"}}'
    rejected = False
    reason = "accepted"
    try:
        parse_jsonrpc_bytes(payload)
    except ValueError as exc:
        rejected = True
        reason = str(exc)
    return AttackOutcome(
        case_id="proto-duplicate-json-keys",
        family="2. Protocol & Framing",
        expected="ValueError on duplicate key",
        observed=reason if rejected else "accepted duplicate keys",
        passed=rejected,
    )


def _check_unsolicited_spoofed_rpc_id(work_dir: Path) -> AttackOutcome:
    pol = _default_pin_policy(work_dir)
    exit_code, _, audit_path = asyncio.run(
        _drive_proxy(
            work_dir=work_dir,
            mode="spoof_id",
            policy=pol,
            requests=[
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "read_file", "arguments": {"path": "ok.txt"}},
                },
            ],
            max_replies=2,
        )
    )
    report = reconstruct_incident(audit_path)
    passed = exit_code == AAD_EXIT_CODE and report.status == "AAD_CONTAINED"
    return AttackOutcome(
        case_id="proto-unsolicited-spoofed-rpc-id",
        family="2. Protocol & Framing",
        expected="AAD_FIRE (exit=78, AAD_CONTAINED)",
        observed=f"exit={exit_code}, status={report.status}",
        passed=passed,
    )


def _check_non_finite_nan() -> AttackOutcome:
    payload = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"x":NaN}}'
    rejected = False
    reason = "accepted"
    try:
        parse_jsonrpc_bytes(payload)
    except ValueError as exc:
        rejected = True
        reason = str(exc)
    return AttackOutcome(
        case_id="proto-non-finite-float-nan",
        family="2. Protocol & Framing",
        expected="ValueError on NaN constant",
        observed=reason if rejected else "accepted NaN",
        passed=rejected,
    )


def _check_oversized_frame_bomb(work_dir: Path) -> AttackOutcome:
    pol = _default_pin_policy(work_dir, max_payload_bytes=512)
    bomb = (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "a" * 1024}},
            }
        ).encode("utf-8")
        + b"\n"
    )
    exit_code, replies, audit_path = asyncio.run(
        _drive_proxy(
            work_dir=work_dir,
            mode="benign",
            policy=pol,
            requests=[
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                bomb,
            ],
            max_replies=2,
        )
    )
    report = reconstruct_incident(audit_path)
    blocked_err = any(r.get("error", {}).get("code") == JSONRPC_POLICY_VIOLATION for r in replies)
    recorded = any(ev.rule_id == "airlock.client_frame_too_large" for s in report.sessions for ev in s.events)
    passed = exit_code == 0 and blocked_err and recorded
    return AttackOutcome(
        case_id="proto-oversized-frame-bomb",
        family="2. Protocol & Framing",
        expected="BLOCK (-32000, frame_too_large)",
        observed=f"exit={exit_code}, err={blocked_err}, logged={recorded}",
        passed=passed,
    )


def _eval_path_across_guards(ws_root: Path, candidate: str) -> tuple[bool, bool, bool]:
    ag = AirlockWorkspacePathGuard(ws_root)
    bg = BackendWorkspacePathGuard(ws_root)
    ag_ok, _ = ag.validate_path(candidate, is_write=False)
    bg_ok, _ = bg.validate_path(candidate, is_write=False)
    pol = AirlockPolicy(
        allowed_tools=["read_file"],
        workspace_roots=[str(ws_root)],
        tool_rules={"read_file": ToolPolicyRule(name="read_file", allowed=True, path_arg_names=["path"])},
    )
    req = JsonRpcRequest(
        jsonrpc="2.0",
        id=1,
        method="tools/call",
        params={"name": "read_file", "arguments": {"path": candidate}},
    )
    verdict = evaluate_tool_call(req, pol)
    return ag_ok, bg_ok, verdict.verdict_allow


def _check_path_case(work_dir: Path, case_id: str, paths: tuple[str, ...]) -> AttackOutcome:
    ws = work_dir / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    results = [(p, *_eval_path_across_guards(ws, p)) for p in paths]
    all_denied = all(not ag_ok and not bg_ok and not eng_ok for _, ag_ok, bg_ok, eng_ok in results)
    detail = "; ".join(f"{p}:ag={ag},bg={bg},eng={eng}" for p, ag, bg, eng in results)
    return AttackOutcome(
        case_id=case_id,
        family="3. Workspace & Paths",
        expected="DENY on airlock/backend/engine",
        observed=detail,
        passed=all_denied,
    )


def _check_egress_plain_and_zwsp() -> AttackOutcome:
    r_plain = scan_payload(f"leak:{CANARY}", canary_tokens=(CANARY,))
    r_zwsp = scan_payload(f"leak:{'\u200b'.join(CANARY)}", canary_tokens=(CANARY,))
    passed = (
        r_plain.canary_matched
        and r_zwsp.canary_matched
        and CANARY not in str(r_plain.redacted_payload)
        and CANARY not in str(r_zwsp.redacted_payload)
    )
    return AttackOutcome(
        case_id="egress-canary-plain-and-zwsp",
        family="4. Egress & Canaries",
        expected="canary_matched=True (AAD_FIRE)",
        observed=f"plain={r_plain.canary_matched}, zwsp={r_zwsp.canary_matched}",
        passed=passed,
    )


def _check_egress_split_list_and_dict() -> AttackOutcome:
    half = len(CANARY) // 2
    list_payload: list[str] = [CANARY[:half], CANARY[half:]]
    dict_payload: dict[str, str] = {"p1": CANARY[:half], "p2": CANARY[half:]}
    r_list = scan_payload(list_payload, canary_tokens=(CANARY,))
    r_dict = scan_payload(dict_payload, canary_tokens=(CANARY,))
    no_leak = CANARY[:half] not in json.dumps(r_list.redacted_payload) and CANARY[:half] not in json.dumps(
        r_dict.redacted_payload
    )
    passed = r_list.canary_matched and r_dict.canary_matched and no_leak
    obs = f"list={r_list.canary_matched} (clean={r_list.clean}), dict={r_dict.canary_matched} (clean={r_dict.clean})"
    return AttackOutcome(
        case_id="egress-canary-split-list-and-dict",
        family="4. Egress & Canaries",
        expected="canary_matched=True (AAD_FIRE)",
        observed=obs,
        passed=passed,
    )


def _check_egress_chunked_base64() -> AttackOutcome:
    b64 = base64.b64encode(CANARY.encode("utf-8")).decode("ascii")
    nl_wrapped = "\n".join(b64[i : i + 8] for i in range(0, len(b64), 8))
    spaced = " ".join(b64[i : i + 8] for i in range(0, len(b64), 8))
    r_nl = scan_payload(nl_wrapped, canary_tokens=(CANARY,))
    r_sp = scan_payload(spaced, canary_tokens=(CANARY,))
    passed = r_nl.canary_matched and r_sp.canary_matched
    return AttackOutcome(
        case_id="egress-canary-chunked-base64",
        family="4. Egress & Canaries",
        expected="canary_matched=True (AAD_FIRE)",
        observed=(
            f"newline_b64={r_nl.canary_matched} (clean={r_nl.clean}), "
            f"spaced_b64={r_sp.canary_matched} (clean={r_sp.clean})"
        ),
        passed=passed,
    )


def _check_egress_percent_encoded_hex_and_b64() -> AttackOutcome:
    hx = CANARY.encode("utf-8").hex()
    b64 = base64.b64encode(CANARY.encode("utf-8")).decode("ascii")
    pct_hex = f"{hx[:4]}%{ord(hx[4]):02X}{hx[5:]}"
    pct_b64 = f"{b64[:4]}%{ord(b64[4]):02X}{b64[5:]}"
    r_hex = scan_payload(pct_hex, canary_tokens=(CANARY,))
    r_b64 = scan_payload(pct_b64, canary_tokens=(CANARY,))
    passed = r_hex.canary_matched and r_b64.canary_matched
    return AttackOutcome(
        case_id="egress-canary-percent-encoded-hex-and-b64",
        family="4. Egress & Canaries",
        expected="canary_matched=True (AAD_FIRE)",
        observed=(
            f"pct_hex={r_hex.canary_matched} (clean={r_hex.clean}), "
            f"pct_b64={r_b64.canary_matched} (entropy={r_b64.high_entropy_matched})"
        ),
        passed=passed,
    )


def _check_egress_0x_reversed_and_base32() -> AttackOutcome:
    raw = CANARY.encode("utf-8")
    ox_hex = " ".join(f"0x{b:02x}" for b in raw)
    rev_hex = raw.hex()[::-1]
    rev_b64 = base64.b64encode(raw).decode("ascii")[::-1]
    b32 = base64.b32encode(raw).decode("ascii")
    checks = {
        "0x_hex": scan_payload(ox_hex, canary_tokens=(CANARY,)),
        "rev_hex": scan_payload(rev_hex, canary_tokens=(CANARY,)),
        "rev_b64": scan_payload(rev_b64, canary_tokens=(CANARY,)),
        "b32": scan_payload(b32, canary_tokens=(CANARY,)),
    }
    passed = all(res.canary_matched for res in checks.values())
    detail = ", ".join(f"{name}={res.canary_matched}(ent={res.high_entropy_matched})" for name, res in checks.items())
    return AttackOutcome(
        case_id="egress-canary-0x-hex-reversed-and-base32",
        family="4. Egress & Canaries",
        expected="all 4 canary_matched=True (AAD_FIRE)",
        observed=detail,
        passed=passed,
    )


def _check_egress_secret_percent_encoded() -> AttackOutcome:
    r = scan_payload(f"aws={SAMPLE_AWS_KEY_PCT}")
    passed = r.secret_matched and not r.clean
    return AttackOutcome(
        case_id="egress-known-secret-percent-encoded",
        family="4. Egress & Canaries",
        expected="secret_matched=True (BLOCK)",
        observed=f"secret={r.secret_matched}, clean={r.clean}, entropy={r.high_entropy_matched}",
        passed=passed,
    )


def _check_egress_secret_lowercase_hex() -> AttackOutcome:
    r_aws = scan_payload(SAMPLE_AWS_KEY.encode("utf-8").hex())
    r_oai = scan_payload(SAMPLE_OPENAI_KEY.encode("utf-8").hex())
    passed = r_aws.secret_matched and r_oai.secret_matched
    return AttackOutcome(
        case_id="egress-known-secret-lowercase-hex",
        family="4. Egress & Canaries",
        expected="secret_matched=True on hex secrets",
        observed=(
            f"aws_hex={r_aws.secret_matched}(clean={r_aws.clean}), "
            f"openai_hex={r_oai.secret_matched}(clean={r_oai.clean})"
        ),
        passed=passed,
    )


def _check_trailing_char_protected_write(work_dir: Path) -> AttackOutcome:
    """Windows drops a trailing dot or space, so writing `.gitleaks.toml.` would create `.gitleaks.toml` itself."""
    ws = work_dir / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    targets = (".gitleaks.toml.", ".mellyn-allowlist.toml ", ".claude./settings.json", ".github./workflows/x.yml")
    results = [
        (
            t,
            AirlockWorkspacePathGuard(ws).validate_path(t, is_write=True)[0],
            BackendWorkspacePathGuard(ws).validate_path(t, is_write=True)[0],
        )
        for t in targets
    ]
    return AttackOutcome(
        case_id="path-trailing-char-creates-protected-file",
        family="3. Workspace & Paths",
        expected="DENY writes on airlock/backend (target absent)",
        observed="; ".join(f"{t!r}:ag={ag},bg={bg}" for t, ag, bg in results),
        passed=not any(ag or bg for _, ag, bg in results),
    )


def _check_egress_split_interleaved_reordered_padded() -> AttackOutcome:
    third = len(CANARY) // 3
    a, b, c = CANARY[:third], CANARY[third : 2 * third], CANARY[2 * third :]
    checks = {
        "interleaved": {"p1": a, "note": "unrelated text", "p2": b, "id": 7, "p3": c},
        "reordered": [c, a, b],
        "padded_128k": ["x" * 131_072, a, b, c],
        "keys_with_values_between": {a: 1, "k": 2, b: 3, c: 4},
    }
    results = {name: scan_payload(payload, canary_tokens=(CANARY,)) for name, payload in checks.items()}
    leaked = [n for n, r in results.items() if any(piece in json.dumps(r.redacted_payload) for piece in (a, b, c))]
    return AttackOutcome(
        case_id="egress-canary-split-interleaved-reordered-padded",
        family="4. Egress & Canaries",
        expected="all canary_matched=True, no piece left in the redacted payload",
        observed=", ".join(f"{n}={r.canary_matched}" for n, r in results.items()) + f", leaked={leaked}",
        passed=all(r.canary_matched for r in results.values()) and not leaked,
    )


def _check_egress_escapes_decimal_and_nested() -> AttackOutcome:
    raw = CANARY.encode("utf-8")
    b64 = base64.b64encode(raw).decode("ascii")
    checks = {
        "x_escapes": "".join(f"\\x{byte:02x}" for byte in raw),
        "u_escapes": "".join(f"\\u{byte:04x}" for byte in raw),
        "decimal": ",".join(str(byte) for byte in raw),
        "double_b64": base64.b64encode(b64.encode("ascii")).decode("ascii"),
        "b64_of_hex": base64.b64encode(raw.hex().encode("ascii")).decode("ascii"),
    }
    results = {name: scan_payload(text, canary_tokens=(CANARY,)) for name, text in checks.items()}
    return AttackOutcome(
        case_id="egress-canary-escapes-decimal-and-nested",
        family="4. Egress & Canaries",
        expected="all 5 canary_matched=True (AAD_FIRE)",
        observed=", ".join(f"{n}={r.canary_matched}" for n, r in results.items()),
        passed=all(r.canary_matched for r in results.values()),
    )


def _check_egress_secret_base64_and_delimited_hex() -> AttackOutcome:
    raw = SAMPLE_AWS_KEY.encode("utf-8")
    checks = {
        "b64": base64.b64encode(raw).decode("ascii"),
        "spaced_hex": " ".join(f"{byte:02x}" for byte in raw),
        "0x_hex": ", ".join(f"0x{byte:02x}" for byte in raw),
        "u_escapes": "".join(f"\\u{byte:04x}" for byte in raw),
    }
    results = {name: scan_payload(f"cfg={text}") for name, text in checks.items()}
    return AttackOutcome(
        case_id="egress-known-secret-base64-delimited-hex-escaped",
        family="4. Egress & Canaries",
        expected="all 4 secret_matched=True (BLOCK)",
        observed=", ".join(f"{n}={r.secret_matched}" for n, r in results.items()),
        passed=all(r.secret_matched and not r.clean for r in results.values()),
    )


def _check_audit_midchain_tamper(work_dir: Path) -> AttackOutcome:
    path = work_dir / "tamper.jsonl"
    ledger = AuditLedger(path)
    ts = datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC).isoformat().replace("+00:00", "Z")
    for idx in range(2):
        ledger.record(
            ZoneEvent(
                event_id=f"evt-{idx}",
                timestamp_utc=ts,
                zone="airlock",
                action="tools/call",
                verdict_allow=True,
                severity="INFO",
                rule_id="airlock.tool_call_allowed",
                reason="ok",
                artifact_sha256="a" * 64,
                metadata={"session_id": "sess-tamper"},
            )
        )
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace('"reason":"ok"', '"reason":"NO"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    report = reconstruct_incident(path)
    passed = not report.chain_valid and report.status == "INTEGRITY_COMPROMISED"
    return AttackOutcome(
        case_id="audit-midchain-1byte-tamper",
        family="5. Forensic Ledger",
        expected="INTEGRITY_COMPROMISED",
        observed=f"chain_valid={report.chain_valid}, status={report.status}",
        passed=passed,
    )


def _check_audit_zero_canary_leak(work_dir: Path) -> AttackOutcome:
    path = work_dir / "canary-redaction.jsonl"
    ledger = AuditLedger(path, canary_tokens=(CANARY,))
    ts = datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC).isoformat().replace("+00:00", "Z")
    b64 = base64.b64encode(CANARY.encode("utf-8")).decode("ascii")
    chunked_b64 = " ".join(b64[i : i + 8] for i in range(0, len(b64), 8))
    ox_hex = " ".join(f"0x{b:02x}" for b in CANARY.encode("utf-8"))
    half = len(CANARY) // 2
    split_parts = [CANARY[:half], CANARY[half:]]

    ledger.record(
        ZoneEvent(
            event_id="evt-leak-probe",
            timestamp_utc=ts,
            zone="egress",
            action="tools/call",
            verdict_allow=False,
            severity="AAD_FIRE",
            rule_id="egress.canary_exfiltration",
            reason="Probing encoded and split canary redaction before disk",
            artifact_sha256="b" * 64,
            metadata={
                "session_id": "sess-redteam",
                "chunked": chunked_b64,
                "ox": ox_hex,
                "split": split_parts,
            },
        )
    )
    disk_text = path.read_text(encoding="utf-8")
    leaked_markers = [
        marker
        for name, marker in (
            ("raw", CANARY),
            ("chunked_b64", chunked_b64),
            ("ox_hex", ox_hex),
            ("split_prefix", split_parts[0]),
        )
        if marker in disk_text
    ]
    passed = len(leaked_markers) == 0
    return AttackOutcome(
        case_id="audit-zero-canary-leak-on-disk",
        family="5. Forensic Ledger",
        expected="0 encoded/split markers on disk",
        observed=f"leaked={leaked_markers}" if leaked_markers else "all redacted before disk",
        passed=passed,
    )


class _RedirectStubHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(302)
        self.send_header("Location", "https://evil.example/steal")
        self.end_headers()


def _viewer_http_call(
    url: str,
    *,
    method: str = "GET",
    api_key: str | None = None,
    host_header: str | None = None,
) -> tuple[int, str]:
    headers: dict[str, str] = {}
    if api_key is not None:
        headers[API_KEY_HEADER] = api_key
    if host_header is not None:
        headers["Host"] = host_header
    req = urllib.request.Request(url, method=method, headers=headers)  # noqa: S310 - test loopback only
    opener = build_approval_opener()
    try:
        with opener.open(req, timeout=5) as resp:
            return int(resp.status), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        with exc:
            return int(exc.code), exc.read().decode("utf-8", errors="replace")


def _check_viewer_security_cases(work_dir: Path) -> list[AttackOutcome]:
    pepper = secrets.token_urlsafe(32)
    viewer_key = secrets.token_urlsafe(24)
    approver_key = secrets.token_urlsafe(24)
    viewer_creds = CredentialConfig(
        pepper=pepper,
        digests={Role.VIEWER: key_digest(viewer_key, pepper)},
        roles=frozenset({Role.VIEWER}),
    )
    approver_creds = CredentialConfig(
        pepper=pepper,
        digests={Role.APPROVER: key_digest(approver_key, pepper)},
        roles=frozenset({Role.APPROVER}),
    )
    audit_log = work_dir / "viewer-audit.jsonl"
    AuditLedger(audit_log)

    redirect_upstream = HTTPServer(("127.0.0.1", 0), _RedirectStubHandler)
    import threading

    redir_thread = threading.Thread(target=redirect_upstream.serve_forever, daemon=True)
    redir_thread.start()
    redir_url = f"http://127.0.0.1:{redirect_upstream.server_address[1]}"

    static_dir = work_dir / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    (static_dir / "index.html").write_text("<html><body>ok</body></html>", encoding="utf-8")
    # A real file just outside the static root, so a traversal that worked would visibly return it.
    outside_marker = f"OUTSIDE-STATIC-{secrets.token_hex(8)}"
    (work_dir / "secret.txt").write_text(outside_marker, encoding="utf-8")

    server = ViewerHTTPServer(
        host="127.0.0.1",
        port=0,
        viewer_credentials=viewer_creds,
        approver_credentials=approver_creds,
        airlock_audit_path=audit_log,
        approval_upstream=redir_url,
        static_dir=static_dir,
    )
    server.start_in_background()
    try:
        rebind_code, _ = _viewer_http_call(f"{server.url}/api/v1/healthz", host_header="evil.attacker:8080")
        viewer_approve_code, _ = _viewer_http_call(
            f"{server.url}/api/v1/pending/apr_12345678/approve",
            method="POST",
            api_key=viewer_key,
        )
        approver_read_code, _ = _viewer_http_call(f"{server.url}/api/v1/airlock/report", api_key=approver_key)
        # Positive control: the static server does serve files, so a leak below would show up in a body.
        control_code, control_body = _viewer_http_call(f"{server.url}/index.html")
        traversal_results = [
            _viewer_http_call(f"{server.url}{probe}")
            for probe in ("/%2e%2e/secret.txt", "/..%2fsecret.txt", "/%252e%252e/secret.txt", "/..\\secret.txt")
        ]
        redirect_code, _ = _viewer_http_call(f"{server.url}/api/v1/pending", api_key=approver_key)
    finally:
        server.shutdown()
        server.server_close()
        redirect_upstream.shutdown()
        redirect_upstream.server_close()

    return [
        AttackOutcome(
            case_id="viewer-dns-rebinding-host-header",
            family="6. Plane 4 Viewer BFF",
            expected="421 Misdirected Request",
            observed=f"status={rebind_code}",
            passed=rebind_code == 421,
        ),
        AttackOutcome(
            case_id="viewer-role-separation-and-traversal",
            family="6. Plane 4 Viewer BFF",
            expected="403, 403; static control served; no traversal returns the outside file",
            observed=(
                f"viewer_approve={viewer_approve_code}, approver_read={approver_read_code}, "
                f"control={control_code}, traversal={[code for code, _ in traversal_results]}, "
                f"leaked={any(outside_marker in body for _, body in traversal_results)}"
            ),
            passed=(
                viewer_approve_code == 403
                and approver_read_code == 403
                and control_code == 200
                and "ok" in control_body
                and not any(outside_marker in body for _, body in traversal_results)
            ),
        ),
        AttackOutcome(
            case_id="viewer-approval-upstream-redirect-refusal",
            family="6. Plane 4 Viewer BFF",
            expected="502 Bad Gateway",
            observed=f"status={redirect_code}",
            passed=redirect_code == 502,
        ),
    ]


def run_all_attacks(*, audit_out: Path | None = None) -> list[AttackOutcome]:
    """Execute all 28 adversarial evaluation scenarios across all 6 families."""
    outcomes: list[AttackOutcome] = []
    with tempfile.TemporaryDirectory(prefix="mellyn-redteam-") as tmp:
        root = Path(tmp)

        def _dir(name: str) -> Path:
            sub = root / name
            sub.mkdir(parents=True, exist_ok=True)
            return sub

        # Family 1: Supply Chain & AgBOM
        outcomes.append(_check_agbom_rug_pull(_dir("f1-rug"), audit_out=audit_out))
        outcomes.append(_check_agbom_unpinned_tool(_dir("f1-unpinned")))
        outcomes.append(_check_agbom_unicode_tag_smuggling(_dir("f1-tag")))
        outcomes.append(_check_initialize_instructions_stripped(_dir("f1-instr")))

        # Family 2: Protocol & Framing
        outcomes.append(_check_duplicate_json_keys())
        outcomes.append(_check_unsolicited_spoofed_rpc_id(_dir("f2-spoof")))
        outcomes.append(_check_non_finite_nan())
        outcomes.append(_check_oversized_frame_bomb(_dir("f2-bomb")))

        # Family 3: Workspace & Paths
        outcomes.append(_check_path_case(_dir("f3-dotdot"), "path-traversal-dotdot-env", ("../.env",)))
        outcomes.append(_check_path_case(_dir("f3-dot"), "path-trailing-dot-env", (".env.",)))
        outcomes.append(_check_path_case(_dir("f3-ads1"), "path-ntfs-ads-env-data", (".env::$DATA",)))
        outcomes.append(
            _check_path_case(_dir("f3-ads2"), "path-ntfs-ads-key-stream", ("secret.key::$DATA", ".env:stream"))
        )
        outcomes.append(_check_trailing_char_protected_write(_dir("f3-protected")))

        # Family 4: Egress & Canaries
        sync_checks: tuple[Callable[[], AttackOutcome], ...] = (
            _check_egress_plain_and_zwsp,
            _check_egress_split_list_and_dict,
            _check_egress_chunked_base64,
            _check_egress_percent_encoded_hex_and_b64,
            _check_egress_0x_reversed_and_base32,
            _check_egress_split_interleaved_reordered_padded,
            _check_egress_escapes_decimal_and_nested,
            _check_egress_secret_percent_encoded,
            _check_egress_secret_lowercase_hex,
            _check_egress_secret_base64_and_delimited_hex,
        )
        for check in sync_checks:
            outcomes.append(check())

        # Family 5: Forensic Ledger
        outcomes.append(_check_audit_midchain_tamper(_dir("f5-tamper")))
        outcomes.append(_check_audit_zero_canary_leak(_dir("f5-leak")))

        # Family 6: Plane 4 Viewer BFF
        outcomes.extend(_check_viewer_security_cases(_dir("f6-viewer")))

    return outcomes


def _print_scorecard(outcomes: list[AttackOutcome]) -> None:
    passed = sum(1 for o in outcomes if o.passed)
    total = len(outcomes)
    print(f"=== Mellyn Adversarial Red-Team Scorecard ({passed}/{total} caught) ===")
    for o in outcomes:
        tag = "PASS" if o.passed else "FAIL"
        print(f"[{tag}] {o.family:24s} | {o.case_id:42s} | {o.observed}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the 28-case Mellyn adversarial red-team scorecard.")
    parser.add_argument("--json", action="store_true", help="Emit deterministic JSON scorecard output.")
    parser.add_argument("--audit-out", type=Path, default=None, help="Optional path to save sample AAD audit.jsonl.")
    args = parser.parse_args(argv)

    outcomes = run_all_attacks(audit_out=args.audit_out)
    passed = sum(1 for o in outcomes if o.passed)
    total = len(outcomes)

    if args.json:
        print(
            json.dumps(
                {
                    "passed": passed,
                    "failed": total - passed,
                    "total": total,
                    "cases": [asdict(o) for o in outcomes],
                },
                indent=2,
            )
        )
    else:
        _print_scorecard(outcomes)

    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
