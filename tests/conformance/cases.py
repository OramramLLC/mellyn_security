"""
Synthetic control-validation cases across six OWASP/ATLAS families plus Linux container boundaries.

Every `fast` case exercises the real production entrypoint (`MCPGateway`, `run_stdio_proxy`,
`Authorizer`, `PendingApprovals`, `CredentialConfig`, `build_approval_opener`, `verify_dependencies`,
`sync_agent_rules`) against disposable synthetic data and `FakeDownstream`.
"""

from __future__ import annotations

import datetime as dt
import email
import io
import json
import secrets
import sys
import tempfile
import urllib.error
import urllib.request
import urllib.response
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"
SCRIPTS_DIR = REPO_ROOT / "scripts"
for _p in (REPO_ROOT, BACKEND_DIR, SCRIPTS_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import sync_agent_rules  # noqa: E402
import verify_dependencies as vd  # noqa: E402
from mellyn import (  # noqa: E402
    AuditLogger,
    Authorizer,
    CredentialConfig,
    CredentialConfigError,
    Decision,
    PolicyConfig,
    RiskTier,
    Role,
    TaintSource,
    ToolCallRequest,
    ToolCapability,
)
from mellyn.approvals import (  # noqa: E402
    PENDING_TTL_SECONDS,
    ApprovalRedirectError,
    PendingApprovals,
    build_approval_opener,
)
from mellyn.credentials import key_digest  # noqa: E402
from mellyn.mcp_gateway import (  # noqa: E402
    DOWNSTREAM_ERROR,
    JSONRPC_INVALID_PARAMS,
    JSONRPC_INVALID_REQUEST,
    JSONRPC_PARSE_ERROR,
    MELLYN_APPROVAL_REQUIRED,
    MELLYN_POLICY_DENIED,
    MCPGateway,
    compute_tools_hash,
    run_stdio_proxy,
)

from tests.conformance.recorder import (  # noqa: E402
    AuditVerification,
    CaseOutcome,
    CaseSpec,
    ControlMapping,
    EvidenceRecorder,
    canonical_args_sha256,
    non_audit_verification,
    verify_audit_sink,
)
from tests.fakes import FakeDownstream  # noqa: E402

# Synthetic markers used across conformance probes; none may ever appear in audit sinks or exported reports.
FORBIDDEN_CONFORMANCE_MARKERS: tuple[str, ...] = (
    "canary_secret_marker_991",
    "canary_ses_probe_774",
    "canary_tool_probe_882",
    "canary_srv_probe_663",
    "evil-docs.python.org.attacker.invalid",
    "approver_secret_canary_551",
)


# --------------------------------------------------------------------------- #
# Family 1: MCP metadata & cross-server taint
# --------------------------------------------------------------------------- #
_MAP_MCP_TAINT = ControlMapping(
    owasp_llm_2025=("LLM01", "LLM03", "LLM06"),
    owasp_agentic_2026=("ASI01", "ASI02", "ASI04"),
    mitre_atlas=("AML.M0014", "AML.M0028"),
)


def _case_pin_matching() -> CaseOutcome:
    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp)
        notes_tools = [{"name": "list_notes", "description": "list notes"}]
        policy = PolicyConfig(
            allowed_mcp_servers=frozenset({"notes", "local"}),
            trusted_mcp_servers=frozenset({"local"}),
            pinned_tool_hashes={"notes": compute_tools_hash(notes_tools)},
            tool_risk_tiers={"notes/list_notes": RiskTier.LOW, "local/workspace_write": RiskTier.MEDIUM},
            tool_capabilities={"notes/list_notes": ToolCapability(pure=True)},
        )
        sink = io.StringIO()
        auth = Authorizer(workspace_root=ws, policy_config=policy, audit_logger=AuditLogger(sink=sink))
        notes_srv = FakeDownstream("notes", notes_tools)
        local_srv = FakeDownstream("local", ["workspace_write"])
        gw = MCPGateway(authorizer=auth, servers={"notes": notes_srv, "local": local_srv})

        list_res = gw.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        write_args = {"path": "draft.txt"}
        write_res = gw.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "local__workspace_write", "arguments": write_args},
            }
        )
        listed_ok = isinstance(list_res, dict) and "result" in list_res
        write_ok = isinstance(write_res, dict) and "result" in write_res
        audit = verify_audit_sink(
            sink.getvalue(),
            expected_decision="allow",
            expected_arguments=write_args,
            forbidden_markers=FORBIDDEN_CONFORMANCE_MARKERS,
        )
        return CaseOutcome(
            observed={
                "listing_verified": listed_ok,
                "session_tainted": auth.is_tainted(gw.session_id),
                "write_decision": "allow" if write_ok else "denied",
                "downstream_calls": len(local_srv.tool_calls),
            },
            audit=audit,
        )


def _case_pin_mismatch() -> CaseOutcome:
    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp)
        reviewed = [{"name": "list_notes", "description": "list notes"}]
        mutated = [{"name": "list_notes", "description": "list project notes"}]
        policy = PolicyConfig(
            allowed_mcp_servers=frozenset({"notes"}),
            pinned_tool_hashes={"notes": compute_tools_hash(reviewed)},
            tool_risk_tiers={"notes/list_notes": RiskTier.LOW},
            tool_capabilities={"notes/list_notes": ToolCapability(pure=True)},
        )
        sink = io.StringIO()
        auth = Authorizer(workspace_root=ws, policy_config=policy, audit_logger=AuditLogger(sink=sink))
        notes_srv = FakeDownstream("notes", mutated)
        gw = MCPGateway(authorizer=auth, servers={"notes": notes_srv})

        list_res = gw.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        call_res = gw.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "notes__list_notes", "arguments": {}},
            }
        )
        list_denied = isinstance(list_res, dict) and list_res.get("error", {}).get("code") == MELLYN_POLICY_DENIED
        call_denied = isinstance(call_res, dict) and call_res.get("error", {}).get("code") == MELLYN_POLICY_DENIED
        corr_id = call_res["error"]["data"]["audit_id"] if call_denied else None
        audit = verify_audit_sink(
            sink.getvalue(),
            expected_decision="deny",
            expected_arguments={},
            correlation_id=corr_id,
            forbidden_markers=FORBIDDEN_CONFORMANCE_MARKERS,
        )
        return CaseOutcome(
            observed={
                "list_denied": list_denied,
                "call_decision": "deny" if call_denied else "other",
                "downstream_calls": len(notes_srv.tool_calls),
            },
            audit=audit,
        )


def _case_unpinned_cross_server_taint() -> CaseOutcome:
    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp)
        policy = PolicyConfig(
            allowed_mcp_servers=frozenset({"notes", "local"}),
            trusted_mcp_servers=frozenset({"local"}),
            tool_risk_tiers={"notes/list_notes": RiskTier.LOW, "local/workspace_write": RiskTier.MEDIUM},
            tool_capabilities={"notes/list_notes": ToolCapability(pure=True)},
        )
        sink = io.StringIO()
        auth = Authorizer(workspace_root=ws, policy_config=policy, audit_logger=AuditLogger(sink=sink))
        notes_srv = FakeDownstream("notes", [{"name": "list_notes", "description": "list notes"}])
        local_srv = FakeDownstream("local", ["workspace_write"])
        gw = MCPGateway(
            authorizer=auth,
            servers={"notes": notes_srv, "local": local_srv},
            approvals=PendingApprovals(auth),
        )

        gw.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        write_args = {"path": "draft.txt"}
        write_res = gw.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "local__workspace_write", "arguments": write_args},
            }
        )
        held = isinstance(write_res, dict) and write_res.get("error", {}).get("code") == MELLYN_APPROVAL_REQUIRED
        corr_id = write_res["error"]["data"]["audit_id"] if held else None
        taint_audit = verify_audit_sink(sink.getvalue(), expected_decision="tainted")
        auth_audit = verify_audit_sink(
            sink.getvalue(),
            expected_decision="require_approval",
            expected_arguments=write_args,
            correlation_id=corr_id,
            forbidden_markers=FORBIDDEN_CONFORMANCE_MARKERS,
        )
        combined = AuditVerification(
            required=True,
            matching_events=auth_audit.matching_events,
            decision_matches=auth_audit.decision_matches and taint_audit.decision_matches,
            argument_digest_matches=auth_audit.argument_digest_matches,
            synthetic_marker_absent=auth_audit.synthetic_marker_absent,
            complete=auth_audit.complete and taint_audit.complete,
        )
        return CaseOutcome(
            observed={
                "session_tainted": auth.is_tainted(gw.session_id),
                "second_server_decision": "require_approval" if held else "other",
                "downstream_calls": len(local_srv.tool_calls),
            },
            audit=combined,
        )


def _case_server_error_vs_local_timeout() -> CaseOutcome:
    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp)
        notes_tools = [{"name": "list_notes", "description": "list notes"}]
        policy = PolicyConfig(
            allowed_mcp_servers=frozenset({"notes", "local"}),
            trusted_mcp_servers=frozenset({"local"}),
            pinned_tool_hashes={"notes": compute_tools_hash(notes_tools)},
            tool_risk_tiers={"notes/list_notes": RiskTier.LOW, "local/workspace_write": RiskTier.MEDIUM},
            tool_capabilities={"notes/list_notes": ToolCapability(pure=True)},
        )
        sink = io.StringIO()
        auth = Authorizer(workspace_root=ws, policy_config=policy, audit_logger=AuditLogger(sink=sink))
        notes_srv = FakeDownstream("notes", notes_tools, failure="no_answer")
        local_srv = FakeDownstream("local", ["workspace_write"])
        gw = MCPGateway(
            authorizer=auth,
            servers={"notes": notes_srv, "local": local_srv},
            approvals=PendingApprovals(auth),
        )

        # 1. Local gateway timeout leaves session clean -> medium write succeeds
        gw.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "notes__list_notes", "arguments": {}},
            }
        )
        clean_after_timeout = not auth.is_tainted(gw.session_id)
        first_write = gw.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "local__workspace_write", "arguments": {"path": "clean.txt"}},
            }
        )
        first_write_allowed = isinstance(first_write, dict) and "result" in first_write

        # 2. Server-authored JSON-RPC error taints session -> next medium write requires approval
        notes_srv.failure = "server_error"
        gw.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "notes__list_notes", "arguments": {}},
            }
        )
        tainted_after_server_error = auth.is_tainted(gw.session_id)
        held_args = {"path": "after_err.txt"}
        second_write = gw.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "local__workspace_write", "arguments": held_args},
            }
        )
        second_held = (
            isinstance(second_write, dict) and second_write.get("error", {}).get("code") == MELLYN_APPROVAL_REQUIRED
        )
        corr_id = second_write["error"]["data"]["audit_id"] if second_held else None
        audit = verify_audit_sink(
            sink.getvalue(),
            expected_decision="require_approval",
            expected_arguments=held_args,
            correlation_id=corr_id,
            forbidden_markers=FORBIDDEN_CONFORMANCE_MARKERS,
        )
        return CaseOutcome(
            observed={
                "clean_after_local_timeout": clean_after_timeout and first_write_allowed,
                "tainted_after_server_error": tainted_after_server_error,
                "second_write_decision": "require_approval" if second_held else "other",
                "local_write_dispatches": len(local_srv.tool_calls),
            },
            audit=audit,
        )


# --------------------------------------------------------------------------- #
# Family 2: Paths, resources, and egress
# --------------------------------------------------------------------------- #
_MAP_BOUNDARIES = ControlMapping(
    owasp_llm_2025=("LLM02", "LLM06"),
    owasp_agentic_2026=("ASI02", "ASI03"),
    mitre_atlas=("AML.M0028",),
)


def _case_protected_file_resource_read() -> CaseOutcome:
    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp)
        (ws / "notes.txt").write_text("public notes\n", encoding="utf-8")
        sensitive = ws / ".env"
        sensitive.write_text(f"TOKEN={FORBIDDEN_CONFORMANCE_MARKERS[0]}\n", encoding="utf-8")
        note_uri = (ws / "notes.txt").as_uri()
        env_uri = sensitive.as_uri()

        policy = PolicyConfig(
            allowed_mcp_servers=frozenset({"fs"}),
            trusted_mcp_servers=frozenset({"fs"}),
            tool_risk_tiers={"fs/resources/read": RiskTier.LOW},
        )
        sink = io.StringIO()
        auth = Authorizer(workspace_root=ws, policy_config=policy, audit_logger=AuditLogger(sink=sink))
        fs_srv = FakeDownstream("fs", resources=[note_uri, env_uri])
        gw = MCPGateway(authorizer=auth, servers={"fs": fs_srv})

        gw.handle_message({"jsonrpc": "2.0", "id": 1, "method": "resources/list"})
        ok_reply = gw.handle_message(
            {"jsonrpc": "2.0", "id": 2, "method": "resources/read", "params": {"uri": note_uri}}
        )
        deny_reply = gw.handle_message(
            {"jsonrpc": "2.0", "id": 3, "method": "resources/read", "params": {"uri": env_uri}}
        )
        ok_passed = isinstance(ok_reply, dict) and "result" in ok_reply
        denied = isinstance(deny_reply, dict) and deny_reply.get("error", {}).get("code") == MELLYN_POLICY_DENIED
        corr_id = deny_reply["error"]["data"]["audit_id"] if denied else None

        # Only the permitted note_uri may reach FakeDownstream; env_uri must get 0 dispatches!
        dispatched_uris = [p.get("uri") for p in fs_srv.calls_for("resources/read")]
        audit = verify_audit_sink(
            sink.getvalue(),
            expected_decision="deny",
            expected_arguments={"uri": env_uri},
            correlation_id=corr_id,
            forbidden_markers=FORBIDDEN_CONFORMANCE_MARKERS,
        )
        return CaseOutcome(
            observed={
                "ordinary_resource_allowed": ok_passed,
                "decision": "deny" if denied else "other",
                "sensitive_downstream_calls": sum(1 for u in dispatched_uris if u == env_uri),
                "ordinary_downstream_calls": sum(1 for u in dispatched_uris if u == note_uri),
            },
            audit=audit,
        )


def _case_ancestor_subtree_move_denied() -> CaseOutcome:
    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp)
        (ws / "project" / "guarded").mkdir(parents=True)
        (ws / "project" / "guarded" / "rule.toml").write_text("x = 1\n", encoding="utf-8")

        policy = PolicyConfig(
            allowed_mcp_servers=frozenset({"fs"}),
            trusted_mcp_servers=frozenset({"fs"}),
            protected_paths=("project/guarded/",),
            server_presets={"fs": "mcp-filesystem"},
            tool_risk_tiers={"fs/move_file": RiskTier.MEDIUM},
        )
        sink = io.StringIO()
        auth = Authorizer(workspace_root=ws, policy_config=policy, audit_logger=AuditLogger(sink=sink))
        fs_srv = FakeDownstream("fs", ["move_file"])
        gw = MCPGateway(authorizer=auth, servers={"fs": fs_srv})

        move_args = {"source": "project", "destination": "relocated"}
        auth.issue_grant(
            session_id=gw.session_id,
            tool_name="move_file",
            mcp_server="fs",
            mcp_method="tools/call",
            arguments=move_args,
            approved_by="reviewer@mellyn.security",
        )
        reply = gw.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "fs__move_file", "arguments": move_args},
            }
        )
        denied = isinstance(reply, dict) and reply.get("error", {}).get("code") == MELLYN_POLICY_DENIED
        corr_id = reply["error"]["data"]["audit_id"] if denied else None
        audit = verify_audit_sink(
            sink.getvalue(),
            expected_decision="deny",
            expected_arguments=move_args,
            correlation_id=corr_id,
            forbidden_markers=FORBIDDEN_CONFORMANCE_MARKERS,
        )
        return CaseOutcome(
            observed={
                "decision": "deny" if denied else "other",
                "downstream_calls": len(fs_srv.tool_calls),
            },
            audit=audit,
        )


def _case_egress_url_matrix() -> CaseOutcome:
    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp)
        policy = PolicyConfig(
            allowed_mcp_servers=frozenset({"net"}),
            trusted_mcp_servers=frozenset({"net"}),
            allowed_egress_domains=frozenset({"docs.python.org"}),
            server_presets={"net": "mcp-fetch"},
            tool_risk_tiers={"net/fetch": RiskTier.LOW},
        )
        sink = io.StringIO()
        auth = Authorizer(workspace_root=ws, policy_config=policy, audit_logger=AuditLogger(sink=sink))
        net_srv = FakeDownstream("net", ["fetch"])
        gw = MCPGateway(authorizer=auth, servers={"net": net_srv})

        allowed_urls = ("https://docs.python.org/3/", "https://sub.docs.python.org/library/")
        denied_urls = (
            f"https://{FORBIDDEN_CONFORMANCE_MARKERS[4]}/path",
            "http://docs.python.org/3/",
            "https://docs.python.org:99999/badport",
        )

        allow_count = 0
        for idx, u in enumerate(allowed_urls, start=1):
            r = gw.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": idx,
                    "method": "tools/call",
                    "params": {"name": "net__fetch", "arguments": {"url": u}},
                }
            )
            if isinstance(r, dict) and "result" in r:
                allow_count += 1

        deny_count = 0
        last_corr_id: str | None = None
        last_bad_args: dict[str, Any] = {}
        for idx, u in enumerate(denied_urls, start=10):
            last_bad_args = {"url": u}
            r = gw.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": idx,
                    "method": "tools/call",
                    "params": {"name": "net__fetch", "arguments": last_bad_args},
                }
            )
            if isinstance(r, dict) and r.get("error", {}).get("code") == MELLYN_POLICY_DENIED:
                deny_count += 1
                last_corr_id = r["error"]["data"]["audit_id"]

        audit = verify_audit_sink(
            sink.getvalue(),
            expected_decision="deny",
            expected_arguments=last_bad_args,
            correlation_id=last_corr_id,
            forbidden_markers=FORBIDDEN_CONFORMANCE_MARKERS,
        )
        return CaseOutcome(
            observed={
                "allowed_passed": allow_count,
                "denied_blocked": deny_count,
                "downstream_calls": len(net_srv.tool_calls),
            },
            audit=audit,
        )


# --------------------------------------------------------------------------- #
# Family 3: Human authority, role separation, and exact grants
# --------------------------------------------------------------------------- #
_MAP_AUTHORITY = ControlMapping(
    owasp_llm_2025=("LLM06",),
    owasp_agentic_2026=("ASI03", "ASI09"),
    mitre_atlas=("AML.M0027", "AML.M0028"),
)


def _case_role_separation_and_redirect_refusal() -> CaseOutcome:
    pepper = secrets.token_urlsafe(32)
    agent_k = secrets.token_urlsafe(32)
    approver_k = FORBIDDEN_CONFORMANCE_MARKERS[5]
    cfg = CredentialConfig.from_env(
        {
            "MELLYN_API_KEY_PEPPER": pepper,
            "MELLYN_AGENT_KEY_DIGEST": key_digest(agent_k, pepper),
            "MELLYN_APPROVER_KEY_DIGEST": key_digest(approver_k, pepper),
        }
    )
    roles_isolated = (
        cfg.verify(agent_k, Role.AGENT)
        and not cfg.verify(agent_k, Role.APPROVER)
        and cfg.verify(approver_k, Role.APPROVER)
        and not cfg.verify(approver_k, Role.AGENT)
    )

    dup_digest = key_digest(agent_k, pepper)
    duplicate_rejected = False
    try:
        CredentialConfig.from_env(
            {
                "MELLYN_API_KEY_PEPPER": pepper,
                "MELLYN_AGENT_KEY_DIGEST": dup_digest,
                "MELLYN_APPROVER_KEY_DIGEST": dup_digest,
            },
            roles=frozenset({Role.APPROVER}),
        )
    except CredentialConfigError:
        duplicate_rejected = True

    transport_calls: list[str] = []

    class _RedirectTransport(urllib.request.HTTPHandler):
        def http_open(self, req: urllib.request.Request) -> Any:
            transport_calls.append(req.full_url)
            hdrs = email.message_from_string("Location: http://169.254.169.254/steal\r\n")
            resp = urllib.response.addinfourl(io.BytesIO(b""), hdrs, req.full_url, 302)
            resp.msg = "Found"
            return resp

    opener = build_approval_opener(_RedirectTransport())
    req = urllib.request.Request("http://127.0.0.1:8765/v1/pending", headers={"X-Mellyn-API-Key": approver_k})
    redirect_code = 0
    err_text = ""
    try:
        opener.open(req, timeout=2)
    except ApprovalRedirectError as exc:
        redirect_code = exc.code
        err_text = str(exc)

    audit = non_audit_verification(raw_evidence_text=err_text, forbidden_markers=FORBIDDEN_CONFORMANCE_MARKERS)
    return CaseOutcome(
        observed={
            "roles_isolated": roles_isolated,
            "duplicate_digest_rejected": duplicate_rejected,
            "redirect_http_code": redirect_code,
            "transport_calls": len(transport_calls),
        },
        audit=audit,
    )


def _case_reserved_resource_read_identity() -> CaseOutcome:
    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp)
        (ws / "doc.txt").write_text("doc\n", encoding="utf-8")
        doc_uri = (ws / "doc.txt").as_uri()

        policy = PolicyConfig(
            allowed_mcp_servers=frozenset({"srv"}),
            trusted_mcp_servers=frozenset({"srv"}),
            tool_risk_tiers={"srv/resources/read": RiskTier.LOW},
        )
        sink = io.StringIO()
        auth = Authorizer(workspace_root=ws, policy_config=policy, audit_logger=AuditLogger(sink=sink))
        srv = FakeDownstream(
            "srv",
            [{"name": "resources/read", "description": "spoofed downstream tool"}],
            resources=[doc_uri],
        )
        gw = MCPGateway(authorizer=auth, servers={"srv": srv})

        gw.handle_message({"jsonrpc": "2.0", "id": 1, "method": "resources/list"})
        legit = gw.handle_message({"jsonrpc": "2.0", "id": 2, "method": "resources/read", "params": {"uri": doc_uri}})
        spoof_args = {"uri": doc_uri}
        spoof = gw.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "srv__resources/read", "arguments": spoof_args},
            }
        )
        legit_ok = isinstance(legit, dict) and "result" in legit
        gateway_rejected = isinstance(spoof, dict) and spoof.get("error", {}).get("code") == JSONRPC_INVALID_PARAMS
        direct_spoof = auth.authorize(
            ToolCallRequest(gw.session_id, "resources/read", spoof_args, mcp_server="srv", mcp_method="tools/call")
        )
        spoof_denied = gateway_rejected and direct_spoof.decision == Decision.DENY
        audit = verify_audit_sink(
            sink.getvalue(),
            expected_decision="deny",
            expected_arguments=spoof_args,
            correlation_id=direct_spoof.audit_id,
            forbidden_markers=FORBIDDEN_CONFORMANCE_MARKERS,
        )
        return CaseOutcome(
            observed={
                "legitimate_resource_read_allowed": legit_ok,
                "spoofed_tool_decision": "deny" if spoof_denied else "other",
                "downstream_tool_calls": len(srv.tool_calls),
            },
            audit=audit,
        )


def _case_expired_approval_and_exact_grant_bounds() -> CaseOutcome:
    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp)
        policy = PolicyConfig(
            allowed_mcp_servers=frozenset({"srv_a", "srv_b"}), trusted_mcp_servers=frozenset({"srv_a", "srv_b"})
        )
        sink = io.StringIO()
        auth = Authorizer(workspace_root=ws, policy_config=policy, audit_logger=AuditLogger(sink=sink))
        approvals = PendingApprovals(auth)
        srv_a = FakeDownstream("srv_a", ["deploy_action"])
        srv_b = FakeDownstream("srv_b", ["deploy_action"])
        gw = MCPGateway(authorizer=auth, servers={"srv_a": srv_a, "srv_b": srv_b}, approvals=approvals)

        t0 = dt.datetime.now(dt.UTC)
        req_exact = ToolCallRequest(gw.session_id, "deploy_action", {"dry_run": True}, mcp_server="srv_a")
        held_result = auth.authorize(req_exact, now=t0)
        held_rec = approvals.add(req_exact, held_result, now=t0)

        # 1. Expired pending approval raises KeyError and issues zero grants
        expired_rejected = False
        try:
            approvals.approve(
                held_rec.approval_id,
                approved_by="sec@mellyn.security",
                now=t0 + dt.timedelta(seconds=PENDING_TTL_SECONDS + 1),
            )
        except KeyError:
            expired_rejected = True

        # 2. Fresh one-use grant authorizes exact call once, then rejects replay, scalar-type drift, and server drift
        fresh_rec = approvals.add(req_exact, held_result, now=t0)
        issued = approvals.approve(fresh_rec.approval_id, approved_by="sec@mellyn.security", now=t0)

        first = gw.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "srv_a__deploy_action", "arguments": {"dry_run": True}},
            }
        )
        replay = gw.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "srv_a__deploy_action", "arguments": {"dry_run": True}},
            }
        )

        # Issue a second grant for {"dry_run": True} on srv_a and test type drift (1 vs True) and server drift (srv_b)
        auth.issue_grant(
            session_id=gw.session_id,
            tool_name="deploy_action",
            mcp_server="srv_a",
            mcp_method="tools/call",
            arguments={"dry_run": True},
            approved_by="sec@mellyn.security",
        )
        type_drift = gw.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "srv_a__deploy_action", "arguments": {"dry_run": 1}},
            }
        )
        srv_drift_args = {"dry_run": True}
        srv_drift = gw.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "srv_b__deploy_action", "arguments": srv_drift_args},
            }
        )
        srv_drift_held = (
            isinstance(srv_drift, dict) and srv_drift.get("error", {}).get("code") == MELLYN_APPROVAL_REQUIRED
        )
        corr_id = srv_drift["error"]["data"]["audit_id"] if srv_drift_held else None
        audit = verify_audit_sink(
            sink.getvalue(),
            expected_decision="require_approval",
            expected_arguments=srv_drift_args,
            correlation_id=corr_id,
            forbidden_markers=FORBIDDEN_CONFORMANCE_MARKERS,
        )
        return CaseOutcome(
            observed={
                "expired_approval_refused": expired_rejected and issued is not None,
                "exact_call_allowed": isinstance(first, dict) and "result" in first,
                "replay_blocked": isinstance(replay, dict)
                and replay.get("error", {}).get("code") == MELLYN_APPROVAL_REQUIRED,
                "type_drift_blocked": isinstance(type_drift, dict)
                and type_drift.get("error", {}).get("code") == MELLYN_APPROVAL_REQUIRED,
                "server_drift_blocked": srv_drift_held,
                "srv_a_calls": len(srv_a.tool_calls),
                "srv_b_calls": len(srv_b.tool_calls),
            },
            audit=audit,
        )


# --------------------------------------------------------------------------- #
# Family 4: JSON-RPC framing & capacity
# --------------------------------------------------------------------------- #
_MAP_FRAMING = ControlMapping(
    owasp_llm_2025=("LLM05", "LLM10"),
    owasp_agentic_2026=("ASI08",),
    # No ATLAS mitigation: AML.M0010 "Input Restoration" is about cleaning adversarial ML inputs, not rejecting
    # malformed or oversized protocol frames, and citing a near miss would overstate the evidence.
    mitre_atlas=(),
)


def _case_framing_errors_and_recovery() -> CaseOutcome:
    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp)
        policy = PolicyConfig(
            allowed_mcp_servers=frozenset({"dual"}),
            trusted_mcp_servers=frozenset({"dual"}),
            tool_risk_tiers={"dual/op": RiskTier.LOW},
            tool_capabilities={"dual/op": ToolCapability(pure=True)},
        )
        auth = Authorizer(workspace_root=ws, policy_config=policy)
        # Downstream configured with invalid dual result+error envelope on tools/call
        dual_srv = FakeDownstream(
            "dual",
            ["op"],
            call_response={"jsonrpc": "2.0", "id": 1, "result": {"ok": True}, "error": {"code": -1, "message": "bad"}},
        )
        gw = MCPGateway(authorizer=auth, servers={"dual": dual_srv})

        frames = (
            "{malformed-json\n"
            '{"jsonrpc":"2.0","id":true,"method":"tools/call","params":{"name":"dual__op","arguments":{}}}\n'
            '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"dual__op","arguments":{}}}\n'
            + ("🚀" * 24 + "\n")
            + '{"jsonrpc":"2.0","id":9,"method":"ping"}\n'
        )
        raw_in = io.TextIOWrapper(io.BytesIO(frames.encode("utf-8")), encoding="utf-8")
        out = io.StringIO()
        run_stdio_proxy(gateway=gw, client_in=raw_in, client_out=out, max_line_bytes=92)
        replies = [json.loads(line) for line in out.getvalue().splitlines()]

        audit = non_audit_verification(
            raw_evidence_text=out.getvalue(),
            forbidden_markers=FORBIDDEN_CONFORMANCE_MARKERS,
        )
        return CaseOutcome(
            observed={
                "reply_count": len(replies),
                "parse_error_code": replies[0].get("error", {}).get("code"),
                "bool_id_error_code": replies[1].get("error", {}).get("code"),
                "dual_envelope_error_code": replies[2].get("error", {}).get("code"),
                "oversized_error_code": replies[3].get("error", {}).get("code"),
                "recovery_ping_ok": replies[4] == {"jsonrpc": "2.0", "id": 9, "result": {}},
                # Boolean-ID request must not dispatch; only id=3 reached downstream before reply validation rejected it
                "downstream_calls": len(dual_srv.tool_calls),
            },
            audit=audit,
        )


# --------------------------------------------------------------------------- #
# Family 5: Manifest & scanner integrity
# --------------------------------------------------------------------------- #
_MAP_SUPPLY_CHAIN = ControlMapping(
    owasp_llm_2025=("LLM03",),
    owasp_agentic_2026=("ASI04",),
    mitre_atlas=("AML.M0014",),
)


def _case_lockfile_duplicate_and_missing_integrity() -> CaseOutcome:
    valid_doc = {
        "name": "app",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app"},
            "node_modules/pkg": {"version": "1.2.3", "integrity": "sha512-valid=="},
            "node_modules/sub/node_modules/pkg": {"version": "1.2.3", "integrity": "sha512-valid=="},
        },
    }
    conflict_doc = {
        "name": "app",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app"},
            "node_modules/pkg": {"version": "1.2.3", "integrity": "sha512-valid=="},
            "node_modules/sub/node_modules/pkg": {"version": "1.2.3", "integrity": "sha512-evil=="},
        },
    }
    missing_doc = {
        "name": "app",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app"},
            "node_modules/pkg": {"version": "1.2.3", "integrity": "sha512-valid=="},
            "node_modules/sub/node_modules/pkg": {"version": "1.2.3"},
        },
    }

    def _run_doc(doc: dict[str, Any]) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "package-lock.json").write_text(json.dumps(doc), encoding="utf-8")
            buf = io.StringIO()
            with (
                mock.patch.object(vd, "verify_registry", return_value=[]),
                mock.patch.object(vd, "npm_release_integrity", return_value="sha512-valid=="),
                mock.patch("sys.stdout", buf),
            ):
                rc = vd.main(["--root", tmp, "--online"])
            return rc, buf.getvalue()

    ok_rc, _ = _run_doc(valid_doc)
    conflict_rc, conflict_out = _run_doc(conflict_doc)
    missing_rc, missing_out = _run_doc(missing_doc)

    audit = non_audit_verification(forbidden_markers=FORBIDDEN_CONFORMANCE_MARKERS)
    return CaseOutcome(
        observed={
            "valid_exit": ok_rc,
            "conflict_exit": conflict_rc,
            "conflict_flagged": "[HASH MISMATCH]" in conflict_out,
            "missing_exit": missing_rc,
            "missing_flagged": "[MISSING HASH]" in missing_out,
        },
        audit=audit,
    )


def _case_nested_manifest_build_deps_and_unicode() -> CaseOutcome:
    def _run_files(files: dict[str, str]) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as tmp:
            for rel, text in files.items():
                p = Path(tmp) / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text, encoding="utf-8")
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc = vd.main(["--root", tmp])
            return rc, buf.getvalue()

    valid_rc, _ = _run_files(
        {
            "services/api/pyproject.toml": (
                '[build-system]\nrequires = ["setuptools>=75.0.0"]\nbuild-backend = "setuptools.build_meta"\n'
                '[project]\nname = "svc"\nversion = "0.1.0"\ndependencies = ["httpx>=0.28.0"]\n'
            )
        }
    )
    nested_weak_rc, _ = _run_files(
        {"services/api/pyproject.toml": '[project]\nname = "svc"\nversion = "0.1.0"\ndependencies = ["httpx>=0"]\n'}
    )
    build_weak_rc, _ = _run_files(
        {
            "pyproject.toml": (
                '[build-system]\nrequires = ["setuptools"]\nbuild-backend = "setuptools.build_meta"\n'
                '[project]\nname = "svc"\nversion = "0.1.0"\ndependencies = ["httpx>=0.28.0"]\n'
            )
        }
    )
    expired_rc, expired_out = _run_files(
        {
            ".mellyn-allowlist.toml": (
                'schema_version = 1\n[[exemptions]]\npackage = "oldpkg"\necosystem = "pypi"\n'
                'reason = "waiver"\napproved_by = "@sec"\nexpires = "2020-01-01"\n'
            )
        }
    )

    hidden_hit = sync_agent_rules.hidden_characters("alpha\fbeta")
    clean_unicode = sync_agent_rules.hidden_characters("⚠️ Rule 1:\n\tKeep builds reproducible.\r\n")

    audit = non_audit_verification(forbidden_markers=FORBIDDEN_CONFORMANCE_MARKERS)
    return CaseOutcome(
        observed={
            "valid_manifest_exit": valid_rc,
            "nested_weak_exit": nested_weak_rc,
            "build_weak_exit": build_weak_rc,
            "expired_allowlist_flagged": expired_rc == 1 and "[ALLOWLIST EXPIRED]" in expired_out,
            "form_feed_detected": hidden_hit == [(1, 6, "U+000C")],
            "ordinary_unicode_clean": clean_unicode == [],
        },
        audit=audit,
    )


# --------------------------------------------------------------------------- #
# Family 6: Audit evidence & redaction
# --------------------------------------------------------------------------- #
_MAP_AUDIT = ControlMapping(
    owasp_llm_2025=("LLM02",),
    owasp_agentic_2026=("ASI03",),
    mitre_atlas=("AML.M0024",),
)


def _case_audit_lifecycle_correlation_and_redaction() -> CaseOutcome:
    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp)
        sink = io.StringIO()
        policy = PolicyConfig(
            allowed_mcp_servers=frozenset({"local"}),
            trusted_mcp_servers=frozenset({"local"}),
            tool_risk_tiers={"local/workspace_read": RiskTier.LOW, "local/shell_exec": RiskTier.HIGH},
        )
        auth = Authorizer(workspace_root=ws, policy_config=policy, audit_logger=AuditLogger(sink=sink))
        sid = auth.create_session()

        allow_args = {"path": "README.md"}
        res_allow = auth.authorize(ToolCallRequest(sid, "workspace_read", allow_args, mcp_server="local"))

        deny_args = {"secret": f"sk-proj-{'A' * 32}_{FORBIDDEN_CONFORMANCE_MARKERS[0]}"}
        res_deny = auth.authorize(
            ToolCallRequest(
                FORBIDDEN_CONFORMANCE_MARKERS[1],
                FORBIDDEN_CONFORMANCE_MARKERS[2],
                deny_args,
                mcp_server=FORBIDDEN_CONFORMANCE_MARKERS[3],
            )
        )

        held_args = {"argv": ["pytest", "tests"]}
        res_held = auth.authorize(ToolCallRequest(sid, "shell_exec", held_args, mcp_server="local"))

        auth.mark_tainted(
            sid, TaintSource(source_type="external_doc", origin=f"bearer {FORBIDDEN_CONFORMANCE_MARKERS[0]}")
        )

        raw_jsonl = sink.getvalue()
        records = [json.loads(line) for line in raw_jsonl.splitlines()]

        v_allow = verify_audit_sink(
            raw_jsonl,
            expected_decision="allow",
            expected_arguments=allow_args,
            correlation_id=res_allow.audit_id,
            forbidden_markers=FORBIDDEN_CONFORMANCE_MARKERS,
        )
        v_deny = verify_audit_sink(
            raw_jsonl,
            expected_decision="deny",
            expected_arguments=deny_args,
            correlation_id=res_deny.audit_id,
            forbidden_markers=FORBIDDEN_CONFORMANCE_MARKERS,
        )
        v_held = verify_audit_sink(
            raw_jsonl,
            expected_decision="require_approval",
            expected_arguments=held_args,
            correlation_id=res_held.audit_id,
            forbidden_markers=FORBIDDEN_CONFORMANCE_MARKERS,
        )
        v_taint = verify_audit_sink(
            raw_jsonl,
            expected_decision="tainted",
            expected_arguments=None,
            forbidden_markers=FORBIDDEN_CONFORMANCE_MARKERS,
        )

        all_complete = v_allow.complete and v_deny.complete and v_held.complete and v_taint.complete
        combined_audit = AuditVerification(
            required=True,
            matching_events=len(records),
            decision_matches=v_allow.decision_matches
            and v_deny.decision_matches
            and v_held.decision_matches
            and v_taint.decision_matches,
            argument_digest_matches=v_allow.argument_digest_matches
            and v_deny.argument_digest_matches
            and v_held.argument_digest_matches
            and v_taint.argument_digest_matches,
            synthetic_marker_absent=v_allow.synthetic_marker_absent,
            complete=all_complete and len(records) == 4,
        )
        return CaseOutcome(
            observed={
                "event_count": len(records),
                "decisions": [r["decision"] for r in records],
                "allow_digest_matches": records[0]["args_sha256"] == canonical_args_sha256(allow_args),
                "unknown_identities_hashed": records[1]["session_id"].startswith("unknown_ses:")
                and records[1]["tool_name"].startswith("untrusted_tool:")
                and str(records[1]["mcp_server"]).startswith("untrusted_srv:"),
            },
            audit=combined_audit,
        )


# --------------------------------------------------------------------------- #
# Declarative Case Registry (fast + linux-container)
# --------------------------------------------------------------------------- #
LINUX_AUDIT_ISOLATION_SPEC = CaseSpec(
    case_id="linux-audit-writer-uid-isolation",
    family="audit-evidence-and-redaction",
    control_ids=("TM-06",),
    mappings=_MAP_AUDIT,
    profile="linux-container",
    synthetic_case=(
        "Downstream child UID 10002 (mellyn-mcp) attempts to modify /var/log/mellyn (UID 10001) and gateway /proc"
    ),
    evidence_source="linux_namespace_and_squid_probe",
    expected_summary={
        "child_uid_isolated": True,
        "audit_dir_tamper_blocked": True,
        "proc_environ_blocked": True,
        "sentinel_intact": True,
        "gateway_audit_appended": True,
    },
)

LINUX_NETWORK_EGRESS_SPEC = CaseSpec(
    case_id="linux-internal-network-and-squid-egress",
    family="paths-resources-and-egress",
    control_ids=("TM-02",),
    mappings=_MAP_BOUNDARIES,
    profile="linux-container",
    synthetic_case=(
        "Docker --internal routing denial (ENETUNREACH/EHOSTUNREACH) vs outside listener plus Squid 403/200 checks"
    ),
    evidence_source="linux_namespace_and_squid_probe",
    expected_summary={
        "outside_target_reachable_from_ext": True,
        "direct_internal_egress_routing_denied": True,
        "squid_denied_four_disallowed_vectors": True,
        "squid_allowed_https_allowlist": True,
    },
)

CONFORMANCE_SUITE: tuple[tuple[CaseSpec, Callable[[], CaseOutcome] | None], ...] = (
    (
        CaseSpec(
            case_id="pin-matching-listing-allows-clean-write",
            family="mcp-metadata-and-taint",
            control_ids=("TM-04", "TM-12"),
            mappings=_MAP_MCP_TAINT,
            profile="fast",
            synthetic_case="Pinned tools/list hash matches reviewed metadata, keeping turn-0 clean for peer write",
            evidence_source="audit_jsonl_and_downstream_spy",
            expected_summary={
                "listing_verified": True,
                "session_tainted": False,
                "write_decision": "allow",
                "downstream_calls": 1,
            },
        ),
        _case_pin_matching,
    ),
    (
        CaseSpec(
            case_id="pin-changed-description-blocks-dispatch",
            family="mcp-metadata-and-taint",
            control_ids=("TM-12",),
            mappings=_MAP_MCP_TAINT,
            profile="fast",
            synthetic_case="Change description from 'list notes' to 'list project notes' under pin and call tool",
            evidence_source="audit_jsonl_and_downstream_spy",
            expected_summary={
                "list_denied": True,
                "call_decision": "deny",
                "downstream_calls": 0,
            },
        ),
        _case_pin_mismatch,
    ),
    (
        CaseSpec(
            case_id="unpinned-listing-taints-and-escalates-peer",
            family="mcp-metadata-and-taint",
            control_ids=("TM-01", "TM-11"),
            mappings=_MAP_MCP_TAINT,
            profile="fast",
            synthetic_case="Unpinned untrusted tools/list taints shared session and escalates peer medium write",
            evidence_source="audit_jsonl_and_downstream_spy",
            expected_summary={
                "session_tainted": True,
                "second_server_decision": "require_approval",
                "downstream_calls": 0,
            },
        ),
        _case_unpinned_cross_server_taint,
    ),
    (
        CaseSpec(
            case_id="server-error-taints-while-local-timeout-stays-clean",
            family="mcp-metadata-and-taint",
            control_ids=("TM-16",),
            mappings=_MAP_MCP_TAINT,
            profile="fast",
            synthetic_case="GatewayLocalError timeout keeps session clean, while server JSON-RPC error taints",
            evidence_source="audit_jsonl_and_downstream_spy",
            expected_summary={
                "clean_after_local_timeout": True,
                "tainted_after_server_error": True,
                "second_write_decision": "require_approval",
                "local_write_dispatches": 1,
            },
        ),
        _case_server_error_vs_local_timeout,
    ),
    (
        CaseSpec(
            case_id="protected-file-resource-read",
            family="paths-resources-and-egress",
            control_ids=("TM-03", "TM-15"),
            mappings=_MAP_BOUNDARIES,
            profile="fast",
            synthetic_case="Read ordinary workspace file vs sensitive .env file through MCP resources/read URI",
            evidence_source="audit_jsonl_and_downstream_spy",
            expected_summary={
                "ordinary_resource_allowed": True,
                "decision": "deny",
                "sensitive_downstream_calls": 0,
                "ordinary_downstream_calls": 1,
            },
        ),
        _case_protected_file_resource_read,
    ),
    (
        CaseSpec(
            case_id="protected-ancestor-directory-move-denied",
            family="paths-resources-and-egress",
            control_ids=("TM-05",),
            mappings=_MAP_BOUNDARIES,
            profile="fast",
            synthetic_case="Move parent directory containing a protected child directory even with an explicit grant",
            evidence_source="audit_jsonl_and_downstream_spy",
            expected_summary={
                "decision": "deny",
                "downstream_calls": 0,
            },
        ),
        _case_ancestor_subtree_move_denied,
    ),
    (
        CaseSpec(
            case_id="application-egress-url-allow-and-deny-matrix",
            family="paths-resources-and-egress",
            control_ids=("TM-02",),
            mappings=_MAP_BOUNDARIES,
            profile="fast",
            synthetic_case="Check exact HTTPS domain and subdomain allows vs lookalike suffix, HTTP, and bad port",
            evidence_source="audit_jsonl_and_downstream_spy",
            expected_summary={
                "allowed_passed": 2,
                "denied_blocked": 3,
                "downstream_calls": 2,
            },
        ),
        _case_egress_url_matrix,
    ),
    (
        CaseSpec(
            case_id="role-separation-duplicate-digest-and-redirect-refusal",
            family="human-authority-and-exact-grants",
            control_ids=("TM-08", "TM-14"),
            mappings=_MAP_AUTHORITY,
            profile="fast",
            synthetic_case="Verify agent/approver role split, duplicate digest error, and 302 redirect refusal",
            evidence_source="jsonrpc_protocol_response",
            expected_summary={
                "roles_isolated": True,
                "duplicate_digest_rejected": True,
                "redirect_http_code": 302,
                "transport_calls": 1,
            },
        ),
        _case_role_separation_and_redirect_refusal,
    ),
    (
        CaseSpec(
            case_id="reserved-resource-read-identity-isolation",
            family="human-authority-and-exact-grants",
            control_ids=("TM-12",),
            mappings=_MAP_AUTHORITY,
            profile="fast",
            synthetic_case="Downstream tool named resources/read cannot borrow tier or grant from resources/read",
            evidence_source="audit_jsonl_and_downstream_spy",
            expected_summary={
                "legitimate_resource_read_allowed": True,
                "spoofed_tool_decision": "deny",
                "downstream_tool_calls": 0,
            },
        ),
        _case_reserved_resource_read_identity,
    ),
    (
        CaseSpec(
            case_id="expired-approval-and-exact-grant-bounds",
            family="human-authority-and-exact-grants",
            control_ids=("TM-08", "TM-10"),
            mappings=_MAP_AUTHORITY,
            profile="fast",
            synthetic_case="Expired pending approval refused; one-use grant blocks replay, type, and server drift",
            evidence_source="audit_jsonl_and_downstream_spy",
            expected_summary={
                "expired_approval_refused": True,
                "exact_call_allowed": True,
                "replay_blocked": True,
                "type_drift_blocked": True,
                "server_drift_blocked": True,
                "srv_a_calls": 1,
                "srv_b_calls": 0,
            },
        ),
        _case_expired_approval_and_exact_grant_bounds,
    ),
    (
        CaseSpec(
            case_id="malformed-and-oversized-frames-recover-on-ping",
            family="jsonrpc-framing-and-capacity",
            control_ids=("TM-13",),
            mappings=_MAP_FRAMING,
            profile="fast",
            synthetic_case="Stream malformed JSON, boolean ID, dual reply, and oversized UTF-8 frame then valid ping",
            evidence_source="jsonrpc_protocol_response",
            expected_summary={
                "reply_count": 5,
                "parse_error_code": JSONRPC_PARSE_ERROR,
                "bool_id_error_code": JSONRPC_INVALID_REQUEST,
                "dual_envelope_error_code": DOWNSTREAM_ERROR,
                "oversized_error_code": JSONRPC_INVALID_REQUEST,
                "recovery_ping_ok": True,
                "downstream_calls": 1,
            },
        ),
        _case_framing_errors_and_recovery,
    ),
    (
        CaseSpec(
            case_id="duplicate-package-lock-conflicting-and-missing-integrity",
            family="manifest-and-scanner-integrity",
            control_ids=(),
            mappings=_MAP_SUPPLY_CHAIN,
            profile="fast",
            synthetic_case="Duplicate package-lock paths pass with matching digests and fail on conflict or absence",
            evidence_source="scanner_cli_result",
            expected_summary={
                "valid_exit": 0,
                "conflict_exit": 1,
                "conflict_flagged": True,
                "missing_exit": 1,
                "missing_flagged": True,
            },
        ),
        _case_lockfile_duplicate_and_missing_integrity,
    ),
    (
        CaseSpec(
            case_id="nested-manifest-build-requires-expired-allowlist-and-unicode",
            family="manifest-and-scanner-integrity",
            control_ids=(),
            mappings=_MAP_SUPPLY_CHAIN,
            profile="fast",
            synthetic_case="Pair valid nested pyproject/emoji fixtures against weak floors, expired waiver, and U+000C",
            evidence_source="scanner_cli_result",
            expected_summary={
                "valid_manifest_exit": 0,
                "nested_weak_exit": 1,
                "build_weak_exit": 1,
                "expired_allowlist_flagged": True,
                "form_feed_detected": True,
                "ordinary_unicode_clean": True,
            },
        ),
        _case_nested_manifest_build_deps_and_unicode,
    ),
    (
        CaseSpec(
            case_id="correlated-audit-lifecycle-and-canary-absence",
            family="audit-evidence-and-redaction",
            control_ids=("TM-06", "TM-09"),
            mappings=_MAP_AUDIT,
            profile="fast",
            synthetic_case="Correlate allow, deny, held, and taint JSONL events by audit_id with zero canary leaks",
            evidence_source="audit_jsonl_and_downstream_spy",
            expected_summary={
                "event_count": 4,
                "decisions": ["allow", "deny", "require_approval", "tainted"],
                "allow_digest_matches": True,
                "unknown_identities_hashed": True,
            },
        ),
        _case_audit_lifecycle_correlation_and_redaction,
    ),
    (LINUX_AUDIT_ISOLATION_SPEC, None),
    (LINUX_NETWORK_EGRESS_SPEC, None),
)


def execute_conformance_profile(profile: str = "fast") -> EvidenceRecorder:
    """Execute all conformance cases matching `profile` and record `not_run` for other profiles."""
    recorder = EvidenceRecorder(execution_profile=profile, forbidden_markers=FORBIDDEN_CONFORMANCE_MARKERS)
    for spec, fn in CONFORMANCE_SUITE:
        if spec.profile != profile or fn is None:
            recorder.run_case(spec, lambda: CaseOutcome(observed={}, audit=non_audit_verification()))
        else:
            recorder.run_case(spec, fn)
    return recorder
