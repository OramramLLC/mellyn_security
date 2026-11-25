"""FastAPI HTTP adapter for the Mellyn Security Self-Hosted MCP Tool-Call Authorizer."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import IO, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from mellyn.audit import AuditLogger
from mellyn.authorizer import MAX_GRANT_TTL_SECONDS, MAX_GRANT_USES, Authorizer, SessionLimitError
from mellyn.credentials import CredentialConfig, CredentialConfigError, Role
from mellyn.egress import check_workspace_root
from mellyn.legacy_env import check_no_legacy_env
from mellyn.models import RiskSignals, TaintSource, ToolCallRequest, canonical_json
from mellyn.policy import PolicyConfig
from mellyn.state_store import AuthorizerStateStore, SqliteStateStore, StateStoreError
from mellyn.unified_config import load_policy_any

MAX_ARGUMENTS_BYTES = 64 * 1024
_STRICT = ConfigDict(extra="forbid", strict=True)


class RiskSignalsPayload(BaseModel):
    model_config = _STRICT

    injection_score: float = Field(default=0.0, ge=0.0, le=1.0)
    dlp_secret_detected: bool = False
    notes: list[str] = Field(default_factory=list, max_length=20)


class AuthorizePayload(BaseModel):
    model_config = _STRICT

    session_id: str = Field(min_length=1, max_length=128)
    tool_name: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)
    mcp_server: str | None = Field(default=None, max_length=128)
    signals: RiskSignalsPayload = Field(default_factory=RiskSignalsPayload)


class TaintPayload(BaseModel):
    model_config = _STRICT

    source_type: str = Field(min_length=1, max_length=64)
    origin: str = Field(min_length=1, max_length=512)


class GrantPayload(BaseModel):
    model_config = _STRICT

    tool_name: str = Field(min_length=1, max_length=128)
    mcp_server: str | None = Field(default=None, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)
    approved_by: str = Field(min_length=1, max_length=128)
    ttl_seconds: int = Field(default=900, ge=1, le=MAX_GRANT_TTL_SECONDS)
    max_uses: int = Field(default=1, ge=1, le=MAX_GRANT_USES)


def _check_arguments_size(arguments: dict[str, Any]) -> None:
    if len(canonical_json(arguments).encode("utf-8")) > MAX_ARGUMENTS_BYTES:
        # Literal 413: the named constant differs across Starlette versions.
        raise HTTPException(status_code=413, detail="Tool arguments too large.")


def create_app(
    workspace_root: Path | None = None,
    policy_config: PolicyConfig | None = None,
    credentials: CredentialConfig | None = None,
    audit_logger: AuditLogger | None = None,
    state_store: AuthorizerStateStore | None = None,
    *,
    _owned_sink: IO[str] | None = None,
    _owned_state_store: AuthorizerStateStore | None = None,
) -> FastAPI:
    """
    Build the FastAPI application wrapping an Authorizer instance.

    Credentials come from the environment unless passed in. If they are missing or malformed the app
    still starts, but every route except /healthz answers 503 (fail closed).
    """

    @asynccontextmanager
    async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            try:
                if _owned_state_store is not None:
                    _owned_state_store.close()
            finally:
                if _owned_sink is not None and not _owned_sink.closed:
                    _owned_sink.close()

    app = FastAPI(title="Mellyn Security MCP Tool-Call Authorizer", version="1.0.0", lifespan=_lifespan)
    authorizer = Authorizer(
        workspace_root=workspace_root or Path.cwd(),
        policy_config=policy_config,
        audit_logger=audit_logger,
        state_store=state_store,
    )

    @app.exception_handler(StateStoreError)
    def _handle_state_store_error(_request: Request, _exc: StateStoreError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": "Authorizer state store unavailable (fail-closed)."},
        )

    loaded: CredentialConfig | None = credentials
    if loaded is None:
        try:
            loaded = CredentialConfig.from_env()
        except CredentialConfigError:
            loaded = None

    def require(role: Role) -> Callable[..., None]:
        def dependency(x_mellyn_api_key: str | None = Header(default=None)) -> None:
            if loaded is None:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Gateway credentials are not configured (fail-closed).",
                )
            if not x_mellyn_api_key:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing X-Mellyn-API-Key header.")
            if not loaded.verify(x_mellyn_api_key, role):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Key is not valid for this route.")

        return dependency

    agent_only = [Depends(require(Role.AGENT))]
    approver_only = [Depends(require(Role.APPROVER))]

    def known_session(session_id: str) -> None:
        if not authorizer.has_session(session_id):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown session.")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        """Public health check (the only unauthenticated route)."""
        return {"status": "ok"}

    @app.post("/v1/sessions", dependencies=agent_only, status_code=status.HTTP_201_CREATED)
    def create_session() -> dict[str, Any]:
        try:
            session_id = authorizer.create_session()
        except SessionLimitError as exc:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc
        return {"session_id": session_id, "tainted": False}

    @app.post("/v1/agent/authorize", dependencies=agent_only)
    def authorize_tool_call(payload: AuthorizePayload) -> dict[str, Any]:
        _check_arguments_size(payload.arguments)
        request = ToolCallRequest(
            session_id=payload.session_id,
            tool_name=payload.tool_name,
            arguments=payload.arguments,
            mcp_server=payload.mcp_server,
            signals=RiskSignals(
                injection_score=payload.signals.injection_score,
                dlp_secret_detected=payload.signals.dlp_secret_detected,
                notes=tuple(payload.signals.notes),
            ),
        )
        result = authorizer.authorize(request)
        return {
            "decision": result.decision.value,
            "risk_tier": result.risk_tier.value,
            "tainted": result.tainted,
            "reasons": list(result.reasons),
            "policy_id": result.policy_id,
            "grant_id": result.grant_id,
            "audit_id": result.audit_id,
        }

    @app.post("/v1/sessions/{session_id}/taint", dependencies=agent_only)
    def taint_session(session_id: str, payload: TaintPayload) -> dict[str, Any]:
        known_session(session_id)
        authorizer.mark_tainted(session_id, TaintSource(source_type=payload.source_type, origin=payload.origin))
        return {"session_id": session_id, "tainted": True}

    @app.post("/v1/sessions/{session_id}/grants", dependencies=approver_only, status_code=status.HTTP_201_CREATED)
    def create_grant(session_id: str, payload: GrantPayload) -> dict[str, Any]:
        known_session(session_id)
        _check_arguments_size(payload.arguments)
        grant = authorizer.issue_grant(
            session_id=session_id,
            tool_name=payload.tool_name,
            mcp_server=payload.mcp_server,
            arguments=payload.arguments,
            approved_by=payload.approved_by,
            ttl_seconds=payload.ttl_seconds,
            max_uses=payload.max_uses,
        )
        return {
            "grant_id": grant.grant_id,
            "session_id": grant.session_id,
            "tool_name": grant.tool_name,
            "max_uses": grant.max_uses,
            "expires_at": grant.expires_at.isoformat(),
        }

    return app


def create_app_from_env() -> FastAPI:
    """
    Uvicorn ASGI factory for self-hosted container deployments.

    Reads:
      MELLYN_POLICY_PATH     optional path to a .toml/.json policy file (fails closed on error)
      MELLYN_WORKSPACE_ROOT  optional workspace root directory (defaults to cwd); must be an existing directory
      MELLYN_REQUIRE_WORKSPACE_MOUNT  "1" = refuse to start unless the workspace root is a mount point. Set in
                            the container image: without the agent's real workspace mounted, the path guard
                            resolves links against an empty directory and cannot see where they lead.
      MELLYN_AUDIT_LOG_PATH  optional append-only JSONL file path for redacted audit events
      MELLYN_STATE_DB_PATH   optional SQLite file path for persistent sessions, taint, and single-use grants
    """
    check_no_legacy_env()  # a half-migrated deployment must not start with its old settings silently ignored
    policy_path_raw = os.environ.get("MELLYN_POLICY_PATH", "").strip()
    # Either a v1 policy file or a v2 mellyn.toml: `mellyn init --unified` points MELLYN_POLICY_PATH at the latter.
    policy_config = load_policy_any(Path(policy_path_raw)) if policy_path_raw else None

    workspace_raw = os.environ.get("MELLYN_WORKSPACE_ROOT", "").strip()
    workspace_root = Path(workspace_raw) if workspace_raw else Path.cwd()
    check_workspace_root(workspace_root, require_mount=os.environ.get("MELLYN_REQUIRE_WORKSPACE_MOUNT") == "1")

    audit_path_raw = os.environ.get("MELLYN_AUDIT_LOG_PATH", "").strip()
    audit_logger: AuditLogger | None = None
    sink: IO[str] | None = None
    state_store: SqliteStateStore | None = None
    if audit_path_raw:
        audit_path = Path(audit_path_raw)
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        sink = audit_path.open("a", encoding="utf-8")
        audit_logger = AuditLogger(sink=sink)

    try:
        state_db_raw = os.environ.get("MELLYN_STATE_DB_PATH", "").strip()
        if state_db_raw:
            state_store = SqliteStateStore(Path(state_db_raw))
        return create_app(
            workspace_root=workspace_root,
            policy_config=policy_config,
            audit_logger=audit_logger,
            state_store=state_store,
            _owned_sink=sink,
            _owned_state_store=state_store,
        )
    except Exception:
        try:
            if state_store is not None:
                state_store.close()
        finally:
            if sink is not None and not sink.closed:
                sink.close()
        raise
