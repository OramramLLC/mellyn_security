"""
Outbound redacted approval alert webhooks (Slack, Microsoft Teams, and generic JSON).

Security invariants:
  - One-way outbound only (no inbound Slack/Teams webhook listener attack surface).
  - Never includes argument values or argument key names (the agent chooses both, so either would be a channel
    out of the workspace and into the approvers' chat); carries `arguments_sha256`, the argument count, the tool
    and server reduced to identifier characters, redacted reasons, and an optional Console deep link.
  - The webhook URL is a bearer credential: it is read from an environment variable (never `mellyn.toml`), may
    only point at the declared `webhook_host`, and that variable is withheld from downstream MCP servers.
  - Zero HTTP redirects (`build_safe_opener`), strict HTTPS/egress-allowlist enforcement, Squid routing,
    bounded non-blocking single-worker queue, and redacted webhook URL logging to `stderr` only.
"""

from __future__ import annotations

import collections
import json
import math
import os
import queue
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from mellyn.audit import hash_arguments, redact_text
from mellyn.egress import EgressValidator
from mellyn.egress_proxy import validate_egress_domain
from mellyn.oauth_client import (
    OAuthError,
    _validate_env_var_name,
    build_safe_opener,
    read_bounded_bytes,
    validate_outbound_url,
)
from mellyn.scanner import redact_canaries_in_text

if TYPE_CHECKING:
    from mellyn.approvals import PendingApproval

WebhookFormatSetting = Literal["auto", "slack", "teams", "generic"]
ResolvedWebhookFormat = Literal["slack", "teams", "generic"]

MAX_WEBHOOK_RESPONSE_BYTES = 16_384
MIN_WEBHOOK_TIMEOUT_SECONDS = 1.0
MAX_WEBHOOK_TIMEOUT_SECONDS = 30.0
DEFAULT_WEBHOOK_TIMEOUT_SECONDS = 5.0
DEFAULT_WEBHOOK_QUEUE_SIZE = 64

MAX_ALERT_REASONS = 3
MAX_ALERT_REASON_CHARS = 200
MAX_ALERT_ID_CHARS = 64

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_STOP_SENTINEL = object()
# Tool names on an unpinned server are whatever the agent sends, so labels keep identifier characters only: no
# brackets, parentheses, colons, slashes or dots, which is what a chat client needs to render or autolink a link
# (Slack and Teams link a bare `name.tld`). The approver reads the exact call in the Console, not in the alert.
_UNSAFE_LABEL_CHARS_RE = re.compile(r"[^A-Za-z0-9_-]")
DEFAULT_MAX_ALERTS_PER_MINUTE = 30


def _scrub_text(raw: Any, *, canary_tokens: Sequence[str] = (), max_chars: int = MAX_ALERT_REASON_CHARS) -> str:
    text = _CONTROL_CHARS_RE.sub(" ", str(raw)).strip()
    if canary_tokens:
        text = redact_canaries_in_text(text, canary_tokens)
    text = redact_text(text)
    return text[:max_chars]


def _safe_label(raw: Any) -> str:
    """Reduce an agent-influenced identifier (tool or server name) to `[A-Za-z0-9_-]`, at most 64 characters."""
    return _UNSAFE_LABEL_CHARS_RE.sub("?", str(raw))[:MAX_ALERT_ID_CHARS] or "unknown"


def _neutralize_teams_markdown(text: str) -> str:
    """Adaptive Card TextBlocks and FactSet values render Markdown: break link, autolink and HTML syntax."""
    return text.replace("[", "(").replace("]", ")").replace("<", "‹").replace(">", "›").replace("://", ":∕∕")


def _escape_slack_mrkdwn(text: str) -> str:
    """Neutralize Slack `mrkdwn` link/mention/code sequences in untrusted dynamic fields."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("`", "'")


def redact_webhook_url(raw_url: str) -> str:
    """Return `scheme://host[:port]/[REDACTED]` so webhook paths/tokens never appear in logs or reprs."""
    try:
        parsed = urllib.parse.urlparse(raw_url.strip())
    except ValueError:
        return "[REDACTED_WEBHOOK]"
    scheme = parsed.scheme.lower() or "https"
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        return "[REDACTED_WEBHOOK]"
    host_fmt = f"[{host}]" if ":" in host else host
    try:
        port = parsed.port
    except ValueError:
        port = None
    netloc = f"{host_fmt}:{port}" if port is not None else host_fmt
    return f"{scheme}://{netloc}/[REDACTED]"


def validate_console_base_url(raw_url: str) -> str:
    """
    Validate `[notifications].console_base_url` used for approval alert deep links.

    Requires `https://` on public domains (rejecting `.local`, `.localhost`, IP literals, query strings,
    fragments, userinfo, and invalid ports), while allowing `http://` for local loopback Console testing.
    """
    if not isinstance(raw_url, str) or not raw_url.strip() or _CONTROL_CHARS_RE.search(raw_url):
        raise ValueError("notifications.console_base_url must be a non-empty URL without control characters.")
    trimmed = raw_url.strip()
    try:
        parsed = urllib.parse.urlparse(trimmed)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Malformed notifications.console_base_url authority or port.") from exc

    if parsed.params or parsed.query or parsed.fragment:
        raise ValueError("notifications.console_base_url must not contain query parameters or fragments.")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise ValueError("notifications.console_base_url must not contain embedded credentials/userinfo.")

    hostport = parsed.netloc
    if "]" in hostport:
        _, _, after_bracket = hostport.rpartition("]")
        has_colon_port = ":" in after_bracket
    else:
        has_colon_port = ":" in hostport
    if has_colon_port and (port is None or port <= 0):
        raise ValueError("notifications.console_base_url specifies an empty or invalid port.")

    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").strip().lower().rstrip(".")
    if not hostname:
        raise ValueError("notifications.console_base_url is missing a valid hostname.")

    is_loopback = hostname in ("127.0.0.1", "localhost", "::1")
    if is_loopback:
        if scheme not in ("http", "https"):
            raise ValueError("notifications.console_base_url must use https or loopback http.")
    else:
        if scheme != "https":
            raise ValueError("notifications.console_base_url must use https:// for non-loopback hosts.")
        if hostname.endswith(".localhost") or hostname.endswith(".local"):
            raise ValueError(f"Disallowed .local/.localhost host '{hostname}' in notifications.console_base_url.")
        if EgressValidator._is_ip_literal(hostname):
            raise ValueError("Direct non-loopback IP literals are forbidden in notifications.console_base_url.")
        hostname = validate_egress_domain(hostname)

    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        port = None
    host_fmt = f"[{hostname}]" if ":" in hostname else hostname
    netloc = f"{host_fmt}:{port}" if port is not None else host_fmt
    clean_path = parsed.path.rstrip("/")
    return f"{scheme}://{netloc}{clean_path}"


@dataclass(frozen=True)
class NotificationsConfig:
    """Configuration for optional outbound approval webhook notifications (`[notifications]`)."""

    approval_webhook_url: str | None = None
    approval_webhook_url_env: str | None = None
    webhook_format: WebhookFormatSetting = "auto"
    console_base_url: str | None = None
    timeout_seconds: float = DEFAULT_WEBHOOK_TIMEOUT_SECONDS
    webhook_host: str | None = None
    allow_insecure_loopback_for_tests: bool = False

    def __post_init__(self) -> None:
        if self.approval_webhook_url is not None and self.approval_webhook_url_env is not None:
            raise ValueError("Specify either approval_webhook_url or approval_webhook_url_env, not both.")
        if self.webhook_format not in ("auto", "slack", "teams", "generic"):
            raise ValueError(
                f"Unsupported webhook_format {self.webhook_format!r}; expected 'auto', 'slack', 'teams', or 'generic'."
            )
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, int | float)
            or not math.isfinite(float(self.timeout_seconds))
            or not MIN_WEBHOOK_TIMEOUT_SECONDS <= float(self.timeout_seconds) <= MAX_WEBHOOK_TIMEOUT_SECONDS
        ):
            raise ValueError(
                f"notifications.timeout_seconds must be between "
                f"{MIN_WEBHOOK_TIMEOUT_SECONDS} and {MAX_WEBHOOK_TIMEOUT_SECONDS}."
            )
        object.__setattr__(self, "timeout_seconds", float(self.timeout_seconds))

        if self.approval_webhook_url is not None:
            validated = validate_outbound_url(
                self.approval_webhook_url,
                allow_loopback_http=self.allow_insecure_loopback_for_tests,
            )
            object.__setattr__(self, "approval_webhook_url", validated)

        if self.approval_webhook_url_env is not None:
            clean_env = _validate_env_var_name(self.approval_webhook_url_env, "notifications.approval_webhook_url_env")
            object.__setattr__(self, "approval_webhook_url_env", clean_env)

        # The destination host is declared rather than read from the secret: it is what the gateway may reach
        # (Squid included), and a URL swapped in the environment cannot send alerts anywhere else.
        literal_url = self.approval_webhook_url
        literal_host = (urllib.parse.urlparse(literal_url).hostname or "").lower().rstrip(".") if literal_url else None
        if self.webhook_host is not None:
            if not self.enabled:
                raise ValueError("notifications.webhook_host needs notifications.approval_webhook_url_env.")
            if not isinstance(self.webhook_host, str) or not self.webhook_host.strip():
                raise ValueError("notifications.webhook_host must be a non-empty host name.")
            clean_host = self.webhook_host.strip().lower().rstrip(".")
            if not (self.allow_insecure_loopback_for_tests and clean_host in ("127.0.0.1", "localhost")):
                clean_host = validate_egress_domain(clean_host)
            if literal_host is not None and literal_host != clean_host:
                raise ValueError("notifications.webhook_host does not match approval_webhook_url's host.")
            object.__setattr__(self, "webhook_host", clean_host)
        elif self.approval_webhook_url_env is not None:
            raise ValueError(
                "notifications.approval_webhook_url_env needs notifications.webhook_host (for example "
                "'hooks.slack.com'): the gateway sends alerts only to that host."
            )
        elif literal_host:
            object.__setattr__(self, "webhook_host", literal_host)

        if self.console_base_url is not None:
            object.__setattr__(self, "console_base_url", validate_console_base_url(self.console_base_url))

    @property
    def enabled(self) -> bool:
        return self.approval_webhook_url is not None or self.approval_webhook_url_env is not None

    @property
    def secret_env_names(self) -> tuple[str, ...]:
        """Environment variables holding a notification secret, which downstream servers must not inherit."""
        return (self.approval_webhook_url_env,) if self.approval_webhook_url_env else ()

    def __repr__(self) -> str:
        url_repr = redact_webhook_url(self.approval_webhook_url) if self.approval_webhook_url else None
        return (
            f"NotificationsConfig(approval_webhook_url={url_repr!r}, "
            f"approval_webhook_url_env={self.approval_webhook_url_env!r}, "
            f"webhook_format={self.webhook_format!r}, "
            f"webhook_host={self.webhook_host!r}, "
            f"console_base_url={self.console_base_url!r}, "
            f"timeout_seconds={self.timeout_seconds!r})"
        )


@dataclass(frozen=True)
class ApprovalAlertSummary:
    """Redacted summary of a held tool call safe to post to an external chat webhook."""

    approval_id: str
    session_id: str
    audit_id: str
    mcp_server: str | None
    tool_name: str
    mcp_method: str | None
    arguments_sha256: str
    argument_count: int
    reasons: tuple[str, ...]
    created_at: str
    console_url: str | None


def build_approval_alert_summary(
    pending: PendingApproval,
    *,
    console_base_url: str | None = None,
    canary_tokens: Sequence[str] = (),
) -> ApprovalAlertSummary:
    """
    Build a strictly redacted alert summary from a `PendingApproval`.

    Argument values and key names never leave the host: the agent chooses both, so either would carry data out of
    the workspace and put the agent's text in front of approvers. Only `arguments_sha256` and the count do.
    """
    safe_reasons = tuple(
        _scrub_text(reason, canary_tokens=canary_tokens, max_chars=MAX_ALERT_REASON_CHARS)
        for reason in pending.reasons[:MAX_ALERT_REASONS]
    )
    safe_server = _safe_label(pending.mcp_server) if pending.mcp_server is not None else None
    safe_tool = _safe_label(_scrub_text(pending.tool_name, canary_tokens=canary_tokens, max_chars=1024))
    safe_method = (
        _scrub_text(pending.mcp_method, canary_tokens=canary_tokens, max_chars=MAX_ALERT_ID_CHARS)
        if pending.mcp_method is not None
        else None
    )
    approval_id = _scrub_text(pending.approval_id, canary_tokens=canary_tokens, max_chars=MAX_ALERT_ID_CHARS)
    console_url = f"{console_base_url.rstrip('/')}/approvals/{approval_id}" if console_base_url else None
    created_str = (
        pending.created_at.isoformat() if hasattr(pending.created_at, "isoformat") else str(pending.created_at)
    )
    return ApprovalAlertSummary(
        approval_id=approval_id,
        session_id=_scrub_text(pending.session_id, canary_tokens=canary_tokens, max_chars=MAX_ALERT_ID_CHARS),
        audit_id=_scrub_text(pending.audit_id, canary_tokens=canary_tokens, max_chars=MAX_ALERT_ID_CHARS),
        mcp_server=safe_server,
        tool_name=safe_tool,
        mcp_method=safe_method,
        arguments_sha256=hash_arguments(pending.arguments),
        argument_count=len(pending.arguments),
        reasons=safe_reasons,
        created_at=_scrub_text(created_str, canary_tokens=canary_tokens, max_chars=MAX_ALERT_ID_CHARS),
        console_url=console_url,
    )


def resolve_webhook_format(configured: WebhookFormatSetting, webhook_url: str) -> ResolvedWebhookFormat:
    """Resolve `auto` formatting from destination webhook host or honor explicit setting."""
    if configured != "auto":
        return configured
    host = (urllib.parse.urlparse(webhook_url.strip()).hostname or "").strip().lower().rstrip(".")
    if host in ("hooks.slack.com", "hooks.slack-gov.com"):
        return "slack"
    if host.endswith(".webhook.office.com") or host.endswith(".logic.azure.com"):
        return "teams"
    return "generic"


def format_webhook_payload(
    summary: ApprovalAlertSummary,
    *,
    fmt: ResolvedWebhookFormat,
    canary_tokens: Sequence[str] = (),
) -> dict[str, Any]:
    """Render an already-redacted `ApprovalAlertSummary` into Slack, Teams, or generic JSON payload."""

    def _defense_scrub(text: str) -> str:
        return _scrub_text(text, canary_tokens=canary_tokens, max_chars=MAX_ALERT_REASON_CHARS)

    target_label = f"{summary.mcp_server}/{summary.tool_name}" if summary.mcp_server else summary.tool_name
    count_label = str(summary.argument_count)
    reasons_clean = [_defense_scrub(r) for r in summary.reasons if r]

    if fmt == "slack":
        target_esc = _escape_slack_mrkdwn(_defense_scrub(target_label))
        server_esc = _escape_slack_mrkdwn(_defense_scrub(summary.mcp_server or "local"))
        approval_esc = _escape_slack_mrkdwn(_defense_scrub(summary.approval_id))
        session_esc = _escape_slack_mrkdwn(_defense_scrub(summary.session_id))
        digest_esc = summary.arguments_sha256[:16]
        reason_lines = "\n".join(f"- {_escape_slack_mrkdwn(r)}" for r in reasons_clean) or "- Policy requires approval."
        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "Mellyn Security: Approval Required"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Tool:*\n`{target_esc}`"},
                    {"type": "mrkdwn", "text": f"*Server:*\n`{server_esc}`"},
                    {"type": "mrkdwn", "text": f"*Approval ID:*\n`{approval_esc}`"},
                    {"type": "mrkdwn", "text": f"*Session:*\n`{session_esc}`"},
                    {"type": "mrkdwn", "text": f"*Args SHA-256:*\n`{digest_esc}...`"},
                    {"type": "mrkdwn", "text": f"*Arguments:*\n`{count_label}`"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Reason(s):*\n{reason_lines}"},
            },
        ]
        if summary.console_url is not None:
            blocks.append(
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Review in Mellyn Console"},
                            "style": "primary",
                            "url": summary.console_url,
                        }
                    ],
                }
            )
        return {
            "text": f"Mellyn Security approval required: {target_esc} ({approval_esc})",
            "blocks": blocks,
        }

    if fmt == "teams":

        def _teams(text: str) -> str:
            return _neutralize_teams_markdown(_defense_scrub(text))

        facts = [
            {"title": "Tool", "value": _teams(target_label)},
            {"title": "Approval ID", "value": _teams(summary.approval_id)},
            {"title": "Session", "value": _teams(summary.session_id)},
            {"title": "Audit ID", "value": _teams(summary.audit_id)},
            {"title": "Args SHA-256", "value": summary.arguments_sha256[:16]},
            {"title": "Arguments", "value": count_label},
        ]
        card_body: list[dict[str, Any]] = [
            {
                "type": "TextBlock",
                "text": "Mellyn Security: Human Approval Required",
                "weight": "Bolder",
                "size": "Medium",
                "wrap": True,
            },
            {"type": "FactSet", "facts": facts},
            {
                "type": "TextBlock",
                "text": _neutralize_teams_markdown("; ".join(reasons_clean)) or "Policy requires approval.",
                "wrap": True,
            },
        ]
        card: dict[str, Any] = {
            "type": "AdaptiveCard",
            "version": "1.4",
            "body": card_body,
        }
        if summary.console_url is not None:
            card["actions"] = [
                {
                    "type": "Action.OpenUrl",
                    "title": "Review in Mellyn Console",
                    "url": summary.console_url,
                }
            ]
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": None,
                    "content": card,
                }
            ],
        }

    payload: dict[str, Any] = {
        "event": "mellyn.approval_required",
        "approval_id": _defense_scrub(summary.approval_id),
        "session_id": _defense_scrub(summary.session_id),
        "audit_id": _defense_scrub(summary.audit_id),
        "mcp_server": _defense_scrub(summary.mcp_server) if summary.mcp_server is not None else None,
        "tool_name": _defense_scrub(summary.tool_name),
        "mcp_method": _defense_scrub(summary.mcp_method) if summary.mcp_method is not None else None,
        "arguments_sha256": summary.arguments_sha256,
        "argument_count": summary.argument_count,
        "reasons": reasons_clean,
        "created_at": _defense_scrub(summary.created_at),
    }
    if summary.console_url is not None:
        payload["console_url"] = summary.console_url
    return payload


class ApprovalWebhookNotifier:
    """Bounded async/sync webhook dispatcher that fails cleanly to `stderr` and never leaks secrets."""

    def __init__(
        self,
        config: NotificationsConfig,
        *,
        allowed_domains: frozenset[str] | None = None,
        canary_tokens: Sequence[str] = (),
        proxy_url: str | None = None,
        ssl_context: ssl.SSLContext | None = None,
        max_queue: int = DEFAULT_WEBHOOK_QUEUE_SIZE,
        max_alerts_per_minute: int = DEFAULT_MAX_ALERTS_PER_MINUTE,
    ) -> None:
        if max_queue <= 0:
            raise ValueError("max_queue must be positive.")
        if max_alerts_per_minute <= 0:
            raise ValueError("max_alerts_per_minute must be positive.")
        self.config = config
        self.allowed_domains = allowed_domains
        self.canary_tokens = tuple(canary_tokens)
        self._opener = build_safe_opener(
            proxy_url=proxy_url,
            ssl_context=ssl_context,
            bypass_ambient_proxy=config.allow_insecure_loopback_for_tests and proxy_url is None,
        )
        self._queue: queue.Queue[Any] = queue.Queue(maxsize=max_queue)
        self._lock = threading.Lock()
        self._worker: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._closed = False
        # A tainted agent can raise a new held call whenever an old one expires; cap how often approvers are paged.
        self._max_alerts_per_minute = max_alerts_per_minute
        self._recent_alerts: collections.deque[float] = collections.deque()
        self._suppressed = 0

    def _resolve_target_url(self) -> str | None:
        if self.config.approval_webhook_url is not None:
            raw_url = self.config.approval_webhook_url
        elif self.config.approval_webhook_url_env is not None:
            raw_url = os.environ.get(self.config.approval_webhook_url_env, "").strip()
            if not raw_url:
                print(
                    f"Approval webhook skipped: env var '{self.config.approval_webhook_url_env}' is unset.",
                    file=sys.stderr,
                )
                return None
        else:
            return None

        redacted = redact_webhook_url(raw_url)
        try:
            validated = validate_outbound_url(
                raw_url,
                allowed_domains=self.allowed_domains,
                allow_loopback_http=self.config.allow_insecure_loopback_for_tests,
            )
        except ValueError as exc:
            print(f"Approval webhook rejected ({redacted}): {exc}", file=sys.stderr)
            return None
        host = (urllib.parse.urlparse(validated).hostname or "").lower().rstrip(".")
        if self.config.webhook_host is None or host != self.config.webhook_host:
            print(
                f"Approval webhook rejected ({redacted}): its host is not notifications.webhook_host "
                f"({self.config.webhook_host!r}).",
                file=sys.stderr,
            )
            return None
        return validated

    def deliver(self, pending: PendingApproval) -> bool:
        """Synchronously build, redact, validate, and POST one approval alert webhook."""
        target_url = self._resolve_target_url()
        if target_url is None:
            return False

        redacted = redact_webhook_url(target_url)
        summary = build_approval_alert_summary(
            pending,
            console_base_url=self.config.console_base_url,
            canary_tokens=self.canary_tokens,
        )
        fmt = resolve_webhook_format(self.config.webhook_format, target_url)
        payload = format_webhook_payload(summary, fmt=fmt, canary_tokens=self.canary_tokens)
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        req = urllib.request.Request(  # noqa: S310 - validated outbound HTTPS/test URL
            target_url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with self._opener.open(req, timeout=self.config.timeout_seconds) as resp:  # noqa: S310 - validated URL
                read_bounded_bytes(resp, max_bytes=MAX_WEBHOOK_RESPONSE_BYTES)
                status = int(getattr(resp, "status", resp.getcode()))
            if 200 <= status < 300:
                return True
            print(f"Approval webhook POST {redacted} returned HTTP {status}.", file=sys.stderr)
            return False
        except urllib.error.HTTPError as exc:
            code = exc.code
            exc.close()
            print(f"Approval webhook POST {redacted} failed with HTTP {code}.", file=sys.stderr)
            return False
        except (OAuthError, urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            print(f"Approval webhook POST {redacted} failed ({type(exc).__name__}).", file=sys.stderr)
            return False

    def _worker_loop(self) -> None:
        while True:
            try:
                item = self._queue.get(timeout=0.2)
            except queue.Empty:
                if self._stop_event.is_set():
                    return
                continue
            try:
                if item is _STOP_SENTINEL:
                    return
                self.deliver(item)
            except Exception as exc:  # noqa: BLE001 - worker must never crash silently or disrupt gateway
                print(f"Approval webhook worker error ({type(exc).__name__}).", file=sys.stderr)
            finally:
                self._queue.task_done()

    def _ensure_worker_locked(self) -> None:
        if self._worker is None and not self._closed:
            worker = threading.Thread(target=self._worker_loop, name="mellyn-webhook-notifier", daemon=True)
            worker.start()
            self._worker = worker

    def on_new_pending(self, pending: PendingApproval) -> None:
        """`PendingApprovals(on_new_pending=...)` hook: queue an alert, ignoring whether it was queued."""
        self.notify_async(pending)

    def notify_async(self, pending: PendingApproval) -> bool:
        """Enqueue an approval alert for background delivery; drops cleanly if the queue is full."""
        if not self.config.enabled:
            return False
        with self._lock:
            if self._closed:
                return False
            now = time.monotonic()
            while self._recent_alerts and now - self._recent_alerts[0] >= 60.0:
                self._recent_alerts.popleft()
            if len(self._recent_alerts) >= self._max_alerts_per_minute:
                self._suppressed += 1
                if self._suppressed == 1 or self._suppressed % 100 == 0:
                    print(
                        f"Approval webhook rate limit ({self._max_alerts_per_minute}/min) reached; "
                        f"{self._suppressed} alert(s) suppressed so far. Check the approval queue directly.",
                        file=sys.stderr,
                    )
                return False
            self._recent_alerts.append(now)
            self._ensure_worker_locked()
            try:
                self._queue.put_nowait(pending)
                return True
            except queue.Full:
                print(
                    f"Approval webhook queue full; dropping alert for {pending.approval_id}.",
                    file=sys.stderr,
                )
                return False

    def close(self, timeout: float = 2.0) -> None:
        """Drain queued approval alerts up to `timeout` seconds and join the worker thread."""
        with self._lock:
            self._closed = True
            self._stop_event.set()
            worker = self._worker
        if worker is None:
            return
        try:
            self._queue.put(_STOP_SENTINEL, timeout=min(0.5, max(0.05, timeout)))
        except queue.Full:
            pass
        worker.join(timeout=timeout)


__all__ = [
    "ApprovalAlertSummary",
    "ApprovalWebhookNotifier",
    "DEFAULT_MAX_ALERTS_PER_MINUTE",
    "DEFAULT_WEBHOOK_QUEUE_SIZE",
    "DEFAULT_WEBHOOK_TIMEOUT_SECONDS",
    "MAX_WEBHOOK_RESPONSE_BYTES",
    "MAX_WEBHOOK_TIMEOUT_SECONDS",
    "MIN_WEBHOOK_TIMEOUT_SECONDS",
    "NotificationsConfig",
    "ResolvedWebhookFormat",
    "WebhookFormatSetting",
    "build_approval_alert_summary",
    "format_webhook_payload",
    "redact_webhook_url",
    "resolve_webhook_format",
    "validate_console_base_url",
]
