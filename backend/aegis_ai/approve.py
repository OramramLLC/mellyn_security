"""
Approver CLI for the MCP gateway's local approval server.

    python -m aegis_ai.approve --url http://127.0.0.1:PORT list
    python -m aegis_ai.approve --url http://127.0.0.1:PORT approve apr_... --by you@example.com [--max-uses N]
    python -m aegis_ai.approve --url http://127.0.0.1:PORT reject apr_...

The URL can also come from AEGIS_APPROVAL_URL. The approver key is read from AEGIS_APPROVER_KEY, or prompted
for without echo. The key is only ever sent to a loopback http:// URL (the gateway's approval server binds to
127.0.0.1), so a mistyped or planted URL cannot carry it off the machine.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

from aegis_ai.approvals import API_KEY_HEADER

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def validate_approval_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "http" or parsed.hostname not in LOOPBACK_HOSTS or parsed.username or parsed.password:
        raise ValueError("The approval URL must be http://127.0.0.1:<port> (loopback only).")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("The approval URL must not include a path, query, or fragment.")
    return f"http://{parsed.netloc}"


def _call(base_url: str, key: str, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - base_url is restricted to loopback http by validate_approval_url
        base_url + path, data=data, method=method, headers={API_KEY_HEADER: key, "Content-Type": "application/json"}
    )
    # No proxies: urllib would otherwise honor HTTP_PROXY and hand the approver key to whatever it names.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=10) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        with exc:
            detail = json.loads(exc.read() or b"{}").get("error", exc.reason)
        raise SystemExit(f"Approval server refused the request ({exc.code}): {detail}") from None


PR_SET_DUMPABLE = 4


def _make_undumpable() -> bool:
    """
    On Linux, mark this process non-dumpable before reading the approver key. In the container deployment the
    CLI runs (via `docker exec`) in the same container and as the same user as the MCP servers the gateway
    launched; non-dumpable stops them reading this process's memory or /proc/<pid>/environ. Returns True when
    applied. Elsewhere it is a no-op.
    """
    if not sys.platform.startswith("linux"):
        return False
    import ctypes

    try:
        libc = ctypes.CDLL(None, use_errno=True)
        return libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0
    except (OSError, AttributeError):
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Approve or reject tool calls held by the Mellyn MCP gateway.")
    parser.add_argument("--url", default=os.environ.get("AEGIS_APPROVAL_URL", ""), help="Approval server URL")
    parser.add_argument(
        "--key-stdin",
        action="store_true",
        help="Read the approver key as one line from stdin instead of AEGIS_APPROVER_KEY or a TTY prompt",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="Show calls waiting for approval")
    approve = sub.add_parser("approve", help="Approve one exact call")
    approve.add_argument("approval_id")
    approve.add_argument("--by", required=True, help="Who is approving (recorded in the audit log)")
    approve.add_argument("--max-uses", type=int, default=1)
    approve.add_argument("--ttl", type=int, default=900, help="Seconds the approval stays valid")
    reject = sub.add_parser("reject", help="Discard a pending call")
    reject.add_argument("approval_id")
    args = parser.parse_args(argv)

    try:
        base_url = validate_approval_url(args.url)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    _make_undumpable()
    if args.key_stdin:
        key = sys.stdin.readline().rstrip("\r\n")
    else:
        key = os.environ.get("AEGIS_APPROVER_KEY") or getpass.getpass("Approver key: ")

    if args.command == "list":
        pending = _call(base_url, key, "GET", "/v1/pending")["pending"]
        if not pending:
            print("No calls are waiting for approval.")
        for item in pending:
            print(f"{item['approval_id']}  {item['mcp_server']}/{item['tool_name']}  (session {item['session_id']})")
            print(f"    arguments: {json.dumps(item['arguments'], sort_keys=True)}")
            for reason in item["reasons"]:
                print(f"    - {reason}")
    elif args.command == "approve":
        body = {"approved_by": args.by, "max_uses": args.max_uses, "ttl_seconds": args.ttl}
        result = _call(base_url, key, "POST", f"/v1/pending/{args.approval_id}/approve", body)
        print(f"Approved {args.approval_id}: grant {result['grant_id']}, expires {result['expires_at']}.")
    else:
        _call(base_url, key, "POST", f"/v1/pending/{args.approval_id}/reject", {})
        print(f"Rejected {args.approval_id}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
