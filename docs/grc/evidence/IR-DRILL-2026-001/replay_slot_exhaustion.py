"""IR-DRILL-2026-001 replay: approval-channel slot exhaustion, pre-patch vs post-patch.

Usage: python replay_slot_exhaustion.py <tree-with-src> <label>
Prints one JSON object per observation (UTC timestamps) to stdout. Loopback only; writes nothing to the repo.
"""

from __future__ import annotations

import json
import secrets
import socket
import sys
import tempfile
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

TREE, LABEL = Path(sys.argv[1]).resolve(), sys.argv[2]
sys.path.insert(0, str(TREE / "src"))

import mellyn  # noqa: E402
from mellyn.approvals import ApprovalHTTPServer, PendingApprovals  # noqa: E402
from mellyn.authorizer import Authorizer  # noqa: E402
from mellyn.credentials import CredentialConfig, Role, key_digest  # noqa: E402

T0 = time.monotonic()


def log(event: str, **fields: object) -> None:
    record = {
        "drill": "IR-DRILL-2026-001",
        "tree": LABEL,
        "utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z",
        "t_plus_s": round(time.monotonic() - T0, 2),
        "event": event,
        **fields,
    }
    print(json.dumps(record), flush=True)


def approver_request(port: int, key: str) -> str:
    request = (
        f"GET /v1/pending HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Mellyn-API-Key: {key}\r\nConnection: close\r\n\r\n"
    ).encode()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5.0) as sock:
            sock.sendall(request)
            reply = sock.recv(64)
    except OSError as exc:
        return f"<{type(exc).__name__}>"
    return reply.split(b"\r\n", 1)[0].decode("latin-1") if reply else "<closed without reply>"


def main() -> None:
    log("tree_loaded", mellyn_module=str(Path(mellyn.__file__).relative_to(TREE)))
    pepper, key = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    creds = CredentialConfig.from_env(
        {"MELLYN_API_KEY_PEPPER": pepper, "MELLYN_APPROVER_KEY_DIGEST": key_digest(key, pepper)},
        roles=frozenset({Role.APPROVER}),
    )
    with tempfile.TemporaryDirectory() as tmp:
        server = ApprovalHTTPServer(PendingApprovals(Authorizer(workspace_root=Path(tmp))), creds, max_connections=2)
        server.start_in_background()
        port = server.server_address[1]
        log("approval_server_started", max_connections=2)
        log("baseline_approver_request", status=approver_request(port, key))
        time.sleep(1.0)  # let the baseline handler thread finish and release its slot

        stop = threading.Event()

        def trickle(n: int) -> None:
            sock = socket.create_connection(("127.0.0.1", port))
            sock.sendall(b"GET /v1/pending HTTP/1.1\r\n")
            log("attacker_connected", client=n)
            try:
                while not stop.is_set():
                    sock.sendall(b"X-Slow: a\r\n")  # one header line every 4 s; never finishes the request
                    stop.wait(4.0)
                    sock.settimeout(0.05)
                    try:
                        if sock.recv(1, socket.MSG_PEEK) == b"":
                            raise ConnectionResetError("server closed the connection")
                    except TimeoutError:
                        pass  # nothing to read: the server is still holding the connection open
                    finally:
                        sock.settimeout(None)
            except (OSError, ValueError) as exc:
                log("attacker_connection_closed_by_server", client=n, error=type(exc).__name__)
                return
            finally:
                sock.close()
            log("attacker_still_holding_slot_at_end", client=n)

        for n in range(2):
            threading.Thread(target=trickle, args=(n,), daemon=True).start()
        time.sleep(0.5)

        for at in (14.0, 34.0):
            time.sleep(max(0.0, at - (time.monotonic() - T0)))
            log("approver_request", status=approver_request(port, key))

        stop.set()
        time.sleep(0.5)
        server.shutdown()
        server.server_close()
        log("drill_finished")


if __name__ == "__main__":
    main()
