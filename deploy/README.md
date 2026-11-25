# Mellyn Security — Self-Hosted Deployment Guide

This stack runs the **Mellyn Security authorizer**, the **MCP gateway** and a **policy-synced Squid egress proxy** on
your own host or VPC. Prompts, secrets, and audit logs stay in your environment.

---

## What the egress proxy does and does not cover

```text
MCP client (IDE) ──stdio── docker compose run mellyn-gateway
                              │  mellyn-internal (internal: true, no internet route)
                              ├─ gateway + the MCP servers it launches
                              │      every outbound connection ──► mellyn-egress (Squid) ──► internet
                              │                                    CONNECT :443 only, allowlisted domains,
                              │                                    private / metadata IPs blocked
mellyn-authorizer (HTTP API, 127.0.0.1:8000) — for custom harnesses; makes no outbound calls itself
```

- **Covered:** tools that run *inside* the gateway container. The internal network has no route out, so they
  can only reach the internet through Squid, whether or not they honour `HTTPS_PROXY`.
- **Not covered:** anything that runs on the developer machine itself: MCP servers the IDE launches directly,
  or a gateway started with `python -m mellyn.mcp_gateway` on the host. Those keep full network access.
- **DNS rebinding, as tested (2026-11-22, Squid 6.14):** Squid checks the resolved address against the blocked ranges
  and then connects using the same cached answer. Names that resolve to private addresses (`10.0.0.1.nip.io`,
  `169.254.169.254.nip.io`, ...) were refused. A name whose DNS answer flips between `127.0.0.1` and `1.1.1.1` on every
  lookup (TTL 0) was refused whenever Squid's cached answer was private and connected to `1.1.1.1` otherwise; in 64
  attempts it never connected to the private address. That is strong evidence, not a proof for every Squid version.

---

## Setup

### 1. Credentials (two separate roles)

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(32))"   # put this in MELLYN_API_KEY_PEPPER
PYTHONPATH=backend python -m mellyn.credentials              # run twice: agent key, approver key
```

Store only the **digests** in `.env`. The gateway never passes `MELLYN_*` variables to the MCP servers it launches.
Never give the approver key to the agent runtime.

> **Upgrading from a pre-rename deployment:** every variable now uses the `MELLYN_` prefix. The authorizer
> and the gateway refuse to start while any variable with the old `AEGIS` prefix is still set, and name each
> one to rename, so old settings are never silently ignored. The gateway also strips both prefixes from the
> environment of every MCP server it launches.

### 2. Point the stack at the agent's workspace

```bash
export MELLYN_WORKSPACE=/absolute/path/to/the/workspace
```

Compose refuses to start without it. The authorizer mounts it read-only and refuses to start if `/workspace` is not
a mount point (`MELLYN_REQUIRE_WORKSPACE_MOUNT=1`): otherwise its path guard would resolve symlinks against an empty
directory and could not see a link that points at a secret.

**Linux hosts: give the MCP servers access to the workspace.** Inside the gateway container, MCP servers run as
the `mellyn-mcp` user (UID `10002`), not as you. On Docker Desktop (Windows, macOS) bind mounts are usually
writable by any container user, but on a Linux host the workspace keeps its host ownership, so a filesystem MCP
server will get "permission denied" until UID 10002 is allowed in. Grant exactly that, rather than opening the
directory to everyone:

```bash
setfacl -R -m u:10002:rwX -m d:u:10002:rwX "$MELLYN_WORKSPACE"   # read/write for 10002, inherited by new files
```

(Without ACL support, `chgrp -R 10002` plus `chmod -R g+rwX` and the setgid bit on directories does the same.)
Read-only MCP servers only need `u:10002:rX`.

### 3. Sync the egress proxy config from your policy

```bash
PYTHONPATH=backend python -m mellyn.egress_proxy \
  --policy config/mellyn-policy.example.toml \
  --output deploy/egress/squid.conf
```

Only clients on `mellyn-internal` (`172.30.250.0/24`) may use the proxy. If you change that subnet in
`docker-compose.yml`, pass the same value with `--client-cidr`.

### 4. Start the authorizer and the egress proxy

```bash
docker compose -f deploy/docker-compose.yml up -d --build
curl -fsS http://127.0.0.1:8000/healthz
```

`mellyn-authorizer` stores durable SQLite session, taint, and single-use grant state in `MELLYN_STATE_DB_PATH`
(`/var/lib/mellyn/state.db`), backed by the dedicated `mellyn-authorizer-state` volume (`0700` owned by `mellyn`
UID `10001`, separate from audit log volumes and never mounted on `mellyn-gateway`).

### 5. Run the MCP gateway from your MCP client

Build an image that adds your MCP servers to the base image, and list their commands in
`config/mellyn-gateway.example.toml`:

```dockerfile
FROM mellyn-security:local
USER root
RUN python -m pip install --no-cache-dir --require-hashes -r /path/to/your-mcp-servers.lock
USER mellyn
```

Then set `MELLYN_GATEWAY_IMAGE` to that image and configure the MCP client to launch the gateway, **and remove the
servers from the client's own MCP config** so it cannot reach them directly:

```json
{
  "command": "docker",
  "args": ["compose", "-f", "/abs/path/deploy/docker-compose.yml", "--profile", "gateway",
           "run", "--rm", "-T", "--name", "mellyn-gateway", "mellyn-gateway"]
}
```

### 6. Approve held calls

`mellyn-approval-relay` publishes `127.0.0.1:8765` on the host and forwards **only** the three exact approval routes (`GET /v1/pending` and `POST /v1/pending/apr_.../(approve|reject)`) to `mellyn-gateway:8765` across `mellyn-internal`—keeping `mellyn-gateway` completely cut off from direct internet routes while letting you run the approver CLI directly on the host:

```bash
PYTHONPATH=backend python -m mellyn.approve --url http://127.0.0.1:8765 list
PYTHONPATH=backend python -m mellyn.approve --url http://127.0.0.1:8765 approve apr_... --by you@example.com
```

Running on the host keeps the raw approver key completely outside `mellyn-gateway`'s container process tree (`mellyn-approval-relay` does not mount `.env` and holds zero credentials). Inside `mellyn-gateway`, downstream MCP servers run under the dedicated unprivileged `mellyn-mcp` (`10002`) UID while the gateway drops to `mellyn` (`10001`), keeping `/var/log/mellyn` (`0700`, mounted from its own isolated `mellyn-gateway-audit-logs` volume) inaccessible to child MCP processes. If you prefer not to run Python on the host, run `docker exec -it -u mellyn mellyn-gateway python -m mellyn.approve --url http://127.0.0.1:8765 ...` (or pipe the key with `docker exec -i -u mellyn ... --key-stdin`); never pass the key via `docker exec -e`.

### 7. Start the approval relay without a detached gateway (`--profile relay`)

To start `mellyn-approval-relay` alongside `mellyn-authorizer` and `mellyn-egress` before your MCP client launches `mellyn-gateway` (step 5), use `--profile relay`:

```bash
docker compose -f deploy/docker-compose.yml --profile relay up -d --build
```

Do not add `--profile gateway` to `up -d`: the MCP client starts `mellyn-gateway` per session (`compose run ...`), and a second detached gateway would answer to the same `mellyn-gateway` DNS alias, causing the relay to deliver approvals to whichever container DNS picks.

---

## Tested

On 2026-11-22 the stack was built and run on Docker Desktop (Windows, engine 29.9): both images built (hash-pinned
install, Squid 6.14 from the Ubuntu archive), Squid ran as `proxy` with every capability dropped, `/healthz` answered
on `127.0.0.1:8000`, the authorizer refused to start without a policy or without a mounted workspace, and a symlink in
the mounted workspace pointing at `/etc/passwd` was denied. From the internal network: no direct route out, only
CONNECT to allowlisted domains on 443, IP literals and private/metadata destinations refused, plain HTTP refused, and
clients outside the internal subnet refused. Through the gateway container: an MCP server saw no `MELLYN_*` variables,
fetched an allowlisted URL, was blocked by Squid for a domain the application layer allowed, could not connect
directly, and a held call was approved with `docker exec` and then ran once.

## Supply chain

- Base images are pinned by digest (`Dockerfile`, `deploy/egress/Dockerfile`).
- Python packages, including transitive ones, come from `deploy/requirements.lock`, installed with `--require-hashes`.
  Every release in it was published before 2026-10-22.
- Squid is installed from the Ubuntu 24.04 archive at build time (the `ubuntu/squid` image only ships edge/beta
  channels and its 24.04 tag had not been rebuilt in a year). Rebuild regularly to pick up security updates.
