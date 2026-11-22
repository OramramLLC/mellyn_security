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
  or a gateway started with `python -m aegis_ai.mcp_gateway` on the host. Those keep full network access.
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
python -c "import secrets; print(secrets.token_urlsafe(32))"   # put this in AEGIS_API_KEY_PEPPER
PYTHONPATH=backend python -m aegis_ai.credentials              # run twice: agent key, approver key
```

Store only the **digests** in `.env`. The gateway never passes `AEGIS_*` variables to the MCP servers it launches.
Never give the approver key to the agent runtime.

### 2. Point the stack at the agent's workspace

```bash
export MELLYN_WORKSPACE=/absolute/path/to/the/workspace
```

Compose refuses to start without it. The authorizer mounts it read-only and refuses to start if `/workspace` is not
a mount point (`AEGIS_REQUIRE_WORKSPACE_MOUNT=1`): otherwise its path guard would resolve symlinks against an empty
directory and could not see a link that points at a secret.

### 3. Sync the egress proxy config from your policy

```bash
PYTHONPATH=backend python -m aegis_ai.egress_proxy \
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
PYTHONPATH=backend python -m aegis_ai.approve --url http://127.0.0.1:8765 list
PYTHONPATH=backend python -m aegis_ai.approve --url http://127.0.0.1:8765 approve apr_... --by you@example.com
```

Running on the host keeps the raw approver key completely outside `mellyn-gateway`'s container process tree (`mellyn-approval-relay` does not mount `.env` and holds zero credentials). If you prefer not to run Python on the host, you can also run `docker exec -it mellyn-gateway python -m aegis_ai.approve --url http://127.0.0.1:8765 ...` (or pipe the key with `docker exec -i ... --key-stdin`); never pass the key via `docker exec -e`.

---

## Tested

On 2026-11-22 the stack was built and run on Docker Desktop (Windows, engine 29.9): both images built (hash-pinned
install, Squid 6.14 from the Ubuntu archive), Squid ran as `proxy` with every capability dropped, `/healthz` answered
on `127.0.0.1:8000`, the authorizer refused to start without a policy or without a mounted workspace, and a symlink in
the mounted workspace pointing at `/etc/passwd` was denied. From the internal network: no direct route out, only
CONNECT to allowlisted domains on 443, IP literals and private/metadata destinations refused, plain HTTP refused, and
clients outside the internal subnet refused. Through the gateway container: an MCP server saw no `AEGIS_*` variables,
fetched an allowlisted URL, was blocked by Squid for a domain the application layer allowed, could not connect
directly, and a held call was approved with `docker exec` and then ran once.

## Supply chain

- Base images are pinned by digest (`Dockerfile`, `egress/Dockerfile`).
- Python packages, including transitive ones, come from `requirements.lock`, installed with `--require-hashes`.
  Every release in it was published before 2026-10-22.
- Squid is installed from the Ubuntu 24.04 archive at build time (the `ubuntu/squid` image only ships edge/beta
  channels and its 24.04 tag had not been rebuilt in a year). Rebuild regularly to pick up security updates.
