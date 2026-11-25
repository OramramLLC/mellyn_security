# Mellyn Security — Self-Hosted MCP Tool-Call Authorizer / MCP Gateway image
# Runs as a non-root user. The base image is pinned by digest and every Python package (including transitive
# dependencies) is installed from a hash-pinned lockfile, so a rebuild cannot silently pull new code.
#
# The image serves two roles (see deploy/docker-compose.yml):
#   - mellyn-authorizer: the HTTP authorization API (default CMD)
#   - mellyn-gateway:    the stdio MCP gateway; extend this image with your MCP servers (see deploy/README.md)
#
# No policy is baked in: mount one at MELLYN_POLICY_PATH, or the API refuses to start (fail closed).

# python:3.12.15-slim-bookworm, published 2026-10-21. Bump the tag and digest together.
FROM python:3.12.15-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/backend \
    MELLYN_POLICY_PATH=/etc/mellyn/policy.toml \
    MELLYN_WORKSPACE_ROOT=/workspace \
    MELLYN_REQUIRE_WORKSPACE_MOUNT=1 \
    MELLYN_AUDIT_LOG_PATH=/var/log/mellyn/audit.jsonl \
    MELLYN_STATE_DB_PATH=/var/lib/mellyn/state.db

WORKDIR /app

# Dedicated non-root identities:
#   - mellyn (10001): runs the authorizer/gateway and owns /var/log/mellyn and /var/lib/mellyn (mode 0700)
#   - mellyn-mcp (10002): unprivileged identity for downstream MCP child servers (zero access to /var/log/mellyn or state)
RUN groupadd --gid 10001 mellyn \
    && useradd --uid 10001 --gid 10001 --shell /usr/sbin/nologin --create-home mellyn \
    && groupadd --gid 10002 mellyn-mcp \
    && useradd --uid 10002 --gid 10002 --shell /usr/sbin/nologin --create-home mellyn-mcp \
    && mkdir -p /var/log/mellyn /var/lib/mellyn /etc/mellyn /workspace \
    && chown mellyn:mellyn /var/log/mellyn /var/lib/mellyn \
    && chmod 0700 /var/log/mellyn \
    && chmod 0700 /var/lib/mellyn

COPY deploy/requirements.lock /tmp/requirements.lock
RUN python -m pip install --no-cache-dir --disable-pip-version-check --require-hashes --no-deps \
        -r /tmp/requirements.lock \
    && rm /tmp/requirements.lock

COPY --chown=root:root backend/ /app/backend/

USER mellyn

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"]

CMD ["uvicorn", "--factory", "mellyn.api:create_app_from_env", "--host", "0.0.0.0", "--port", "8000"]
