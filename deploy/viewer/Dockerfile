# Mellyn Security — Plane 4 Posture, Forensic Audit & Approval Viewer image
# Multi-stage, non-root, digest-pinned build:
#   - Stage 1 builds the Vite + React + TypeScript SPA with `npm ci --ignore-scripts` from `frontend/package-lock.json`.
#   - Stage 2 copies the compiled `dist/` bundle into the same digest-pinned Python 3.12 runtime and hash-pinned
#     dependencies (`deploy/requirements.lock`) used by the authorizer/gateway image.
#
# Security defaults:
#   - Runs as dedicated non-root `mellyn` UID/GID 10001 (matches root Dockerfile so the `:ro` mount of the mode-0700
#     gateway audit volume stays readable without loosening permissions).
#   - Binds 0.0.0.0 only with `--allow-non-loopback` so Docker can publish 127.0.0.1:8080:8080; still rejects
#     unexpected `Host` headers (421) and requires `Role.VIEWER` / `Role.APPROVER` API keys.

# node:22.21.1-bookworm-slim, digest-pinned build stage
FROM node:22.21.1-bookworm-slim@sha256:25b3eb23a00590b7499f2a2ce939322727fcce1b15fdd69754fcd09536a3ae2c AS frontend-builder

WORKDIR /build/frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund

COPY frontend/tsconfig.json frontend/vite.config.ts frontend/index.html ./
COPY frontend/src/ ./src/
RUN npm run build

# python:3.12.15-slim-bookworm, published 2026-10-21. Keep in sync with root Dockerfile.
FROM python:3.12.15-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/backend:/app/src

WORKDIR /app

# Match UID/GID 10001 from root Dockerfile and pre-create mount points for `:ro` audit/evidence volumes.
RUN groupadd --gid 10001 mellyn \
    && useradd --uid 10001 --gid 10001 --shell /usr/sbin/nologin --create-home mellyn \
    && mkdir -p /var/log/mellyn/gateway /var/lib/mellyn/evidence \
    && chown mellyn:mellyn /var/log/mellyn/gateway /var/lib/mellyn/evidence \
    && chmod 0700 /var/log/mellyn/gateway /var/lib/mellyn/evidence

COPY deploy/requirements.lock /tmp/requirements.lock
RUN python -m pip install --no-cache-dir --disable-pip-version-check --require-hashes --no-deps \
        -r /tmp/requirements.lock \
    && rm /tmp/requirements.lock

COPY --chown=root:root backend/ /app/backend/
COPY --chown=root:root src/ /app/src/
COPY --from=frontend-builder --chown=root:root /build/frontend/dist/ /app/frontend/dist/

USER mellyn

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/v1/healthz', timeout=3)"]

CMD ["python", "-m", "mellyn.viewer_server", "--listen-host", "0.0.0.0", "--allow-non-loopback", "--listen-port", "8080", "--static-dir", "/app/frontend/dist"]
