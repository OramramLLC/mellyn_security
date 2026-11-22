# Mellyn Security — egress proxy image (Squid from the Ubuntu 24.04 archive)
#
# Built locally instead of using ubuntu/squid: that image only publishes edge/beta channels, and its 24.04
# tag had not been rebuilt for a year. Installing squid from the Ubuntu archive at build time picks up the
# archive's security updates; the base image is pinned by digest.
#
# Squid runs directly as the unprivileged `proxy` user (no root start-up step), so the container can drop
# every capability. squid.conf is generated from the policy by `python -m mellyn.egress_proxy`.

# ubuntu:noble-20260930.1, published 2026-10-17. Bump the tag and digest together.
FROM ubuntu:noble-20260930.1@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac

RUN apt-get update \
    && apt-get install -y --no-install-recommends squid \
    && rm -rf /var/lib/apt/lists/*

USER proxy

EXPOSE 3128

ENTRYPOINT ["squid", "-N", "-f", "/etc/squid/squid.conf"]
