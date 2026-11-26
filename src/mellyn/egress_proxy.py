"""
Policy-synced network egress proxy configuration generator for Mellyn Security.

Renders a hardened Squid forward-proxy config from `PolicyConfig.allowed_egress_domains`. It enforces
Threat Model TM-02 (SSRF, DNS rebinding, cross-host redirects) at the network layer only for traffic that
cannot bypass it: in deploy/docker-compose.yml the MCP gateway and its servers sit on an internal network
whose only way out is this proxy. Tools running directly on a developer machine are not covered.

Usage:
    python -m mellyn.egress_proxy \
        --policy config/mellyn-policy.example.toml \
        --output deploy/egress/squid.conf
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from collections.abc import Iterable
from pathlib import Path

from mellyn.policy import PolicyConfig
from mellyn.policy_loader import PolicyLoadError

# Strict RFC 1035 / 1123 hostname (at least one dot, lowercase labels, no wildcards/spaces/newlines)
_VALID_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

# Private, loopback, link-local, CGNAT, cloud-metadata, and IPv6 local/ULA CIDRs
# blocked at DNS resolution / connect time to defeat DNS rebinding (TM-02).
BLOCKED_DESTINATION_CIDRS: tuple[str, ...] = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
)


def validate_egress_domain(domain: str) -> str:
    """Normalize and strictly validate a domain for inclusion in Squid ACLs (prevents directive injection)."""
    if not isinstance(domain, str):
        raise ValueError("Egress domain must be a string.")
    normalized = domain.strip().lower().lstrip(".")
    if not _VALID_DOMAIN_RE.fullmatch(normalized):
        raise ValueError(
            f"Invalid egress domain '{domain}': must be a valid public DNS hostname (no IPs, wildcards, or whitespace)."
        )
    if normalized == "localhost" or normalized.endswith(".localhost") or normalized.endswith(".local"):
        raise ValueError(f"Local/loopback domain '{domain}' is forbidden in egress allowlists.")
    return normalized


# The mellyn-internal subnet in deploy/docker-compose.yml. Only these clients may use the proxy.
DEFAULT_CLIENT_CIDRS: tuple[str, ...] = ("172.30.250.0/24",)
REGENERATE_HINT = "python -m mellyn.egress_proxy --policy <policy.toml> --output deploy/egress/squid.conf"


def generate_squid_config(
    policy: PolicyConfig,
    *,
    listen_port: int = 3128,
    client_cidrs: tuple[str, ...] = DEFAULT_CLIENT_CIDRS,
    gateway_domains: Iterable[str] = (),
) -> str:
    """
    Render a hardened, fail-closed Squid egress proxy config from PolicyConfig.

    `gateway_domains` are hosts only the gateway process should contact (remote MCP servers and their OAuth
    hosts). They are not in the tool policy, so the authorizer refuses tool calls aimed at them, but Squid cannot
    tell the gateway from the MCP servers it launches in the same container, so they are reachable at the network
    layer.
    """
    if not 1 <= listen_port <= 65535:
        raise ValueError("listen_port must be between 1 and 65535.")
    if not client_cidrs:
        raise ValueError("At least one client CIDR is required.")
    clients = [str(ipaddress.ip_network(cidr, strict=True)) for cidr in client_cidrs]

    domains = sorted(validate_egress_domain(d) for d in policy.allowed_egress_domains)
    gw_domains = sorted({validate_egress_domain(d) for d in gateway_domains} - set(domains))

    lines: list[str] = [
        "# GENERATED FILE — Mellyn Security Network Egress Proxy (Squid)",
        f"# Regenerate from policy: {REGENERATE_HINT}",
        "#",
        "# Enforces Threat Model TM-02 at the network layer:",
        "#   1. HTTPS CONNECT on port 443 only (no plaintext HTTP, no arbitrary ports).",
        "#   2. Blocks all RFC1918, loopback, CGNAT, cloud-metadata (169.254.169.254), and IPv6 ULA/link-local",
        "#      destinations AFTER DNS resolution to defeat DNS rebinding.",
        "#   3. Denies direct IP literals and every domain not explicitly allowlisted.",
        "",
        f"http_port {listen_port}",
        "pid_filename /tmp/squid.pid",
        "coredump_dir /tmp",
        "pinger_enable off",
        "cache deny all",
        "cache_log stdio:/dev/stderr",
        "access_log stdio:/dev/stdout squid",
        "via off",
        "forwarded_for delete",
        "httpd_suppress_version_string on",
        "",
        "# Only the internal agent network may use the proxy",
        *[f"acl mellyn_clients src {cidr}" for cidr in clients],
        "http_access deny !mellyn_clients",
        "",
        "# Restrict allowed ports and methods strictly to HTTPS tunneling (CONNECT :443)",
        "acl SSL_ports port 443",
        "acl CONNECT method CONNECT",
        "http_access deny !CONNECT",
        "http_access deny !SSL_ports",
        "",
        "# Reject raw IPv4/IPv6 literals in the request host",
        r"acl raw_ip_host url_regex -i ^([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]+)?$ ^\[?[0-9a-f:]+\]?(:[0-9]+)?$",
        "http_access deny raw_ip_host",
        "",
        "# Block private, loopback, link-local, and cloud-metadata IPs at connect time (anti-DNS-rebinding)",
    ]

    for cidr in BLOCKED_DESTINATION_CIDRS:
        lines.append(f"acl blocked_dst dst {cidr}")
    lines.append("http_access deny blocked_dst")
    lines.append("")

    if domains:
        lines.append("# Policy-synced domain allowlist (exact domain and subdomains)")
        for domain in domains:
            lines.append(f"acl allowed_domains dstdomain .{domain}")
        lines.append("http_access allow CONNECT SSL_ports allowed_domains")
    else:
        lines.append("# Policy has no allowed_egress_domains; failing closed (all outbound traffic denied).")

    if gw_domains:
        lines.append("")
        lines.append("# Gateway-only hosts (remote MCP servers and their OAuth hosts): NOT in the tool policy, so the")
        lines.append("# authorizer refuses tool calls to them, but processes on the gateway's network can reach them.")
        for domain in gw_domains:
            lines.append(f"acl gateway_domains dstdomain {domain}")
        lines.append("http_access allow CONNECT SSL_ports gateway_domains")

    lines.append("")
    lines.append("# Default deny everything else (fail closed)")
    lines.append("http_access deny all")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate Mellyn Security Squid egress proxy config from policy.")
    parser.add_argument("--policy", type=Path, required=True, help="Path to Mellyn policy (.toml or .json)")
    parser.add_argument("--output", type=Path, help="Output squid.conf path (prints to stdout if omitted)")
    parser.add_argument("--port", type=int, default=3128, help="Squid listen port (default: 3128)")
    parser.add_argument(
        "--client-cidr",
        action="append",
        help=f"Subnet allowed to use the proxy (repeatable; default: {', '.join(DEFAULT_CLIENT_CIDRS)})",
    )
    args = parser.parse_args(argv)

    from mellyn.unified_config import load_gateway_egress_domains_any, load_policy_any

    try:
        policy = load_policy_any(args.policy)
        rendered = generate_squid_config(
            policy,
            listen_port=args.port,
            client_cidrs=tuple(args.client_cidr or DEFAULT_CLIENT_CIDRS),
            gateway_domains=load_gateway_egress_domains_any(args.policy),
        )
    except (PolicyLoadError, ValueError) as exc:
        print(f"Egress config generation failed: {exc}", file=sys.stderr)
        return 2

    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
        print(f"Wrote policy-synced egress config to {args.output}")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
