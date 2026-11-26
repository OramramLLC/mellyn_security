# Security Policy

## Supported Versions

| Version | Supported | Notes |
| :--- | :--- | :--- |
| `1.0.x` | Yes | Core MCP runtime release (`src/mellyn/`, `deploy/`) |
| `< 1.0` | No | Pre-release development snapshots |

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for suspected security vulnerabilities.**

Please report security findings privately through **GitHub Security Advisories** (`Security` tab -> `Report a vulnerability`) on the repository.

When reporting an issue, please include:
1. Affected component (e.g., `src/mellyn/` or `deploy/`).
2. Clear reproduction steps or a minimal proof-of-concept showing how a fail-closed boundary, AgBOM/tool pin, taint/grant invariant, egress filter, or AAD containment control can be bypassed.
3. Exact version/commit SHA and runtime environment (OS, Python version, Docker or local mode).

You can expect an initial acknowledgment within **3 business days** and a coordinated status update as the fix and regression tests are prepared.

---

## Security Boundaries & Non-Negotiable Invariants

Mellyn Security assumes the connected LLM or agent loop is **inside the blast radius of indirect prompt injection** and enforces deterministic authorization boundaries at the tool-execution layer. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full asset, trust-boundary, and `TM-01`–`TM-16` / `AL-01`–`AL-06` control traceability matrix.

Key security commitments in `1.0.0`:
- **Fail-Closed Defaults**: Unknown session IDs, malformed JSON-RPC frames, unpinned tools, corrupt/schema-mismatched SQLite state DBs, missing policy files, or unconfigured API credentials refuse execution rather than falling back open.
- **Role & Secret Separation**: `Role.AGENT`, `Role.APPROVER`, and `Role.VIEWER` credentials are stored exclusively as `HMAC-SHA256(pepper, key)` digests and checked in constant time; downstream MCP servers never inherit `MELLYN_*` environment variables (or configured OAuth secret env names) and run under an unprivileged UID (`mellyn-mcp`, `10002`) in container deployments.
- **Redact-Before-Disk Telemetry**: `src/mellyn/core/audit.py` and `src/mellyn/audit.py` compute payload digests first and redact secrets and canaries before writing structured JSONL logs or SQLite taint entries. One deliberate exception: a live human grant in the SQLite state database keeps the exact approved arguments and `approved_by` label unredacted, because a grant must match its call exactly. Spent and expired grants are deleted, and the database is created `0600` in a `0700` folder.
- **Detection Is a Tripwire, Not a Boundary**: Canary and secret detection compares content against known encodings. Ciphers, compression, homoglyphs, and pieces split across separate calls are out of scope (see the sibling `mellyn-redteam` repository for adversarial evasion scorecards); network egress isolation and least-privilege tool policy are the controls that keep data in.
- **Out-of-Scope Expectations**: Workstation deployments outside the container stack receive application-layer URL/egress enforcement without the kernel network namespace + Squid proxy layer; probabilistic injection/DLP scores act strictly as risk-escalating signals, never allow gates.
