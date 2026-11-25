import { useMemo, useState } from "react";
import type { GatewayAuditEvent } from "../types.ts";
import { StatusBadge, toneForSeverity } from "./StatusBadge.tsx";

interface GatewayAuditTabProps {
  events: GatewayAuditEvent[];
  totalLines: number;
  malformedLines: number;
  chainValid: boolean | null;
  chainReason: string | null;
}

export function GatewayAuditTab({
  events,
  totalLines,
  malformedLines,
  chainValid,
  chainReason,
}: GatewayAuditTabProps) {
  const [decisionFilter, setDecisionFilter] = useState<string>("all");
  const [taintOnly, setTaintOnly] = useState<boolean>(false);
  const [search, setSearch] = useState<string>("");

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    const targetDecision = decisionFilter.toLowerCase();
    return [...events]
      .reverse()
      .filter((ev) => decisionFilter === "all" || ev.decision.toLowerCase() === targetDecision)
      .filter((ev) => !taintOnly || ev.tainted)
      .filter((ev) => {
        if (!q) return true;
        return (
          ev.tool_name.toLowerCase().includes(q) ||
          (ev.mcp_server ?? "").toLowerCase().includes(q) ||
          ev.session_id.toLowerCase().includes(q) ||
          ev.reasons.join(" ").toLowerCase().includes(q)
        );
      });
  }, [events, decisionFilter, taintOnly, search]);

  return (
    <div className="stack-lg">
      <section className="card">
        <div className="card-header">
          <div>
            <div className="banner-title-row">
              <h2>Control Plane Authorization &amp; Taint Stream</h2>
              {chainValid === true && <StatusBadge tone="pass">CHAIN VERIFIED</StatusBadge>}
              {chainValid === false && <StatusBadge tone="aad">INTEGRITY COMPROMISED</StatusBadge>}
              {chainValid === null && <StatusBadge tone="warn">NO HASH CHAIN — UNVERIFIED</StatusBadge>}
            </div>
            <p className="muted">
              Showing {filtered.length} of {events.length} loaded events (total lines: {totalLines}
              {malformedLines > 0 ? `, malformed skipped: ${malformedLines}` : ""}). Raw prompts, secrets, and canaries
              are scrubbed before hashing and disk write.
            </p>
          </div>
          <div className="controls-row">
            <select
              aria-label="Filter by decision"
              value={decisionFilter}
              onChange={(e) => setDecisionFilter(e.target.value)}
            >
              <option value="all">All Decisions</option>
              <option value="allow">ALLOW</option>
              <option value="deny">DENY</option>
              <option value="require_approval">REQUIRE_APPROVAL</option>
              <option value="tainted">TAINTED</option>
              <option value="aad_fire">AAD_FIRE</option>
              <option value="blocked_egress">BLOCKED_EGRESS</option>
              <option value="observed_aad">OBSERVED_AAD</option>
              <option value="observed_block">OBSERVED_BLOCK</option>
            </select>
            <label className="checkbox-inline">
              <input type="checkbox" checked={taintOnly} onChange={(e) => setTaintOnly(e.target.checked)} />
              Tainted sessions only
            </label>
            <input
              type="search"
              placeholder="Search tool, server, session…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        </div>

        {chainValid === false && (
          <div className="callout-danger">
            <strong>Tamper or truncation detected:</strong>{" "}
            {chainReason ?? "Gateway hash-chain verification failed."}
          </div>
        )}
        {chainValid === null && (
          <div className="callout-warn">
            <strong>This log has no hash chain, so none of it can be verified.</strong> Gateway and authorizer logs are
            chained from 1.1 on, and an older log is moved aside as <code>*.pre-chain-*</code> on upgrade. A live log
            without a chain may have had its chain fields stripped; treat every entry here as untrusted.
          </div>
        )}

        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Session</th>
                <th>Server / Tool</th>
                <th>Decision</th>
                <th>Tier &amp; Taint</th>
                <th>Digests</th>
                <th>Policy Reasons</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} className="empty-cell">
                    No gateway authorization events match the active filters.
                  </td>
                </tr>
              ) : (
                filtered.map((ev) => (
                  <tr key={ev.audit_id}>
                    <td className="nowrap muted small">
                      <div>{ev.timestamp}</div>
                      {ev.seq !== undefined && <div>seq #{ev.seq}</div>}
                    </td>
                    <td>
                      <code>{ev.session_id}</code>
                    </td>
                    <td>
                      <code>{ev.tool_name}</code>
                      {ev.mcp_server && <div className="muted small">server: {ev.mcp_server}</div>}
                    </td>
                    <td>
                      <StatusBadge tone={toneForSeverity(ev.decision)}>{ev.decision.toUpperCase()}</StatusBadge>
                      {ev.enforcement_mode === "observe" && (
                        <div className="small">
                          <StatusBadge tone="warn">OBSERVE</StatusBadge>
                        </div>
                      )}
                    </td>
                    <td>
                      <StatusBadge tone={toneForSeverity(ev.risk_tier)}>{ev.risk_tier}</StatusBadge>
                      {ev.tainted && (
                        <div className="warn-text small">
                          tainted ({ev.taint_count})
                          {ev.taint_sources[0] ? ` · ${ev.taint_sources[0]}` : ""}
                        </div>
                      )}
                    </td>
                    <td>
                      <div>
                        <code>{ev.args_sha256 ? `${ev.args_sha256.slice(0, 14)}…` : "-"}</code>
                      </div>
                      {ev.entry_hash && (
                        <div className="muted small">
                          chain: <code>{ev.entry_hash.slice(0, 12)}…</code>
                        </div>
                      )}
                    </td>
                    <td>
                      <div className="small">{ev.reasons.join("; ")}</div>
                      {ev.grant_id && <div className="muted small">grant: {ev.grant_id}</div>}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
