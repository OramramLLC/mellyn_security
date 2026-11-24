import { useMemo, useState } from "react";
import type { GatewayAuditEvent } from "../types.ts";
import { StatusBadge, toneForSeverity } from "./StatusBadge.tsx";

interface GatewayAuditTabProps {
  events: GatewayAuditEvent[];
  totalLines: number;
  malformedLines: number;
}

export function GatewayAuditTab({ events, totalLines, malformedLines }: GatewayAuditTabProps) {
  const [decisionFilter, setDecisionFilter] = useState<string>("all");
  const [taintOnly, setTaintOnly] = useState<boolean>(false);
  const [search, setSearch] = useState<string>("");

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return [...events]
      .reverse()
      .filter((ev) => decisionFilter === "all" || ev.decision === decisionFilter)
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
            <h2>Control Plane Authorization &amp; Taint Stream</h2>
            <p className="muted">
              Showing {filtered.length} of {events.length} loaded events (total lines: {totalLines}
              {malformedLines > 0 ? `, malformed skipped: ${malformedLines}` : ""}). Raw prompts and secrets are never
              stored.
            </p>
          </div>
          <div className="controls-row">
            <select
              aria-label="Filter by decision"
              value={decisionFilter}
              onChange={(e) => setDecisionFilter(e.target.value)}
            >
              <option value="all">All Decisions</option>
              <option value="ALLOW">ALLOW</option>
              <option value="DENY">DENY</option>
              <option value="REQUIRE_APPROVAL">REQUIRE_APPROVAL</option>
              <option value="TAINT">TAINT</option>
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

        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Session</th>
                <th>Server / Tool</th>
                <th>Decision</th>
                <th>Tier &amp; Taint</th>
                <th>Args SHA-256</th>
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
                    <td className="nowrap muted small">{ev.timestamp}</td>
                    <td>
                      <code>{ev.session_id}</code>
                    </td>
                    <td>
                      <code>{ev.tool_name}</code>
                      {ev.mcp_server && <div className="muted small">server: {ev.mcp_server}</div>}
                    </td>
                    <td>
                      <StatusBadge tone={toneForSeverity(ev.decision)}>{ev.decision}</StatusBadge>
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
                      <code>{ev.args_sha256 ? `${ev.args_sha256.slice(0, 14)}…` : "-"}</code>
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
