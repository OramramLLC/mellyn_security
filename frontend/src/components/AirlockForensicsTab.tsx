import { useMemo, useState } from "react";
import type { IncidentReport, ReportProvenance } from "../types.ts";
import { StatusBadge, toneForSeverity } from "./StatusBadge.tsx";

interface AirlockForensicsTabProps {
  report: IncidentReport;
}

function provenanceLabel(provenance: ReportProvenance | undefined): string {
  switch (provenance) {
    case "server_verified":
      return "viewer server (mellyn-ir)";
    case "browser_verified":
      return "this browser";
    case "imported_unverified":
      return "nobody (imported report)";
    case "demo":
      return "synthetic demo data";
    default:
      return "unknown";
  }
}

export function AirlockForensicsTab({ report }: AirlockForensicsTabProps) {
  const imported = report.provenance === "imported_unverified";
  const [selectedSessionId, setSelectedSessionId] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [query, setQuery] = useState<string>("");

  const allEvents = useMemo(() => {
    const activeSessions =
      selectedSessionId === "all"
        ? report.sessions
        : report.sessions.filter((s) => s.session_id === selectedSessionId);
    const q = query.trim().toLowerCase();
    return activeSessions
      .flatMap((s) => s.events)
      .filter((ev) => severityFilter === "all" || ev.severity === severityFilter)
      .filter((ev) => {
        if (!q) return true;
        return (
          ev.action.toLowerCase().includes(q) ||
          ev.rule_id.toLowerCase().includes(q) ||
          ev.reason_code.toLowerCase().includes(q) ||
          ev.reason.toLowerCase().includes(q) ||
          (ev.tool_name ?? "").toLowerCase().includes(q)
        );
      });
  }, [report.sessions, selectedSessionId, severityFilter, query]);

  const v = report.verification;
  const term = report.terminal_event;

  return (
    <div className="stack-lg">
      <section
        className={`card banner-card ${
          imported ? "banner-unverified" : report.chain_valid ? "banner-ok" : "banner-danger"
        }`}
      >
        <div className="banner-header">
          <div>
            <div className="banner-title-row">
              <h2>Cryptographic Flight Recorder Status</h2>
              <StatusBadge tone={toneForSeverity(report.status)}>{report.status}</StatusBadge>
            </div>
            <p className="muted">
              Ledger: <code>{v.ledger_path}</code> · {imported ? "Entries (claimed by the file)" : "Entries verified"}:{" "}
              <strong>{v.entry_count}</strong> · Tail seq: <code>{v.last_seq ?? "none"}</code> · Anchor checked:{" "}
              <code>{String(v.anchored)}</code> · Verified by: <code>{provenanceLabel(report.provenance)}</code>
            </p>
          </div>
          <div className="hash-chip">
            <span className="muted small">Tail Entry Hash</span>
            <code>{v.last_hash ? `${v.last_hash.slice(0, 20)}…` : "empty / invalid"}</code>
          </div>
        </div>

        {imported && (
          <div className="callout-warn">
            <strong>Imported report — not verified.</strong> This file was a pre-built report, so its status and
            chain result are only what the file claims; nothing here checked them. Upload the raw{" "}
            <code>audit.jsonl</code> to verify the hash chain in this browser, or run <code>mellyn-ir</code>.
          </div>
        )}

        {!report.chain_valid && (
          <div className="callout-danger">
            <strong>INTEGRITY_COMPROMISED:</strong> First invalid seq <code>{v.first_invalid_seq ?? "?"}</code> (line{" "}
            <code>{v.first_invalid_line ?? "?"}</code>) — {v.reason ?? "Hash chain check failed."}
          </div>
        )}

        {report.status === "AAD_TRIGGERED_UNCONFIRMED" && (
          <div className="callout-warn">
            <strong>Containment Unconfirmed:</strong> {report.unconfirmed_aad_triggers} enforced <code>AAD_FIRE</code>{" "}
            trigger(s) lack a matching <code>airlock.aad_containment_confirmed</code> post-reap receipt.
          </div>
        )}

        {(report.observed_aad_count > 0 || report.observed_block_count > 0) && (
          <div className="callout-info">
            <strong>Red-Team Observe Telemetry:</strong> Recorded <code>{report.observed_aad_count}</code> observed AAD
            trigger(s) and <code>{report.observed_block_count}</code> observed block(s) without terminating downstream.
          </div>
        )}
      </section>

      {term && (
        <section className="card">
          <h3>Terminal AAD_FIRE Containment Record</h3>
          <div className="detail-grid">
            <div>
              <span className="muted small">Reason Code &amp; Rule</span>
              <div>
                <strong>{term.reason_code}</strong> (<code>{term.rule_id}</code>)
              </div>
            </div>
            <div>
              <span className="muted small">Session &amp; Sequence</span>
              <div>
                <code>{term.session_id}</code> (seq <code>{term.seq}</code>)
              </div>
            </div>
            <div>
              <span className="muted small">Post-Reap Confirmation</span>
              <div>
                <StatusBadge tone={term.containment_confirmed ? "pass" : "aad"}>
                  {term.containment_confirmed ? `CONFIRMED (seq=${term.containment_seq})` : "UNCONFIRMED"}
                </StatusBadge>
              </div>
            </div>
            <div>
              <span className="muted small">Exact Artifact SHA-256</span>
              <div>
                <code>{term.artifact_sha256.slice(0, 24)}…</code>
              </div>
            </div>
          </div>
          <p className="summary-text">{term.redacted_summary}</p>
        </section>
      )}

      <section className="card">
        <div className="card-header">
          <div>
            <h3>Session Timeline Events ({allEvents.length})</h3>
            <p className="muted">All ledger text is rendered strictly as inert text nodes after redaction.</p>
          </div>
          <div className="controls-row">
            <select
              aria-label="Filter by session"
              value={selectedSessionId}
              onChange={(e) => setSelectedSessionId(e.target.value)}
            >
              <option value="all">All Sessions ({report.sessions.length})</option>
              {report.sessions.map((s) => (
                <option key={s.session_id} value={s.session_id}>
                  {s.session_id} ({s.event_count})
                </option>
              ))}
            </select>
            <select
              aria-label="Filter by severity"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
            >
              <option value="all">All Severities</option>
              <option value="AAD_FIRE">AAD_FIRE</option>
              <option value="BLOCK">BLOCK</option>
              <option value="WARN">WARN</option>
              <option value="INFO">INFO</option>
              <option value="ALLOW">ALLOW</option>
            </select>
            <input
              type="search"
              placeholder="Search rule, tool, action…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
        </div>

        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Seq</th>
                <th>Time (UTC)</th>
                <th>Session</th>
                <th>Action / Tool</th>
                <th>Severity</th>
                <th>Rule &amp; Summary</th>
                <th>Artifact SHA-256</th>
              </tr>
            </thead>
            <tbody>
              {allEvents.length === 0 ? (
                <tr>
                  <td colSpan={7} className="empty-cell">
                    No verified Airlock events match the active filters.
                  </td>
                </tr>
              ) : (
                allEvents.map((ev) => (
                  <tr key={`${ev.session_id}-${ev.seq}`}>
                    <td>
                      <code>{ev.seq}</code>
                    </td>
                    <td className="nowrap muted small">{ev.timestamp_utc}</td>
                    <td>
                      <code>{ev.session_id}</code>
                    </td>
                    <td>
                      <code>{ev.action}</code>
                      {ev.tool_name && <div className="muted small">tool: {ev.tool_name}</div>}
                    </td>
                    <td>
                      <StatusBadge tone={toneForSeverity(ev.severity)}>{ev.severity}</StatusBadge>
                    </td>
                    <td>
                      <div>
                        <code>{ev.rule_id}</code>
                      </div>
                      <div className="small muted">{ev.reason}</div>
                    </td>
                    <td>
                      <code>{ev.artifact_sha256.slice(0, 14)}…</code>
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
