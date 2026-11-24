import { useState } from "react";
import type { ControlAssuranceReport, IncidentReport } from "../types.ts";
import { StatusBadge, toneForSeverity } from "./StatusBadge.tsx";

interface OverviewTabProps {
  assurance: ControlAssuranceReport;
  airlockReport: IncidentReport;
  gatewayCount: number;
  pendingCount: number;
  modeLabel: string;
}

export function OverviewTab({
  assurance,
  airlockReport,
  gatewayCount,
  pendingCount,
  modeLabel,
}: OverviewTabProps) {
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const filteredCases = assurance.cases.filter((c) => statusFilter === "all" || c.status === statusFilter);

  return (
    <div className="stack-lg">
      <section className="kpi-grid">
        <div className="card kpi-card">
          <div className="kpi-label">Airlock Chain &amp; Containment</div>
          <div className="kpi-value-row">
            <StatusBadge tone={toneForSeverity(airlockReport.status)}>{airlockReport.status}</StatusBadge>
          </div>
          <div className="kpi-sub">
            {airlockReport.chain_valid
              ? `${airlockReport.total_events} canonical entries verified (${airlockReport.session_count} sessions)`
              : `Tamper/truncation detected at seq ${airlockReport.verification.first_invalid_seq ?? "?"}`}
          </div>
        </div>

        <div className="card kpi-card">
          <div className="kpi-label">Control Assurance Gate</div>
          <div className="kpi-value-row">
            <StatusBadge tone={toneForSeverity(assurance.overall_status)}>
              {assurance.overall_status.toUpperCase()}
            </StatusBadge>
            <span className="kpi-number">
              {assurance.summary.counts.pass}/{assurance.summary.total_cases} passing
            </span>
          </div>
          <div className="kpi-sub">
            Profile: <code>{assurance.execution_profile}</code> · Not run: {assurance.summary.counts.not_run}
          </div>
        </div>

        <div className="card kpi-card">
          <div className="kpi-label">Control Plane Audit Events</div>
          <div className="kpi-value-row">
            <span className="kpi-number">{gatewayCount}</span>
            <StatusBadge tone="info">{modeLabel}</StatusBadge>
          </div>
          <div className="kpi-sub">Redacted args SHA-256 + taint provenance ledger</div>
        </div>

        <div className="card kpi-card">
          <div className="kpi-label">Pending Human Approvals</div>
          <div className="kpi-value-row">
            <span className="kpi-number">{pendingCount}</span>
            <StatusBadge tone={pendingCount > 0 ? "warn" : "pass"}>
              {pendingCount > 0 ? "Action Required" : "Queue Clear"}
            </StatusBadge>
          </div>
          <div className="kpi-sub">Role.APPROVER exact-call grant verification</div>
        </div>
      </section>

      <section className="card">
        <div className="card-header">
          <div>
            <h2>Compliance &amp; Control Assurance Matrix</h2>
            <p className="muted">
              OWASP LLM Top 10 ({assurance.frameworks.owasp_llm_top_10}) · OWASP Agentic Top 10 (
              {assurance.frameworks.owasp_agentic_top_10}) · MITRE ATLAS ({assurance.frameworks.mitre_atlas})
            </p>
          </div>
          <div className="filter-pills">
            {(["all", "pass", "fail", "error", "not_run"] as const).map((status) => (
              <button
                key={status}
                type="button"
                className={`pill ${statusFilter === status ? "pill-active" : ""}`}
                onClick={() => setStatusFilter(status)}
              >
                {status}
              </button>
            ))}
          </div>
        </div>

        <div className="meta-strip">
          <span>
            Commit: <code>{assurance.git_commit.slice(0, 12)}</code>
          </span>
          <span>
            Policy Digest: <code>{assurance.policy_sha256.slice(0, 16)}…</code>
          </span>
          <span>
            Platform: <code>{assurance.platform_system}</code> (Python {assurance.python_version})
          </span>
        </div>

        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Case ID</th>
                <th>Profile</th>
                <th>Threat IDs</th>
                <th>Framework Mappings</th>
                <th>Validation Summary</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {filteredCases.map((rec) => (
                <tr key={rec.case_id}>
                  <td>
                    <code>{rec.case_id}</code>
                    <div className="muted small">{rec.family}</div>
                  </td>
                  <td>
                    <code>{rec.profile}</code>
                  </td>
                  <td>{rec.control_ids.join(", ")}</td>
                  <td>
                    <div className="tag-list">
                      {rec.mappings.owasp_llm_2025.map((m) => (
                        <span key={m} className="micro-tag">
                          {m}
                        </span>
                      ))}
                      {rec.mappings.owasp_agentic_2026.map((m) => (
                        <span key={m} className="micro-tag">
                          {m}
                        </span>
                      ))}
                      {rec.mappings.mitre_atlas.map((m) => (
                        <span key={m} className="micro-tag micro-tag-atlas">
                          {m}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td>
                    <div>{rec.synthetic_case}</div>
                    {rec.failure_detail && <div className="danger-text small">{rec.failure_detail}</div>}
                  </td>
                  <td>
                    <StatusBadge tone={toneForSeverity(rec.status)}>{rec.status.toUpperCase()}</StatusBadge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {assurance.out_of_scope_controls.length > 0 && (
          <div className="callout-neutral">
            <strong>Explicit Scope Boundaries</strong>
            <ul>
              {assurance.out_of_scope_controls.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          </div>
        )}
      </section>
    </div>
  );
}
