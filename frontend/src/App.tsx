import { useCallback, useState } from "react";
import { AirlockForensicsTab } from "./components/AirlockForensicsTab.tsx";
import { ApprovalsTab } from "./components/ApprovalsTab.tsx";
import { DataSourceDrawer } from "./components/DataSourceDrawer.tsx";
import { GatewayAuditTab } from "./components/GatewayAuditTab.tsx";
import { OverviewTab } from "./components/OverviewTab.tsx";
import { StatusBadge, toneForSeverity } from "./components/StatusBadge.tsx";
import {
  SAMPLE_ASSURANCE_REPORT,
  SAMPLE_GATEWAY_EVENTS,
  SAMPLE_INCIDENT_REPORT,
  SAMPLE_PENDING_APPROVALS,
} from "./data/sampleData.ts";
import {
  approvePendingCall,
  fetchAirlockReport,
  fetchAssuranceReport,
  fetchGatewayAudit,
  fetchHealthz,
  fetchPendingApprovals,
  fetchStatus,
  rejectPendingCall,
} from "./lib/api.ts";
import { parseAirlockInput, parseAssuranceReportJson, parseGatewayAuditJsonl } from "./lib/parsers.ts";
import type { ControlAssuranceReport, GatewayAuditEvent, IncidentReport, PendingApproval } from "./types.ts";

type TabId = "overview" | "airlock" | "gateway" | "approvals";

export function App() {
  const [activeTab, setActiveTab] = useState<TabId>("overview");
  const [drawerOpen, setDrawerOpen] = useState<boolean>(false);

  const [isLiveMode, setIsLiveMode] = useState<boolean>(false);
  const [baseUrl, setBaseUrl] = useState<string>("");
  // Read-only Role.VIEWER key. The approver key never lives here: ApprovalsTab holds it for its own lifetime.
  const [viewerKey, setViewerKey] = useState<string>("");
  const [sourceLabel, setSourceLabel] = useState<string>("Redacted Demo");
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const [airlockReport, setAirlockReport] = useState<IncidentReport>(SAMPLE_INCIDENT_REPORT);
  const [gatewayEvents, setGatewayEvents] = useState<GatewayAuditEvent[]>(SAMPLE_GATEWAY_EVENTS);
  const [gatewayTotalLines, setGatewayTotalLines] = useState<number>(SAMPLE_GATEWAY_EVENTS.length);
  const [gatewayMalformed, setGatewayMalformed] = useState<number>(0);
  const [assuranceReport, setAssuranceReport] = useState<ControlAssuranceReport>(SAMPLE_ASSURANCE_REPORT);
  const [pendingApprovals, setPendingApprovals] = useState<PendingApproval[]>(SAMPLE_PENDING_APPROVALS);

  const refreshLive = useCallback(async (url: string, key: string) => {
    await fetchHealthz(url);
    const status = await fetchStatus(url, key);
    const loadedParts: string[] = [];

    if (status.airlock_ledger_configured) {
      setAirlockReport(await fetchAirlockReport(url, key));
      loadedParts.push("Airlock ledger");
    }
    if (status.gateway_audit_configured) {
      const gw = await fetchGatewayAudit(url, key, 500);
      setGatewayEvents(gw.events);
      setGatewayTotalLines(gw.total_lines);
      setGatewayMalformed(gw.malformed_lines);
      loadedParts.push("Gateway audit");
    }
    if (status.assurance_report_configured) {
      setAssuranceReport(await fetchAssuranceReport(url, key));
      loadedParts.push("Assurance report");
    }
    // The approval queue needs the separate Role.APPROVER key, which the Approvals tab asks for itself.
    setPendingApprovals([]);

    setStatusMessage(
      loadedParts.length > 0
        ? `Loaded live telemetry: ${loadedParts.join(", ")}.`
        : "Connected to viewer server (no artifact paths configured on server).",
    );
  }, []);

  async function handleConnectLive(nextUrl: string, nextKey: string) {
    setErrorMessage(null);
    await refreshLive(nextUrl, nextKey);
    setBaseUrl(nextUrl);
    setViewerKey(nextKey);
    setIsLiveMode(true);
    setSourceLabel("Live Loopback");
  }

  function handleResetSample() {
    setIsLiveMode(false);
    setViewerKey("");
    setBaseUrl("");
    setSourceLabel("Redacted Demo");
    setAirlockReport(SAMPLE_INCIDENT_REPORT);
    setGatewayEvents(SAMPLE_GATEWAY_EVENTS);
    setGatewayTotalLines(SAMPLE_GATEWAY_EVENTS.length);
    setGatewayMalformed(0);
    setAssuranceReport(SAMPLE_ASSURANCE_REPORT);
    setPendingApprovals(SAMPLE_PENDING_APPROVALS);
    setErrorMessage(null);
    setStatusMessage("Reset to built-in redacted synthetic data.");
  }

  async function handleLoadAirlockText(text: string, filename: string) {
    const parsed = await parseAirlockInput(text, filename);
    setAirlockReport(parsed);
    setIsLiveMode(false);
    setSourceLabel(`Local: ${filename}`);
    setStatusMessage(`Verified Airlock ledger '${filename}': ${parsed.status} (${parsed.total_events} entries).`);
    setActiveTab("airlock");
  }

  function handleLoadGatewayText(text: string) {
    const gw = parseGatewayAuditJsonl(text);
    setGatewayEvents(gw.events);
    setGatewayTotalLines(gw.total_lines);
    setGatewayMalformed(gw.malformed_lines);
    setIsLiveMode(false);
    setSourceLabel("Local Gateway Audit");
    setStatusMessage(`Loaded ${gw.returned_count} gateway audit events.`);
    setActiveTab("gateway");
  }

  function handleLoadAssuranceText(text: string) {
    const rep = parseAssuranceReportJson(text);
    setAssuranceReport(rep);
    setIsLiveMode(false);
    setSourceLabel("Local Assurance");
    setStatusMessage(`Loaded Control Assurance Report (${rep.summary.total_cases} cases).`);
    setActiveTab("overview");
  }

  async function handleApprove(
    approvalId: string,
    opts: { approvedBy: string; ttlSeconds: number; maxUses: number },
    approverKey: string,
  ) {
    if (isLiveMode) {
      await approvePendingCall(baseUrl, approverKey, approvalId, {
        approved_by: opts.approvedBy,
        ttl_seconds: opts.ttlSeconds,
        max_uses: opts.maxUses,
      });
      const res = await fetchPendingApprovals(baseUrl, approverKey);
      setPendingApprovals(res.pending);
      return;
    }
    setPendingApprovals((prev) => prev.filter((item) => item.approval_id !== approvalId));
  }

  async function handleReject(approvalId: string, approverKey: string) {
    if (isLiveMode) {
      await rejectPendingCall(baseUrl, approverKey, approvalId);
      const res = await fetchPendingApprovals(baseUrl, approverKey);
      setPendingApprovals(res.pending);
      return;
    }
    setPendingApprovals((prev) => prev.filter((item) => item.approval_id !== approvalId));
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-group">
          <div className="brand-mark">M</div>
          <div>
            <h1>Mellyn Security Console</h1>
            <p className="muted small">Plane 4 — Posture, Airlock Forensics &amp; Human-in-the-Loop Approvals</p>
          </div>
        </div>

        <div className="topbar-actions">
          <StatusBadge tone={toneForSeverity(airlockReport.status)}>Airlock: {airlockReport.status}</StatusBadge>
          <StatusBadge tone={isLiveMode ? "pass" : "info"}>{sourceLabel}</StatusBadge>
          {isLiveMode && (
            <button type="button" className="btn btn-secondary" onClick={() => void refreshLive(baseUrl, viewerKey)}>
              Refresh Live
            </button>
          )}
          <button type="button" className="btn btn-primary" onClick={() => setDrawerOpen(true)}>
            Data Sources &amp; Key
          </button>
        </div>
      </header>

      <nav className="tabbar" aria-label="Console Views">
        <button
          type="button"
          className={`tab-btn ${activeTab === "overview" ? "tab-active" : ""}`}
          onClick={() => setActiveTab("overview")}
        >
          Posture &amp; Assurance
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === "airlock" ? "tab-active" : ""}`}
          onClick={() => setActiveTab("airlock")}
        >
          Airlock Forensics ({airlockReport.total_events})
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === "gateway" ? "tab-active" : ""}`}
          onClick={() => setActiveTab("gateway")}
        >
          Control Plane Audit ({gatewayEvents.length})
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === "approvals" ? "tab-active" : ""}`}
          onClick={() => setActiveTab("approvals")}
        >
          Approvals Queue ({pendingApprovals.length})
        </button>
      </nav>

      <main className="main-content">
        {activeTab === "overview" && (
          <OverviewTab
            assurance={assuranceReport}
            airlockReport={airlockReport}
            gatewayCount={gatewayEvents.length}
            pendingCount={pendingApprovals.length}
            modeLabel={sourceLabel}
          />
        )}
        {activeTab === "airlock" && <AirlockForensicsTab report={airlockReport} />}
        {activeTab === "gateway" && (
          <GatewayAuditTab
            events={gatewayEvents}
            totalLines={gatewayTotalLines}
            malformedLines={gatewayMalformed}
          />
        )}
        {activeTab === "approvals" && (
          <ApprovalsTab
            pending={pendingApprovals}
            isLiveMode={isLiveMode}
            onRefresh={async (approverKey: string) => {
              if (isLiveMode) {
                const res = await fetchPendingApprovals(baseUrl, approverKey);
                setPendingApprovals(res.pending);
              }
            }}
            onApprove={handleApprove}
            onReject={handleReject}
          />
        )}
      </main>

      <DataSourceDrawer
        isOpen={drawerOpen}
        isLiveMode={isLiveMode}
        baseUrl={baseUrl}
        hasApiKey={Boolean(viewerKey)}
        statusMessage={statusMessage}
        errorMessage={errorMessage}
        onClose={() => setDrawerOpen(false)}
        onConnectLive={handleConnectLive}
        onResetSample={handleResetSample}
        onLoadAirlockText={handleLoadAirlockText}
        onLoadGatewayText={handleLoadGatewayText}
        onLoadAssuranceText={handleLoadAssuranceText}
      />
    </div>
  );
}

export default App;
