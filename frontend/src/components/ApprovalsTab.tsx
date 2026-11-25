import { useState } from "react";
import type { PendingApproval } from "../types.ts";
import { StatusBadge } from "./StatusBadge.tsx";

interface ApprovalsTabProps {
  pending: PendingApproval[];
  isLiveMode: boolean;
  focusedApprovalId?: string | null;
  onClearFocus?: () => void;
  onRefresh: (approverKey: string) => Promise<void>;
  onApprove: (
    approvalId: string,
    opts: { approvedBy: string; ttlSeconds: number; maxUses: number },
    approverKey: string,
  ) => Promise<void>;
  onReject: (approvalId: string, approverKey: string) => Promise<void>;
}

export function ApprovalsTab({
  pending,
  isLiveMode,
  focusedApprovalId = null,
  onClearFocus,
  onRefresh,
  onApprove,
  onReject,
}: ApprovalsTabProps) {
  const [approvedBy, setApprovedBy] = useState<string>("security-operator");
  const [ttlSeconds, setTtlSeconds] = useState<number>(300);
  const [maxUses, setMaxUses] = useState<number>(1);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);
  // The Role.APPROVER key lives only in this tab's state: it is never lifted into App, never stored, and is
  // dropped when the tab unmounts (switching tabs) or when the operator clicks "Forget key".
  const [approverKey, setApproverKey] = useState<string>("");

  function requireApproverKey(): string | null {
    const key = approverKey.trim();
    if (isLiveMode && !key) {
      setActionMsg("Enter the Role.APPROVER key to load or act on the live queue.");
      return null;
    }
    return key;
  }

  async function handleRefresh() {
    const key = requireApproverKey();
    if (key === null) return;
    setActionMsg(null);
    try {
      await onRefresh(key);
    } catch (err) {
      setActionMsg(`Loading the queue failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  async function handleApprove(approvalId: string) {
    const key = requireApproverKey();
    if (key === null) return;
    setBusyId(approvalId);
    setActionMsg(null);
    try {
      const opts = { approvedBy: approvedBy.trim() || "security-operator", ttlSeconds, maxUses };
      await onApprove(approvalId, opts, key);
      setActionMsg(`Approved ${approvalId} with exact-call grant (TTL ${ttlSeconds}s, max_uses ${maxUses}).`);
    } catch (err) {
      setActionMsg(`Approval failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusyId(null);
    }
  }

  async function handleReject(approvalId: string) {
    const key = requireApproverKey();
    if (key === null) return;
    setBusyId(approvalId);
    setActionMsg(null);
    try {
      await onReject(approvalId, key);
      setActionMsg(`Rejected ${approvalId}.`);
    } catch (err) {
      setActionMsg(`Rejection failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusyId(null);
    }
  }

  const focusedMatch = focusedApprovalId ? pending.find((item) => item.approval_id === focusedApprovalId) : undefined;
  const orderedPending =
    focusedMatch !== undefined
      ? [focusedMatch, ...pending.filter((item) => item.approval_id !== focusedMatch.approval_id)]
      : pending;

  return (
    <div className="stack-lg">
      {focusedApprovalId && (
        <div className="callout-info approval-deeplink-banner">
          <div>
            <strong>Deep Link Target:</strong> <code>{focusedApprovalId}</code>.{" "}
            {isLiveMode
              ? focusedMatch
                ? "Highlighted at the top of the approval queue below."
                : 'Enter your Role.APPROVER key and click "Load / Refresh Queue" to inspect this request.'
              : 'Connect via "Data Sources & Key" and enter your Role.APPROVER key to load live approvals.'}
          </div>
          {onClearFocus && (
            <button type="button" className="btn btn-secondary" onClick={onClearFocus}>
              Clear focus
            </button>
          )}
        </div>
      )}

      {!isLiveMode && (
        <div className="callout-info">
          <strong>Offline Sample Mode:</strong> Approvals below are interactive synthetic demos. Connect a live
          loopback <code>viewer_server</code> with your <code>Role.APPROVER</code> key to authorize real gateway calls.
        </div>
      )}

      <section className="card">
        <div className="card-header">
          <div>
            <h2>Human-in-the-Loop Exact-Call Approval Queue</h2>
            <p className="muted">
              Grants bind cryptographically to the session, tool, server, and canonical JSON argument set.
            </p>
          </div>
          {isLiveMode && (
            <button type="button" className="btn btn-secondary" onClick={() => void handleRefresh()}>
              Load / Refresh Queue
            </button>
          )}
        </div>

        {isLiveMode && (
          <div className="grant-controls">
            <label>
              <span className="muted small">X-Mellyn-API-Key (Role.APPROVER — held only while this tab is open)</span>
              <input
                type="password"
                autoComplete="off"
                placeholder="Enter approver key…"
                value={approverKey}
                onChange={(e) => setApproverKey(e.target.value)}
              />
            </label>
            <div className="btn-row">
              <button type="button" className="btn btn-secondary" onClick={() => setApproverKey("")}>
                Forget key
              </button>
            </div>
          </div>
        )}

        <div className="grant-controls">
          <label>
            <span className="muted small">Approver label</span>
            <input
              type="text"
              maxLength={128}
              value={approvedBy}
              onChange={(e) => setApprovedBy(e.target.value)}
            />
          </label>
          <label>
            <span className="muted small">Grant TTL (seconds)</span>
            <input
              type="number"
              min={1}
              max={86400}
              value={ttlSeconds}
              onChange={(e) => setTtlSeconds(Math.max(1, Math.min(86400, Number(e.target.value) || 300)))}
            />
          </label>
          <label>
            <span className="muted small">Max uses</span>
            <input
              type="number"
              min={1}
              max={20}
              value={maxUses}
              onChange={(e) => setMaxUses(Math.max(1, Math.min(20, Number(e.target.value) || 1)))}
            />
          </label>
        </div>

        {actionMsg && <div className="callout-neutral">{actionMsg}</div>}

        {orderedPending.length === 0 ? (
          <div className="empty-box">
            <strong>No held calls waiting for approval.</strong>
          </div>
        ) : (
          <div className="stack-md">
            {orderedPending.map((item) => {
              const isFocused = focusedApprovalId === item.approval_id;
              return (
                <article
                  key={item.approval_id}
                  data-focused={isFocused ? "true" : undefined}
                  className={`approval-item ${isFocused ? "approval-item-focused" : ""}`}
                >
                <div className="approval-head">
                  <div>
                    <div className="approval-title-row">
                      <StatusBadge tone="block">REQUIRE_APPROVAL</StatusBadge>
                      <code>{item.mcp_server ? `${item.mcp_server} / ${item.tool_name}` : item.tool_name}</code>
                      <span className="muted small">{item.approval_id}</span>
                    </div>
                    <div className="muted small">
                      Session: <code>{item.session_id}</code> · Audit: <code>{item.audit_id}</code> · Held:{" "}
                      {item.created_at}
                    </div>
                  </div>
                  <div className="btn-row">
                    <button
                      type="button"
                      className="btn btn-primary"
                      disabled={busyId === item.approval_id}
                      onClick={() => void handleApprove(item.approval_id)}
                    >
                      Approve Exact Call
                    </button>
                    <button
                      type="button"
                      className="btn btn-danger"
                      disabled={busyId === item.approval_id}
                      onClick={() => void handleReject(item.approval_id)}
                    >
                      Reject
                    </button>
                  </div>
                </div>
                <div className="reasons-box">
                  {item.reasons.map((r) => (
                    <div key={r} className="warn-text small">
                      • {r}
                    </div>
                  ))}
                </div>
                <pre className="json-pre">{JSON.stringify(item.arguments, null, 2)}</pre>
                </article>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}
