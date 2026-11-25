import { useState, type ChangeEvent, type FormEvent } from "react";
import { validateLoopbackBaseUrl } from "../lib/parsers.ts";
import { StatusBadge } from "./StatusBadge.tsx";

interface DataSourceDrawerProps {
  isOpen: boolean;
  isLiveMode: boolean;
  baseUrl: string;
  hasApiKey: boolean;
  statusMessage: string | null;
  errorMessage: string | null;
  onClose: () => void;
  onConnectLive: (baseUrl: string, apiKey: string) => Promise<void>;
  onResetSample: () => void;
  onLoadAirlockText: (text: string, filename: string) => Promise<void>;
  onLoadGatewayText: (text: string) => Promise<void>;
  onLoadAssuranceText: (text: string) => void;
}

export function DataSourceDrawer({
  isOpen,
  isLiveMode,
  baseUrl,
  hasApiKey,
  statusMessage,
  errorMessage,
  onClose,
  onConnectLive,
  onResetSample,
  onLoadAirlockText,
  onLoadGatewayText,
  onLoadAssuranceText,
}: DataSourceDrawerProps) {
  const [urlInput, setUrlInput] = useState<string>(baseUrl);
  const [apiKeyInput, setApiKeyInput] = useState<string>("");
  const [localError, setLocalError] = useState<string | null>(null);
  const [connecting, setConnecting] = useState<boolean>(false);

  if (!isOpen) {
    return null;
  }

  async function handleConnectSubmit(event: FormEvent) {
    event.preventDefault();
    setLocalError(null);
    let normalizedUrl: string;
    try {
      normalizedUrl = validateLoopbackBaseUrl(urlInput);
    } catch (err) {
      setLocalError(err instanceof Error ? err.message : String(err));
      return;
    }
    if (!apiKeyInput.trim()) {
      setLocalError("Enter your read-only Role.VIEWER X-Mellyn-API-Key (kept in memory only).");
      return;
    }
    setConnecting(true);
    try {
      await onConnectLive(normalizedUrl, apiKeyInput.trim());
    } catch (err) {
      setLocalError(err instanceof Error ? err.message : String(err));
    } finally {
      setConnecting(false);
    }
  }

  async function handleFileChange(
    e: ChangeEvent<HTMLInputElement>,
    kind: "airlock" | "gateway" | "assurance",
  ) {
    const file = e.target.files?.[0];
    if (!file) {
      return;
    }
    setLocalError(null);
    try {
      const text = await file.text();
      if (kind === "airlock") {
        await onLoadAirlockText(text, file.name);
      } else if (kind === "gateway") {
        await onLoadGatewayText(text);
      } else {
        onLoadAssuranceText(text);
      }
    } catch (err) {
      setLocalError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <div className="drawer-backdrop" role="dialog" aria-modal="true" aria-label="Data Sources & Credentials">
      <div className="drawer-panel">
        <div className="drawer-header">
          <div>
            <h2>Data Sources &amp; Credentials</h2>
            <p className="muted small">
              Live keys stay strictly in React memory (never persisted to browser storage). The viewer key here
              only reads; the Approvals tab asks for the separate approver key.
            </p>
          </div>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>

        <div className="stack-md">
          <section className="subcard">
            <div className="subcard-title-row">
              <h3>1. Connect Live Viewer Server (Loopback)</h3>
              <StatusBadge tone={isLiveMode && hasApiKey ? "pass" : "muted"}>
                {isLiveMode && hasApiKey ? "LIVE CONNECTED" : "OFFLINE"}
              </StatusBadge>
            </div>
            <form className="stack-sm" onSubmit={(e) => void handleConnectSubmit(e)}>
              <label>
                <span className="muted small">Viewer Base URL (blank = same-origin /api)</span>
                <input
                  type="text"
                  placeholder="http://127.0.0.1:8080"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                />
              </label>
              <label>
                <span className="muted small">X-Mellyn-API-Key (Role.VIEWER, read-only)</span>
                <input
                  type="password"
                  autoComplete="off"
                  placeholder="Enter viewer key…"
                  value={apiKeyInput}
                  onChange={(e) => setApiKeyInput(e.target.value)}
                />
              </label>
              <div className="btn-row">
                <button type="submit" className="btn btn-primary" disabled={connecting}>
                  {connecting ? "Connecting…" : "Connect & Fetch Live Telemetry"}
                </button>
                <button type="button" className="btn btn-secondary" onClick={onResetSample}>
                  Use Redacted Sample Data
                </button>
              </div>
            </form>
          </section>

          <section className="subcard">
            <h3>2. Inspect Local Audit &amp; Assurance Files (Client-Side Only)</h3>
            <p className="muted small">
              Files are parsed locally in your browser; Airlock and Gateway JSONL ledgers undergo full Web Crypto
              SHA-256 hash chain verification.
            </p>
            <div className="upload-grid">
              <label className="upload-field">
                <span>Airlock Ledger (audit.jsonl or mellyn-ir --json)</span>
                <input
                  type="file"
                  accept=".jsonl,.json"
                  onChange={(e) => void handleFileChange(e, "airlock")}
                />
              </label>
              <label className="upload-field">
                <span>Gateway Audit Log (gateway-audit.jsonl)</span>
                <input
                  type="file"
                  accept=".jsonl,.json"
                  onChange={(e) => void handleFileChange(e, "gateway")}
                />
              </label>
              <label className="upload-field">
                <span>Control Assurance Report (assurance.json)</span>
                <input
                  type="file"
                  accept=".json"
                  onChange={(e) => void handleFileChange(e, "assurance")}
                />
              </label>
            </div>
          </section>

          {(localError || errorMessage) && <div className="callout-danger">{localError ?? errorMessage}</div>}
          {statusMessage && <div className="callout-info">{statusMessage}</div>}
        </div>
      </div>
    </div>
  );
}
