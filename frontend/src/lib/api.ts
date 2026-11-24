import type {
  ControlAssuranceReport,
  GatewayAuditPayload,
  IncidentReport,
  PendingApproval,
  ViewerStatus,
} from "../types.ts";
import { validateLoopbackBaseUrl } from "./parsers.ts";

export interface ApproveResult {
  approval_id: string;
  grant_id: string;
  max_uses: number;
  expires_at: string;
}

export interface RejectResult {
  approval_id: string;
  rejected: boolean;
}

async function requestJson<T>(
  baseUrl: string,
  path: string,
  options: { method?: "GET" | "POST"; apiKey?: string; body?: unknown } = {},
): Promise<T> {
  const safeBase = validateLoopbackBaseUrl(baseUrl);
  const headers: Record<string, string> = {};
  if (options.apiKey) {
    headers["X-Mellyn-API-Key"] = options.apiKey;
  }
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(`${safeBase}${path}`, {
    method: options.method ?? "GET",
    headers,
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
    redirect: "error",
    cache: "no-store",
  });

  const text = await response.text();
  let parsed: unknown = null;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = { error: text };
    }
  }

  if (!response.ok) {
    const errMsg =
      parsed !== null && typeof parsed === "object" && "error" in parsed && typeof parsed.error === "string"
        ? parsed.error
        : `HTTP ${response.status} (${response.statusText || "Request failed"})`;
    throw new Error(errMsg);
  }

  return parsed as T;
}

export function fetchHealthz(baseUrl: string): Promise<{ status: string }> {
  return requestJson<{ status: string }>(baseUrl, "/api/v1/healthz");
}

export function fetchStatus(baseUrl: string, apiKey: string): Promise<ViewerStatus> {
  return requestJson<ViewerStatus>(baseUrl, "/api/v1/status", { apiKey });
}

export async function fetchAirlockReport(baseUrl: string, apiKey: string): Promise<IncidentReport> {
  const report = await requestJson<IncidentReport>(baseUrl, "/api/v1/airlock/report", { apiKey });
  // The viewer server verified this ledger with Python's `mellyn-ir` reconstruction.
  return { ...report, provenance: "server_verified" };
}

export function fetchGatewayAudit(baseUrl: string, apiKey: string, limit = 500): Promise<GatewayAuditPayload> {
  return requestJson<GatewayAuditPayload>(baseUrl, `/api/v1/gateway/audit?limit=${encodeURIComponent(String(limit))}`, {
    apiKey,
  });
}

export function fetchAssuranceReport(baseUrl: string, apiKey: string): Promise<ControlAssuranceReport> {
  return requestJson<ControlAssuranceReport>(baseUrl, "/api/v1/assurance", { apiKey });
}

export function fetchPendingApprovals(baseUrl: string, apiKey: string): Promise<{ pending: PendingApproval[] }> {
  return requestJson<{ pending: PendingApproval[] }>(baseUrl, "/api/v1/pending", { apiKey });
}

export function approvePendingCall(
  baseUrl: string,
  apiKey: string,
  approvalId: string,
  payload: { approved_by: string; ttl_seconds: number; max_uses: number },
): Promise<ApproveResult> {
  return requestJson<ApproveResult>(baseUrl, `/api/v1/pending/${encodeURIComponent(approvalId)}/approve`, {
    method: "POST",
    apiKey,
    body: payload,
  });
}

export function rejectPendingCall(baseUrl: string, apiKey: string, approvalId: string): Promise<RejectResult> {
  return requestJson<RejectResult>(baseUrl, `/api/v1/pending/${encodeURIComponent(approvalId)}/reject`, {
    method: "POST",
    apiKey,
    body: {},
  });
}
