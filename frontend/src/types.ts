export type Severity = "ALLOW" | "INFO" | "WARN" | "BLOCK" | "AAD_FIRE";
export type Zone = "core" | "egress" | "airlock" | "ir_lab";

export type IncidentStatus =
  | "CLEAN"
  | "BLOCKED_ACTIVITY"
  | "OBSERVED_VIOLATIONS"
  | "AAD_CONTAINED"
  | "AAD_TRIGGERED_UNCONFIRMED"
  | "INTEGRITY_COMPROMISED";

export interface ChainVerificationReport {
  ledger_path: string;
  valid: boolean;
  entry_count: number;
  last_seq: number | null;
  last_hash: string | null;
  first_invalid_seq: number | null;
  first_invalid_line: number | null;
  anchored: boolean;
  reason: string | null;
}

export interface TimelineEvent {
  seq: number;
  timestamp_utc: string;
  session_id: string;
  zone: Zone;
  action: string;
  severity: Severity;
  verdict_allow: boolean;
  rule_id: string;
  reason_code: string;
  reason: string;
  tool_name: string | null;
  rpc_id: number | string | null;
  artifact_sha256: string;
}

export interface TerminalTrigger {
  seq: number;
  timestamp_utc: string;
  session_id: string;
  zone: Zone;
  action: string;
  rule_id: string;
  reason_code: string;
  rpc_id: number | string | null;
  tool_name: string | null;
  artifact_sha256: string;
  redacted_summary: string;
  trigger_event_id: string | null;
  containment_confirmed: boolean;
  containment_seq: number | null;
}

export interface SessionTimeline {
  session_id: string;
  event_count: number;
  zones_traversed: Zone[];
  zone_transitions: string[];
  block_precursors: TimelineEvent[];
  terminal_event: TerminalTrigger | null;
  events: TimelineEvent[];
  enforcement_mode?: "enforce" | "observe" | null;
}

/**
 * Where a report's verdict came from: checked by the Python server (`server_verified`), checked in this browser
 * from a raw `audit.jsonl` (`browser_verified`), a pre-built report file that nothing here checked
 * (`imported_unverified`), or the built-in synthetic sample (`demo`).
 */
export type ReportProvenance = "server_verified" | "browser_verified" | "imported_unverified" | "demo";

export interface IncidentReport {
  status: IncidentStatus;
  chain_valid: boolean;
  provenance?: ReportProvenance;
  verification: ChainVerificationReport;
  session_count: number;
  total_events: number;
  unconfirmed_aad_triggers: number;
  observed_aad_count: number;
  observed_block_count: number;
  sessions: SessionTimeline[];
  terminal_event: TerminalTrigger | null;
}

export interface GatewayAuditEvent {
  audit_id: string;
  timestamp: string;
  session_id: string;
  tool_name: string;
  mcp_server: string | null;
  decision: string;
  risk_tier: string;
  tainted: boolean;
  taint_sources: string[];
  args_sha256: string;
  reasons: string[];
  policy_id: string | null;
  grant_id: string | null;
  event_type: string;
  taint_count: number;
  seq?: number;
  prev_hash?: string;
  entry_hash?: string;
  enforcement_mode?: string;
}

export interface GatewayAuditPayload {
  events: GatewayAuditEvent[];
  total_lines: number;
  returned_count: number;
  malformed_lines: number;
  chain_valid?: boolean | null;
  chain_reason?: string | null;
}

export interface AssuranceCaseRecord {
  case_id: string;
  family: string;
  control_ids: string[];
  mappings: {
    owasp_llm_2025: string[];
    owasp_agentic_2026: string[];
    mitre_atlas: string[];
  };
  profile: string;
  synthetic_case: string;
  evidence_source: string;
  status: "pass" | "fail" | "error" | "not_run";
  failure_detail: string | null;
}

export interface ControlAssuranceReport {
  schema_version: string;
  generated_at: string;
  git_commit: string;
  policy_sha256: string;
  python_version: string;
  platform_system: string;
  execution_profile: string;
  frameworks: {
    owasp_llm_top_10: string;
    owasp_agentic_top_10: string;
    mitre_atlas: string;
  };
  overall_status: "pass" | "fail" | "not_run";
  summary: {
    total_cases: number;
    counts: {
      pass: number;
      fail: number;
      error: number;
      not_run: number;
    };
  };
  out_of_scope_controls: string[];
  cases: AssuranceCaseRecord[];
}

export interface PendingApproval {
  approval_id: string;
  session_id: string;
  mcp_server: string | null;
  tool_name: string;
  arguments: Record<string, unknown>;
  reasons: string[];
  audit_id: string;
  created_at: string;
  mcp_method: string | null;
}

export interface ViewerStatus {
  airlock_ledger_configured: boolean;
  gateway_audit_configured: boolean;
  assurance_report_configured: boolean;
  approval_relay_configured: boolean;
}
