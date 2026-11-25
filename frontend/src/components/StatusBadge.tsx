import type { ReactNode } from "react";

export type BadgeTone = "pass" | "info" | "warn" | "block" | "aad" | "muted";

interface StatusBadgeProps {
  tone: BadgeTone;
  children: ReactNode;
}

export function StatusBadge({ tone, children }: StatusBadgeProps) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}

export function toneForSeverity(severity: string): BadgeTone {
  switch (severity.toLowerCase()) {
    case "aad_fire":
    case "aad_triggered_unconfirmed":
    case "integrity_compromised":
    case "deny":
    case "blocked_egress":
    case "chain_invalid":
    case "fail":
    case "error":
      return "aad";
    case "block":
    case "blocked_activity":
    case "high":
    case "require_approval":
      return "block";
    case "warn":
    case "observed_violations":
    case "observed_aad":
    case "observed_block":
    case "observe":
    case "taint":
    case "tainted":
    case "medium":
      return "warn";
    case "allow":
    case "aad_contained":
    case "clean":
    case "low":
    case "pass":
    case "enforce":
    case "chain_valid":
      return "pass";
    case "info":
      return "info";
    default:
      return "muted";
  }
}
