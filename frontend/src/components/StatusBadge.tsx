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
  switch (severity) {
    case "AAD_FIRE":
    case "AAD_TRIGGERED_UNCONFIRMED":
    case "INTEGRITY_COMPROMISED":
    case "DENY":
    case "fail":
    case "error":
      return "aad";
    case "BLOCK":
    case "BLOCKED_ACTIVITY":
    case "HIGH":
    case "REQUIRE_APPROVAL":
      return "block";
    case "WARN":
    case "OBSERVED_VIOLATIONS":
    case "TAINT":
    case "MEDIUM":
      return "warn";
    case "ALLOW":
    case "AAD_CONTAINED":
    case "CLEAN":
    case "LOW":
    case "pass":
      return "pass";
    case "INFO":
      return "info";
    default:
      return "muted";
  }
}
