import { Badge } from "@/components/ui/badge";

// The DS badge mapping, in one place.
const TONES: Record<string, "success" | "warning" | "danger" | "info" | "neutral"> = {
  active: "success",
  healthy: "success",
  success: "success",
  enrolled: "success",
  pending: "warning",
  rotating: "warning",
  degraded: "warning",
  invited: "warning",
  locked: "warning",
  warning: "warning",
  suspicious: "warning",
  inactive: "neutral",
  disabled: "neutral",
  retired: "neutral",
  expired: "neutral",
  suspended: "danger",
  down: "danger",
  failure: "danger",
  revoked: "danger",
  error: "danger",
  critical: "danger",
};

export function StatusBadge({ status, label }: { status: string; label?: string }) {
  const text = label ?? status.charAt(0).toUpperCase() + status.slice(1).replaceAll("_", " ");
  return <Badge tone={TONES[status] ?? "neutral"}>{text}</Badge>;
}

export function ManagedBadge({ managedBy }: { managedBy: string }) {
  if (managedBy !== "config") return null;
  return <Badge tone="neutral">Managed by config</Badge>;
}

export function ProtocolBadge({ protocol }: { protocol: string }) {
  const label = protocol === "saml2" ? "SAML 2.0" : protocol === "both" ? "OIDC + SAML" : "OIDC";
  return <Badge tone="info">{label}</Badge>;
}
