"use client";

import { Badge } from "@/components/ui/badge";
import { m, type Msg } from "@/i18n";
import { useT } from "@/i18n/client";

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

// The words of the statuses the API sends; an unknown one is shown as it is.
const LABELS: Record<string, Msg> = {
  active: m("status.active", "Active"),
  healthy: m("status.healthy", "Healthy"),
  success: m("status.success", "Success"),
  enrolled: m("status.enrolled", "Enrolled"),
  pending: m("status.pending", "Pending"),
  rotating: m("status.rotating", "Rotating"),
  degraded: m("status.degraded", "Degraded"),
  invited: m("status.invited", "Invited"),
  locked: m("status.locked", "Locked"),
  warning: m("status.warning", "Warning"),
  suspicious: m("status.suspicious", "Suspicious"),
  inactive: m("status.inactive", "Inactive"),
  disabled: m("status.disabled", "Disabled"),
  retired: m("status.retired", "Retired"),
  expired: m("status.expired", "Expired"),
  suspended: m("status.suspended", "Suspended"),
  down: m("status.down", "Down"),
  failure: m("status.failure", "Failure"),
  revoked: m("status.revoked", "Revoked"),
  error: m("status.error", "Error"),
  critical: m("status.critical", "Critical"),
  info: m("status.info", "Info"),
  not_configured: m("status.not_configured", "Not configured"),
};

export function StatusBadge({ status, label }: { status: string; label?: string }) {
  const { tm } = useT();
  const known = LABELS[status];
  const text = label ?? (known ? tm(known) : status.charAt(0).toUpperCase() + status.slice(1).replaceAll("_", " "));
  return <Badge tone={TONES[status] ?? "neutral"}>{text}</Badge>;
}

export function ManagedBadge({ managedBy }: { managedBy: string }) {
  const { t } = useT();
  if (managedBy !== "config") return null;
  return <Badge tone="neutral">{t("status.managed_by_config", "Managed by config")}</Badge>;
}

export function ProtocolBadge({ protocol }: { protocol: string }) {
  const label = protocol === "saml2" ? "SAML 2.0" : protocol === "both" ? "OIDC + SAML" : "OIDC";
  return <Badge tone="info">{label}</Badge>;
}
