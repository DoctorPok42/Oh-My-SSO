import { lines } from "@/lib/format";
import type { Settings } from "@/lib/types";

// The settings form's helpers (pure, unit-tested in tests/settings-form.test.ts).

export type SettingsPatch = Partial<
  Pick<
    Settings,
    | "min_password_length"
    | "password_expiry_days"
    | "password_reset_ttl_minutes"
    | "session_idle_minutes"
    | "session_max_hours"
    | "lockout_threshold"
    | "lockout_duration_minutes"
    | "ip_allowlist"
    | "key_rotation_grace_hours"
    | "notification_email_enabled"
    | "suspicious_login_email_enabled"
  >
>;

export const NUMBERS = [
  "min_password_length",
  "password_expiry_days",
  "password_reset_ttl_minutes",
  "session_idle_minutes",
  "session_max_hours",
  "lockout_threshold",
  "lockout_duration_minutes",
  "key_rotation_grace_hours",
] as const;
export type NumberKey = (typeof NUMBERS)[number];

/** The changed fields only (PATCH). */
export function settingsDiff(
  before: Settings,
  form: Record<NumberKey, string>,
  allowlist: string,
  notif: boolean,
  suspicious: boolean,
): SettingsPatch {
  const patch: SettingsPatch = {};
  for (const k of NUMBERS) {
    const v = Number(form[k]);
    if (form[k].trim() !== "" && v !== before[k]) patch[k] = v;
  }
  const ips = lines(allowlist);
  if (ips.join("\n") !== (before.ip_allowlist ?? []).join("\n")) patch.ip_allowlist = ips;
  if (notif !== before.notification_email_enabled) patch.notification_email_enabled = notif;
  if (suspicious !== before.suspicious_login_email_enabled) patch.suspicious_login_email_enabled = suspicious;
  return patch;
}
