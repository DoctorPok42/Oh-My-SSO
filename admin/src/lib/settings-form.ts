import { lines } from "@/lib/format";
import type { Settings } from "@/lib/types";

// The settings form's helpers (pure, unit-tested in tests/settings-form.test.ts).

export type SettingsPatch = Partial<
  Pick<
    Settings,
    | "min_password_length"
    | "password_reset_ttl_minutes"
    | "invite_ttl_hours"
    | "session_idle_minutes"
    | "session_max_hours"
    | "remember_me_enabled"
    | "remember_me_idle_days"
    | "remember_me_max_days"
    | "lockout_threshold"
    | "lockout_duration_minutes"
    | "ip_allowlist"
    | "key_rotation_grace_hours"
    | "notification_email_enabled"
    | "suspicious_login_email_enabled"
    | "default_locale"
    | "mail_from_name"
    | "mail_from_address"
    | "mail_reply_to"
    | "mail_logo_url"
    | "bulk_limit"
    | "expired_data_retention_days"
    | "audit_log_retention_days"
  >
>;

/** expired_data_retention_days: its bounds and default (service.MinRetentionDays…). */
export const RETENTION_DAYS = { min: 7, max: 3650, default: 90 } as const;

/** audit_log_retention_days: the default (service.DefaultAuditLogRetentionDays). */
export const AUDIT_RETENTION_DEFAULT = 365;

/** The choices offered, in days (30 to 3650); 0 (unlimited) is always offered, last. */
export const AUDIT_RETENTION_CHOICES: readonly number[] = [30, 90, 180, 365, 730, 1095, 1825, 2555, 3650];

/**
 * The choices of the audit retention select: the usual ones, plus the saved
 * value when it is another one (set through the Admin API, 30 to 3650 days),
 * so that the select shows it. Shortest first, "forever" last.
 */
export function auditRetentionChoices(saved: number): number[] {
  const days = new Set(AUDIT_RETENTION_CHOICES);
  if (saved > 0) days.add(saved);
  return [...[...days].sort((a, b) => a - b), 0];
}

/**
 * Whether saving `after` (days, 0 = forever) in place of `before` deletes
 * audit log entries that are kept today: a shorter retention, or one where
 * there was none.
 */
export function shortensAuditRetention(before: number, after: number): boolean {
  if (!Number.isFinite(after) || after <= 0) return false;
  return before <= 0 || after < before;
}

/** The e-mail sender fields of the form (all optional). */
export const MAIL_FIELDS = ["mail_from_name", "mail_from_address", "mail_reply_to", "mail_logo_url"] as const;
export type MailKey = (typeof MAIL_FIELDS)[number];
export type MailForm = Record<MailKey, string>;

export const NUMBERS = [
  "min_password_length",
  "password_reset_ttl_minutes",
  "invite_ttl_hours",
  "session_idle_minutes",
  "session_max_hours",
  "remember_me_idle_days",
  "remember_me_max_days",
  "lockout_threshold",
  "lockout_duration_minutes",
  "key_rotation_grace_hours",
  "bulk_limit",
  "expired_data_retention_days",
  "audit_log_retention_days",
] as const;
export type NumberKey = (typeof NUMBERS)[number];

/** The sub-pages of the settings (?tab=; no tab: the first one). One form across them. */
export const SETTINGS_SECTIONS = ["general", "security", "sessions", "email", "audit"] as const;
export type SettingsSection = (typeof SETTINGS_SECTIONS)[number];

export function settingsSection(tab?: string): SettingsSection {
  return SETTINGS_SECTIONS.find((s) => s === tab) ?? "general";
}

const SECTION_FIELDS: Record<SettingsSection, readonly string[]> = {
  general: ["default_locale", "bulk_limit", "expired_data_retention_days"],
  security: [
    "min_password_length",
    "password_reset_ttl_minutes",
    "invite_ttl_hours",
    "lockout_threshold",
    "lockout_duration_minutes",
    "ip_allowlist",
    "key_rotation_grace_hours",
  ],
  sessions: [
    "session_idle_minutes",
    "session_max_hours",
    "remember_me_enabled",
    "remember_me_idle_days",
    "remember_me_max_days",
  ],
  email: ["notification_email_enabled", "suspicious_login_email_enabled", ...MAIL_FIELDS],
  audit: ["audit_log_retention_days"],
};

/** The section that shows a field: an error on another one must not go unseen. */
export function fieldSection(field: string): SettingsSection | undefined {
  return SETTINGS_SECTIONS.find((s) => SECTION_FIELDS[s].includes(field));
}

/** The on/off settings of the form. */
export type SettingsToggles = {
  notif: boolean;
  suspicious: boolean;
  remember: boolean;
};

/** The changed fields only (PATCH). */
export function settingsDiff(
  before: Settings,
  form: Record<NumberKey, string>,
  allowlist: string,
  toggles: SettingsToggles,
  locale?: string,
  mail?: MailForm,
): SettingsPatch {
  const patch: SettingsPatch = {};
  for (const k of NUMBERS) {
    const v = Number(form[k]);
    if (form[k].trim() !== "" && v !== before[k]) patch[k] = v;
  }
  const ips = lines(allowlist);
  if (ips.join("\n") !== (before.ip_allowlist ?? []).join("\n")) patch.ip_allowlist = ips;
  if (toggles.notif !== before.notification_email_enabled) patch.notification_email_enabled = toggles.notif;
  if (toggles.suspicious !== before.suspicious_login_email_enabled)
    patch.suspicious_login_email_enabled = toggles.suspicious;
  if (toggles.remember !== before.remember_me_enabled) patch.remember_me_enabled = toggles.remember;
  if (locale && locale !== (before.default_locale || "en")) patch.default_locale = locale;
  if (mail) {
    // An empty field is a valid value (back to the server default), so it
    // is sent when it differs from what is saved.
    for (const k of MAIL_FIELDS) {
      const v = mail[k].trim();
      if (v !== (before[k] ?? "")) patch[k] = v;
    }
  }
  return patch;
}
