import { describe, expect, it } from "vitest";
import { realmMfaDraft, realmMfaPatch } from "@/lib/mfa-form";
import {
  auditRetentionChoices,
  fieldSection,
  MAIL_FIELDS,
  NUMBERS,
  settingsDiff,
  settingsSection,
  shortensAuditRetention,
} from "@/lib/settings-form";
import type { MfaPolicies, Settings } from "@/lib/types";
import { profilePatch, sameSet } from "@/lib/user-form";

describe("user form", () => {
  it("sends only profile changes, removed keys as null", () => {
    const before = { name: "Alice", department: "R&D", phone: "1" };
    expect(
      profilePatch(before, "Alice M.", [
        { key: "department", value: "R&D" },
        { key: "site", value: "Lyon" },
        { key: " ", value: "ignored" },
      ]),
    ).toEqual({ name: "Alice M.", site: "Lyon", phone: null });
    expect(profilePatch({}, "", [])).toEqual({});
  });

  it("compares memberships in any order", () => {
    expect(sameSet(["a", "b"], ["b", "a"])).toBe(true);
    expect(sameSet(["a"], ["a", "b"])).toBe(false);
  });
});

describe("settings form", () => {
  const before = {
    managed_by: "ui",
    min_password_length: 12,
    password_expiry_days: 0,
    password_reset_ttl_minutes: 30,
    invite_ttl_hours: 4,
    session_idle_minutes: 30,
    session_max_hours: 8,
    remember_me_enabled: true,
    remember_me_idle_days: 7,
    remember_me_max_days: 30,
    lockout_threshold: 5,
    lockout_duration_minutes: 15,
    ip_allowlist: ["10.0.0.0/8"],
    mfa_required_globally: false,
    mfa_step_up_max_age_minutes: 10,
    key_rotation_grace_hours: 24,
    bulk_limit: 100,
    expired_data_retention_days: 90,
    audit_log_retention_days: 0,
    notification_email_enabled: true,
    suspicious_login_email_enabled: false,
    updated_at: "",
    updated_by: "",
    email_enabled: true,
    default_locale: "en",
    mail_from_name: "",
    mail_from_address: "",
    mail_reply_to: "",
    mail_logo_url: "",
    languages: [
      { tag: "en", name: "English" },
      { tag: "fr", name: "Français" },
    ],
  } satisfies Settings;
  const form = {
    min_password_length: "12",
    password_reset_ttl_minutes: "30",
    invite_ttl_hours: "4",
    session_idle_minutes: "30",
    session_max_hours: "8",
    remember_me_idle_days: "7",
    remember_me_max_days: "30",
    lockout_threshold: "5",
    lockout_duration_minutes: "15",
    key_rotation_grace_hours: "24",
    bulk_limit: "100",
    expired_data_retention_days: "90",
    audit_log_retention_days: "0",
  };

  it("sends nothing when nothing changed", () => {
    const toggles = { notif: true, suspicious: false, remember: true };
    expect(settingsDiff(before, form, "10.0.0.0/8\n", toggles)).toEqual({});
  });

  it("sends the changed fields only", () => {
    expect(
      settingsDiff(before, { ...form, min_password_length: "14", lockout_threshold: "" }, "10.0.0.0/8\n192.168.1.1", {
        notif: true,
        suspicious: true,
        remember: true,
      }),
    ).toEqual({
      min_password_length: 14,
      ip_allowlist: ["10.0.0.0/8", "192.168.1.1"],
      suspicious_login_email_enabled: true,
    });
  });

  it("sends the keep-me-signed-in switch and its durations", () => {
    expect(
      settingsDiff(before, { ...form, remember_me_idle_days: "14", remember_me_max_days: "30" }, "10.0.0.0/8", {
        notif: true,
        suspicious: false,
        remember: false,
      }),
    ).toEqual({ remember_me_enabled: false, remember_me_idle_days: 14 });
  });

  it("sends the bulk limit when it changed", () => {
    const toggles = { notif: true, suspicious: false, remember: true };
    expect(settingsDiff(before, { ...form, bulk_limit: "250" }, "10.0.0.0/8", toggles)).toEqual({ bulk_limit: 250 });
  });

  it("sends the data retention when it changed", () => {
    const toggles = { notif: true, suspicious: false, remember: true };
    expect(settingsDiff(before, { ...form, expired_data_retention_days: "365" }, "10.0.0.0/8", toggles)).toEqual({
      expired_data_retention_days: 365,
    });
  });

  it("sends the audit log retention when it changed, back to forever included", () => {
    const toggles = { notif: true, suspicious: false, remember: true };
    expect(settingsDiff(before, { ...form, audit_log_retention_days: "365" }, "10.0.0.0/8", toggles)).toEqual({
      audit_log_retention_days: 365,
    });
    const year = { ...before, audit_log_retention_days: 365 };
    expect(settingsDiff(year, form, "10.0.0.0/8", toggles)).toEqual({ audit_log_retention_days: 0 });
  });

  it("offers the usual audit retentions, and the saved one when it is another", () => {
    const usual = [30, 90, 180, 365, 730, 1095, 1825, 2555, 3650, 0];
    expect(auditRetentionChoices(0)).toEqual(usual);
    expect(auditRetentionChoices(365)).toEqual(usual);
    expect(auditRetentionChoices(200)).toEqual([30, 90, 180, 200, 365, 730, 1095, 1825, 2555, 3650, 0]);
  });

  it("warns when a new audit retention deletes entries kept today", () => {
    expect(shortensAuditRetention(0, 365)).toBe(true);
    expect(shortensAuditRetention(365, 90)).toBe(true);
    expect(shortensAuditRetention(90, 365)).toBe(false);
    expect(shortensAuditRetention(365, 365)).toBe(false);
    expect(shortensAuditRetention(90, 0)).toBe(false);
    expect(shortensAuditRetention(0, 0)).toBe(false);
    expect(shortensAuditRetention(0, Number.NaN)).toBe(false);
  });

  it("sends the default language when it changed", () => {
    const toggles = { notif: true, suspicious: false, remember: true };
    expect(settingsDiff(before, form, "10.0.0.0/8", toggles, "en")).toEqual({});
    expect(settingsDiff(before, form, "10.0.0.0/8", toggles, "fr")).toEqual({ default_locale: "fr" });
  });

  it("sends the e-mail sender fields that changed, empty ones included", () => {
    const toggles = { notif: true, suspicious: false, remember: true };
    const blank = { mail_from_name: "", mail_from_address: "", mail_reply_to: "", mail_logo_url: "" };
    expect(settingsDiff(before, form, "10.0.0.0/8", toggles, "en", blank)).toEqual({});
    expect(
      settingsDiff(before, form, "10.0.0.0/8", toggles, "en", {
        ...blank,
        mail_from_name: " Acme ",
        mail_reply_to: "help@acme.test",
      }),
    ).toEqual({ mail_from_name: "Acme", mail_reply_to: "help@acme.test" });
    const saved = { ...before, mail_from_name: "Acme", mail_logo_url: "https://acme.test/logo.png" };
    expect(settingsDiff(saved, form, "10.0.0.0/8", toggles, "en", { ...blank, mail_from_name: "Acme" })).toEqual({
      mail_logo_url: "",
    });
  });
});

describe("settings sub-pages", () => {
  it("reads ?tab=, the first sub-page otherwise", () => {
    expect(settingsSection("email")).toBe("email");
    expect(settingsSection("audit")).toBe("audit");
    expect(settingsSection(undefined)).toBe("general");
    expect(settingsSection("nope")).toBe("general");
    expect(settingsSection("constructor")).toBe("general");
  });

  it("knows the sub-page of every field of the form", () => {
    for (const k of [...NUMBERS, ...MAIL_FIELDS]) expect(fieldSection(k), k).toBeDefined();
    expect(fieldSection("default_locale")).toBe("general");
    expect(fieldSection("key_rotation_grace_hours")).toBe("security");
    expect(fieldSection("remember_me_max_days")).toBe("sessions");
    expect(fieldSection("mail_reply_to")).toBe("email");
    expect(fieldSection("audit_log_retention_days")).toBe("audit");
    expect(fieldSection("unknown")).toBeUndefined();
  });
});

describe("realm MFA form", () => {
  const before: MfaPolicies = {
    required_globally: false,
    step_up_max_age_minutes: 10,
    trusted_devices_enabled: true,
    trusted_device_days: 30,
    roles: [],
    clients: [],
    known_methods: [],
  };

  it("sends only what changed", () => {
    const d = realmMfaDraft(before);
    expect(realmMfaPatch(before, d, false)).toEqual({});
    expect(realmMfaPatch(before, { ...d, trustedDays: "14" }, false)).toEqual({ trusted_device_days: 14 });
    expect(realmMfaPatch(before, { ...d, trusted: false, trustedDays: "14" }, false)).toEqual({
      trusted_devices_enabled: false,
    });
    expect(realmMfaPatch(before, { ...d, required: true, maxAge: "5" }, false)).toEqual({
      required_globally: true,
      step_up_max_age_minutes: 5,
    });
  });

  it("never sends the locked switches of the master realm", () => {
    const master = { ...before, required_globally: true, trusted_devices_enabled: false };
    const d = { ...realmMfaDraft(master), required: false, trusted: true, maxAge: "60" };
    expect(realmMfaPatch(master, d, true)).toEqual({ step_up_max_age_minutes: 60 });
  });
});
