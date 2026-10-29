import { describe, expect, it } from "vitest";
import { realmMfaDraft, realmMfaPatch } from "@/lib/mfa-form";
import { settingsDiff } from "@/lib/settings-form";
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
    notification_email_enabled: true,
    suspicious_login_email_enabled: false,
    updated_at: "",
    updated_by: "",
    email_enabled: true,
  } satisfies Settings;
  const form = {
    min_password_length: "12",
    password_expiry_days: "0",
    password_reset_ttl_minutes: "30",
    session_idle_minutes: "30",
    session_max_hours: "8",
    remember_me_idle_days: "7",
    remember_me_max_days: "30",
    lockout_threshold: "5",
    lockout_duration_minutes: "15",
    key_rotation_grace_hours: "24",
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
