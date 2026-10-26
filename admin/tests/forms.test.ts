import { describe, expect, it } from "vitest";
import { settingsDiff } from "@/lib/settings-form";
import type { Settings } from "@/lib/types";
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
    lockout_threshold: "5",
    lockout_duration_minutes: "15",
    key_rotation_grace_hours: "24",
  };

  it("sends nothing when nothing changed", () => {
    expect(settingsDiff(before, form, "10.0.0.0/8\n", true, false)).toEqual({});
  });

  it("sends the changed fields only", () => {
    expect(
      settingsDiff(
        before,
        { ...form, min_password_length: "14", lockout_threshold: "" },
        "10.0.0.0/8\n192.168.1.1",
        true,
        true,
      ),
    ).toEqual({
      min_password_length: 14,
      ip_allowlist: ["10.0.0.0/8", "192.168.1.1"],
      suspicious_login_email_enabled: true,
    });
  });
});
