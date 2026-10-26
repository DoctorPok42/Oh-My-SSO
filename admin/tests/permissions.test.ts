import { describe, expect, it } from "vitest";
import { needsSignIn, needsStepUp, ApiError } from "@/lib/api-error";
import { can, canWrite, stepUpFresh } from "@/lib/permissions";

describe("permissions", () => {
  const auditor = { permissions: ["client:read", "session:read"] };
  const admin = { permissions: ["client:read", "client:write", "session:read", "session:revoke"] };

  it("reads /me's permission list", () => {
    expect(can(auditor, "client")).toBe(true);
    expect(canWrite(auditor, "client")).toBe(false);
    expect(canWrite(admin, "client")).toBe(true);
    expect(canWrite(admin, "session")).toBe(true); // sessions are revoked, not written
    expect(can(null, "client")).toBe(false);
  });

  it("knows when changes are unlocked (step-up)", () => {
    const now = Date.parse("2026-10-23T12:00:00Z");
    expect(stepUpFresh({ step_up_fresh_until: "2026-10-23T12:05:00Z" }, now)).toBe(true);
    expect(stepUpFresh({ step_up_fresh_until: "2026-10-23T12:00:05Z" }, now)).toBe(false); // too close
    expect(stepUpFresh({ step_up_fresh_until: null }, now)).toBe(false);
  });
});

describe("API errors", () => {
  it("classifies what fixes them", () => {
    expect(needsStepUp({ error: "step_up_required" })).toBe(true);
    expect(needsStepUp({ error: "mfa_enrollment_required" })).toBe(true);
    expect(needsSignIn({ status: 401 })).toBe(true);
    expect(needsSignIn({ error: "invalid_token" })).toBe(true);
    expect(needsSignIn({ error: "forbidden", status: 403 })).toBe(false);
  });

  it("serialises for Server Action results", () => {
    const e = new ApiError(409, { error: "last_admin", message: "keep one admin", field: "status" });
    expect(e.toJSON()).toEqual({ error: "last_admin", message: "keep one admin", field: "status", status: 409 });
    expect(e.code).toBe("last_admin");
  });
});
