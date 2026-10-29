import { describe, expect, it } from "vitest";
import {
  createdMessage,
  emptyTimeoutDraft,
  endDate,
  fromLocalInput,
  isCurrent,
  signOutNote,
  timeoutBody,
  timeoutPatch,
  timeoutSummary,
  toLocalInput,
  type TimeoutDraft,
} from "@/lib/timeout-form";

// Local times: the form's inputs have no zone, so the expectations are
// built with the same local clock (the test passes in any TZ).
const now = new Date(2026, 10, 2, 9, 0); // 2 Nov 2026, 09:00 local
const draft = (d: Partial<TimeoutDraft> = {}): TimeoutDraft => ({
  ...emptyTimeoutDraft(),
  targetId: "u-1",
  targetName: "alice",
  reason: "investigation",
  ...d,
});
const iso = (d: Date) => d.toISOString();
const fmt = (d: Date) => toLocalInput(d).replace("T", " ");

describe("timeout form: create", () => {
  it("pre-fills a target from the URL, a user by default, 24 hours", () => {
    expect(emptyTimeoutDraft({ type: "group", id: "g-1", name: "staff" })).toMatchObject({
      targetType: "group",
      targetId: "g-1",
      targetName: "staff",
      end: "24h",
      startLater: false,
    });
    expect(emptyTimeoutDraft({ type: "realm" }).targetType).toBe("user");
  });

  it("starts now: no starts_at, the end from now", () => {
    const r = timeoutBody(draft({ end: "1h" }), now);
    expect(r).toEqual({
      body: {
        target_type: "user",
        target_id: "u-1",
        reason: "investigation",
        ends_at: iso(new Date(2026, 10, 2, 10, 0)),
      },
    });
  });

  it("no end: no ends_at", () => {
    const r = timeoutBody(draft({ end: "none" }), now);
    expect("body" in r && r.body.ends_at).toBe(undefined);
  });

  it("starts later: the duration counts from the start", () => {
    const r = timeoutBody(draft({ startLater: true, startAt: "2026-11-03T08:30", end: "7d" }), now);
    expect(r).toEqual({
      body: {
        target_type: "user",
        target_id: "u-1",
        reason: "investigation",
        starts_at: iso(new Date(2026, 10, 3, 8, 30)),
        ends_at: iso(new Date(2026, 10, 10, 8, 30)),
      },
    });
  });

  it("until a date", () => {
    const r = timeoutBody(draft({ end: "date", endAt: "2026-11-05T18:00" }), now);
    expect("body" in r && r.body.ends_at).toBe(iso(new Date(2026, 10, 5, 18, 0)));
  });

  it.each([
    [{ targetId: "" }, "target_id"],
    [{ reason: "   " }, "reason"],
    [{ startLater: true, startAt: "" }, "starts_at"],
    [{ startLater: true, startAt: "2026-11-01T08:00" }, "starts_at"], // in the past
    [{ end: "date" as const, endAt: "" }, "ends_at"],
    [{ end: "date" as const, endAt: "2026-11-02T08:00" }, "ends_at"], // before now
  ])("refuses %o (%s)", (d, field) => {
    expect(timeoutBody(draft(d), now)).toMatchObject({ field });
  });

  it("trims the reason", () => {
    const r = timeoutBody(draft({ reason: "  spam  " }), now);
    expect("body" in r && r.body.reason).toBe("spam");
  });
});

describe("timeout form: change", () => {
  const t = { reason: "investigation", ends_at: iso(new Date(2026, 10, 3, 9, 0)) };

  it("sends only what changed", () => {
    expect(timeoutPatch(t, "investigation", "keep", "")).toBeNull();
    expect(timeoutPatch(t, " fraud ", "keep", "")).toEqual({ body: { reason: "fraud" } });
    expect(timeoutPatch(t, "investigation", "none", "")).toEqual({ body: { ends_at: "" } });
    expect(timeoutPatch({ ...t, ends_at: null }, "investigation", "none", "")).toBeNull();
    expect(timeoutPatch(t, "investigation", "date", "2026-11-04T12:00")).toEqual({
      body: { ends_at: iso(new Date(2026, 10, 4, 12, 0)) },
    });
    expect(timeoutPatch(t, "investigation", "date", toLocalInput(new Date(t.ends_at)))).toBeNull();
  });

  it("refuses an empty reason or a missing date", () => {
    expect(timeoutPatch(t, "", "keep", "")).toMatchObject({ field: "reason" });
    expect(timeoutPatch(t, "x", "date", "")).toMatchObject({ field: "ends_at" });
  });
});

describe("timeout form: texts and times", () => {
  it("says what will happen", () => {
    expect(timeoutSummary(draft({ end: "1h" }), fmt, now)).toBe(
      "alice cannot sign in or get a token until 2026-11-02 10:00.",
    );
    expect(timeoutSummary(draft({ targetType: "group", targetName: "staff", end: "none" }), fmt, now)).toBe(
      "No member of staff can sign in or get a token until the timeout is lifted.",
    );
    expect(
      timeoutSummary(
        draft({ targetType: "client", targetName: "Wiki", startLater: true, startAt: "2026-11-03T08:00", end: "1h" }),
        fmt,
        now,
      ),
    ).toBe("Nobody can sign in to Wiki from 2026-11-03 08:00 until 2026-11-03 09:00.");
    expect(signOutNote("client", false)).toContain("every token issued to this application");
    expect(signOutNote("group", true)).toMatch(/^When it starts, every member is signed out/);
  });

  it("round-trips local times to the minute", () => {
    const d = new Date(2026, 0, 5, 7, 4, 59);
    expect(toLocalInput(d)).toBe("2026-01-05T07:04");
    expect(fromLocalInput("2026-01-05T07:04")?.getTime()).toBe(new Date(2026, 0, 5, 7, 4).getTime());
    expect(fromLocalInput("")).toBeNull();
    expect(fromLocalInput("not a date")).toBeNull();
    expect(endDate("date", "", now)).toBe("invalid");
    expect(endDate("none", "", now)).toBeNull();
  });

  it("tells what the start revoked", () => {
    const base = { status: "active" as const, starts_at: "2026-11-02T09:00:00Z", target_type: "user" as const };
    const f = (s: string) => `<${s}>`;
    expect(createdMessage({ ...base, status: "scheduled" }, f)).toBe("Timeout scheduled for <2026-11-02T09:00:00Z>");
    expect(createdMessage({ ...base, sign_out: { users: 1, sessions: 2, tokens: 0 } }, f)).toBe(
      "Suspended: 2 sessions revoked",
    );
    expect(createdMessage({ ...base, sign_out: { users: 0, sessions: 0, tokens: 0 } }, f)).toBe(
      "Suspended (nobody was signed in)",
    );
    expect(createdMessage({ ...base, target_type: "client", sign_out: { users: 0, sessions: 0, tokens: 1 } }, f)).toBe(
      "Suspended: 1 token revoked",
    );
    expect(createdMessage({ ...base, sign_out_pending: true }, f)).toMatch(/retried/);
  });

  it("only scheduled and active timeouts can change", () => {
    expect(isCurrent({ status: "active" })).toBe(true);
    expect(isCurrent({ status: "scheduled" })).toBe(true);
    expect(isCurrent({ status: "ended" })).toBe(false);
    expect(isCurrent({ status: "lifted" })).toBe(false);
  });
});
