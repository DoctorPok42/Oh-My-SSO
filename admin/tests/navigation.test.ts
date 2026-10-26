import { describe, expect, it } from "vitest";
import { beginPending, isContentPending, isPending } from "@/components/console/navigation-progress";
import { progressAt } from "@/components/console/progress-curve";
import { searchHref } from "@/components/console/search-form";

describe("progress bar counter", () => {
  it("shows while at least one wait runs, dims only for content navigations", () => {
    expect(isPending()).toBe(false);
    const drawer = beginPending(); // a drawer opening: bar only
    expect([isPending(), isContentPending()]).toEqual([true, false]);
    const link = beginPending(true); // a link: bar and dimmed content
    expect([isPending(), isContentPending()]).toEqual([true, true]);
    link();
    expect([isPending(), isContentPending()]).toEqual([true, false]);
    drawer();
    expect(isPending()).toBe(false);
  });

  it("ending a wait twice counts once", () => {
    const a = beginPending(true);
    const b = beginPending(true);
    a();
    a();
    expect(isContentPending()).toBe(true);
    b();
    expect([isPending(), isContentPending()]).toEqual([false, false]);
  });
});

describe("searchHref", () => {
  it("keeps the non-empty fields, trimmed", () => {
    expect(
      searchHref("/r/demo/users", [
        ["q", "  alice "],
        ["status", ""],
      ]),
    ).toBe("/r/demo/users?q=alice");
  });
  it("is the bare action when every field is empty", () => {
    expect(searchHref("/r/demo/audit", [["action", " "]])).toBe("/r/demo/audit");
  });
  it("encodes what it keeps", () => {
    expect(
      searchHref("/r/demo/audit", [
        ["action", "admin.client.update"],
        ["user", "a b&c"],
      ]),
    ).toBe("/r/demo/audit?action=admin.client.update&user=a+b%26c");
  });
});

describe("progress curve (worker bar)", () => {
  it("starts quickly, never passes 95 %, never stops moving", () => {
    expect(progressAt(0)).toBeCloseTo(0.08, 2);
    expect(progressAt(500)).toBeGreaterThan(0.3);
    let prev = progressAt(0);
    for (let t = 250; t <= 20_000; t += 250) {
      const p = progressAt(t);
      expect(p).toBeLessThanOrEqual(0.95);
      expect(p).toBeGreaterThan(prev); // still moving, even after 20 s
      prev = p;
    }
  });
});
