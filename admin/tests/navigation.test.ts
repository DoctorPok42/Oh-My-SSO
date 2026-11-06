import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { beginPending, isContentPending, isPending, pendingTarget } from "@/components/console/navigation-progress";
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

describe("where the page is going", () => {
  it("is the latest running navigation, and nothing once they end", () => {
    expect(pendingTarget()).toBeNull();
    const first = beginPending(true, "/r/demo/users");
    const drawer = beginPending(); // a wait that goes nowhere
    const second = beginPending(true, "/r/demo/audit");
    expect(pendingTarget()).toBe("/r/demo/audit");
    second();
    second();
    expect(pendingTarget()).toBe("/r/demo/users");
    first();
    drawer();
    expect(pendingTarget()).toBeNull();
  });
});

// A Suspense fallback makes React hold back the real content for 300 ms
// (navigation-progress.tsx): a skeleton around a page's content sets a floor
// of 330 ms under every navigation, however fast the server. Slow pages get
// theirs from PendingContent. fallback={null} stays allowed for the drawers:
// a drawer has its own skeleton, and nothing else waits for it.
describe("console pages", () => {
  const dir = join(__dirname, "..", "src", "app", "r");
  const files = readdirSync(dir, { recursive: true, encoding: "utf8" }).map((f) => f.replaceAll("\\", "/"));

  it("have no loading.tsx", () => {
    expect(files.filter((f) => /(^|\/)loading\.tsx$/.test(f))).toEqual([]);
  });

  it("have no Suspense skeleton", () => {
    const withFallback = files.filter(
      (f) => f.endsWith(".tsx") && /fallback=\{(?!null\})/.test(readFileSync(join(dir, f), "utf8")),
    );
    expect(withFallback).toEqual([]);
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
        ["action", "client.updated"],
        ["user", "a b&c"],
      ]),
    ).toBe("/r/demo/audit?action=client.updated&user=a+b%26c");
  });
});
