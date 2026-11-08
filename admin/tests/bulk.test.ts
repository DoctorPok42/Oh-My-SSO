import { describe, expect, it } from "vitest";
import {
  BULK_LIMIT,
  bulkLimitOf,
  bulkReasons,
  bulkTone,
  collectIds,
  EMPTY_SELECTION,
  pageState,
  parseIdentifiers,
  parseSelection,
  toggleId,
  togglePage,
  type BulkItem,
} from "@/lib/bulk";

const ids = (n: number, from = 0) => Array.from({ length: n }, (_, i) => `id-${from + i}`);

describe("selection", () => {
  it("toggles one id", () => {
    expect(toggleId(["a"], "b")).toEqual(["a", "b"]);
    expect(toggleId(["a", "b"], "a")).toEqual(["b"]);
  });

  it("adds nothing past the limit, but still removes", () => {
    const full = ids(BULK_LIMIT);
    expect(toggleId(full, "another")).toEqual(full);
    expect(toggleId(full, "id-0")).toHaveLength(BULK_LIMIT - 1);
  });

  it("selects a page, keeping what other pages hold", () => {
    expect(togglePage(["x"], ["a", "b"])).toEqual(["x", "a", "b"]);
    expect(togglePage(["x", "a"], ["a", "b"])).toEqual(["x", "a", "b"]);
  });

  it("unselects a page that is fully selected", () => {
    expect(togglePage(["x", "a", "b"], ["a", "b"])).toEqual(["x"]);
  });

  it("fills up to the limit", () => {
    expect(togglePage(ids(99), ["a", "b"])).toEqual([...ids(99), "a"]);
  });

  it("tells the state of the select-all box", () => {
    expect(pageState([], ["a", "b"])).toBe(false);
    expect(pageState(["a"], ["a", "b"])).toBe("indeterminate");
    expect(pageState(["a", "b", "x"], ["a", "b"])).toBe(true);
    expect(pageState(["x"], [])).toBe(false);
  });
});

describe("result", () => {
  const item = (status: BulkItem["status"], code?: string, message?: string): BulkItem => ({
    id: "x",
    label: "x",
    status,
    code,
    message,
  });

  it("groups the reasons, the most frequent first", () => {
    const items = [
      item("done"),
      item("skipped", "not_locked", "not locked"),
      item("skipped", "self_change", "your own account"),
      item("skipped", "self_change", "your own account"),
    ];
    expect(bulkReasons(items)).toEqual([
      { code: "self_change", message: "your own account", count: 2 },
      { code: "not_locked", message: "not locked", count: 1 },
    ]);
  });

  it("chooses the tone", () => {
    expect(bulkTone({ done: 3, skipped: 0, failed: 0 })).toBe("success");
    expect(bulkTone({ done: 3, skipped: 1, failed: 0 })).toBe("warning");
    expect(bulkTone({ done: 3, skipped: 1, failed: 1 })).toBe("danger");
  });
});

describe("collectIds", () => {
  const source = (all: string[]) => {
    const calls: number[] = [];
    const fetchPage = async (offset: number, limit: number) => {
      calls.push(offset);
      return { items: all.slice(offset, offset + limit).map((id) => ({ id })), total: all.length };
    };
    return { calls, fetchPage };
  };

  it("stops at the limit", async () => {
    const { calls, fetchPage } = source(ids(500));
    expect(await collectIds(fetchPage, [])).toEqual(ids(100));
    expect(calls).toEqual([0]);
  });

  it("leaves out the excluded ids", async () => {
    const { fetchPage } = source(ids(3));
    expect(await collectIds(fetchPage, ["id-1"])).toEqual(["id-0", "id-2"]);
  });

  it("reads further pages when an earlier pass covers the first ones", async () => {
    const { calls, fetchPage } = source(ids(500));
    const got = await collectIds(fetchPage, ids(250));
    expect(got).toEqual(ids(100, 250));
    expect(calls).toEqual([0, 200]);
  });

  it("leaves out the rows that cannot be selected, and goes on until the limit", async () => {
    const { calls, fetchPage } = source(ids(400));
    const even = ({ id }: { id: string }) => Number(id.slice(3)) % 2 === 0;
    const got = await collectIds(fetchPage, [], even, 150);
    expect(got).toHaveLength(150);
    expect(got.at(-1)).toBe("id-298");
    expect(calls).toEqual([0, 200]);
  });

  it("ends with the results", async () => {
    const { calls, fetchPage } = source(ids(200));
    expect(await collectIds(fetchPage, ids(200))).toEqual([]);
    expect(calls).toEqual([0]);
  });
});

describe("parseIdentifiers", () => {
  it("splits on spaces, commas, semicolons and new lines, each name once", () => {
    expect(parseIdentifiers(" alice, bob@example.test;carol\n\ndave  alice ")).toEqual([
      "alice",
      "bob@example.test",
      "carol",
      "dave",
    ]);
    expect(parseIdentifiers("  ")).toEqual([]);
  });
});

describe("parseSelection", () => {
  it("reads what was saved", () => {
    expect(parseSelection(JSON.stringify({ selected: ["a"], fromFilter: true, seen: ["b"] }))).toEqual({
      selected: ["a"],
      fromFilter: true,
      seen: ["b"],
    });
  });

  it("treats anything else as an empty selection", () => {
    expect(parseSelection(null)).toEqual(EMPTY_SELECTION);
    expect(parseSelection("not json")).toEqual(EMPTY_SELECTION);
    expect(parseSelection('{"selected":"a"}').selected).toEqual([]);
    expect(parseSelection('{"selected":[1,"a"]}').selected).toEqual(["a"]);
  });

  it("never gives back more than the API takes", () => {
    expect(parseSelection(JSON.stringify({ selected: ids(150) })).selected).toHaveLength(BULK_LIMIT);
    expect(parseSelection(JSON.stringify({ selected: ids(150) }), 20).selected).toHaveLength(20);
  });
});

describe("bulkLimitOf", () => {
  it("keeps a limit the Settings accept, falls back to the default otherwise", () => {
    expect(bulkLimitOf(250)).toBe(250);
    expect(bulkLimitOf(1)).toBe(1);
    expect(bulkLimitOf(500)).toBe(500);
    for (const bad of [0, 501, 2.5, "100", null, undefined]) expect(bulkLimitOf(bad)).toBe(BULK_LIMIT);
  });
});
