import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  CACHE_TTL_MS,
  cached,
  cacheSize,
  clearCache,
  CONFIG_TTL_MS,
  invalidate,
  LIVE_TTL_MS,
  ttlOf,
  USERS_TTL_MS,
} from "@/lib/cache";

type R = { ok: boolean; data?: number };

describe("read cache", () => {
  beforeEach(() => {
    clearCache();
  });

  it("serves a read again within the TTL, and asks again after it", async () => {
    const load = vi.fn(async (): Promise<R> => ({ ok: true, data: 1 }));
    const t0 = 1_000_000;
    await cached("a", load, t0);
    await cached("a", load, t0 + CACHE_TTL_MS - 1);
    expect(load).toHaveBeenCalledTimes(1);
    await cached("a", load, t0 + CACHE_TTL_MS);
    expect(load).toHaveBeenCalledTimes(2);
  });

  it("shares one call between concurrent identical reads", async () => {
    let resolve!: (r: R) => void;
    const load = vi.fn(() => new Promise<R>((r) => (resolve = r)));
    const a = cached("me", load);
    const b = cached("me", load);
    resolve({ ok: true, data: 7 });
    expect(await a).toEqual({ ok: true, data: 7 });
    expect(await b).toEqual({ ok: true, data: 7 });
    expect(load).toHaveBeenCalledTimes(1);
  });

  it("never keeps an error", async () => {
    const failing = vi.fn(async (): Promise<R> => ({ ok: false }));
    await cached("x", failing);
    await Promise.resolve(); // the drop runs when the promise settles
    await cached("x", failing);
    expect(failing).toHaveBeenCalledTimes(2);

    const throwing = vi.fn(async (): Promise<R> => {
      throw new Error("redirect");
    });
    await expect(cached("y", throwing)).rejects.toThrow("redirect");
    await expect(cached("y", throwing)).rejects.toThrow("redirect");
    expect(throwing).toHaveBeenCalledTimes(2);
  });

  it("keys are separate (one per session and path)", async () => {
    const load = vi.fn(async (): Promise<R> => ({ ok: true }));
    await cached("alice:1:/me", load);
    await cached("bob:1:/me", load);
    await cached("alice:2:/me", load); // signed in again
    expect(load).toHaveBeenCalledTimes(3);
  });

  it("is emptied by clearCache (a change went through)", async () => {
    const load = vi.fn(async (): Promise<R> => ({ ok: true }));
    await cached("a", load);
    clearCache();
    expect(cacheSize()).toBe(0);
    await cached("a", load);
    expect(load).toHaveBeenCalledTimes(2);
  });

  it("keeps what others change for less long", () => {
    expect(ttlOf("a:1:/realms/demo/dashboard")).toBe(LIVE_TTL_MS);
    expect(ttlOf("a:1:/realms/demo/sessions?offset=25")).toBe(LIVE_TTL_MS);
    expect(ttlOf("a:1:/realms/demo/audit-logs?limit=25")).toBe(LIVE_TTL_MS);
    expect(ttlOf("a:1:/infrastructure")).toBe(LIVE_TTL_MS);
    expect(ttlOf("a:1:/realms/demo/users?q=bob")).toBe(USERS_TTL_MS);
    expect(ttlOf("a:1:/realms/demo/clients")).toBe(CONFIG_TTL_MS);
    expect(ttlOf("a:1:/realms/demo")).toBe(CONFIG_TTL_MS);
    expect(ttlOf("a:1:/realms/demo/audit-logs/actions")).toBe(CONFIG_TTL_MS); // a fixed catalogue
    expect(ttlOf("a:1:/me")).toBe(CACHE_TTL_MS);
    expect(ttlOf("a:1:/realms")).toBe(CACHE_TTL_MS);
  });

  it("expires each entry after its own TTL", async () => {
    const load = vi.fn(async (): Promise<R> => ({ ok: true }));
    const t0 = 1_000_000;
    await cached("a:1:/realms/demo/sessions", load, t0);
    await cached("a:1:/realms/demo/sessions", load, t0 + LIVE_TTL_MS - 1);
    expect(load).toHaveBeenCalledTimes(1);
    await cached("a:1:/realms/demo/sessions", load, t0 + LIVE_TTL_MS);
    expect(load).toHaveBeenCalledTimes(2);
  });

  describe("a change", () => {
    const reads = [
      "alice:1:/me",
      "alice:1:/me/language",
      "alice:1:/realms",
      "alice:1:/realms/demo",
      "alice:1:/realms/demo/clients",
      "alice:1:/realms/demo/users?q=a",
      "bob:1:/realms/demo/clients",
      "alice:1:/realms/demo2/clients",
      "alice:1:/realms/master/users",
    ];
    const left = async (change: string) => {
      const load = async (): Promise<R> => ({ ok: true });
      for (const r of reads) await cached(r, load);
      invalidate(change);
      const hit = vi.fn(load);
      const kept: string[] = [];
      for (const r of reads) {
        const before = hit.mock.calls.length;
        await cached(r, hit);
        if (hit.mock.calls.length === before) kept.push(r);
      }
      return kept;
    };

    it("in a realm drops that realm, for every admin, and nothing else", async () => {
      expect(await left("/realms/demo/clients/42")).toEqual([
        "alice:1:/me",
        "alice:1:/me/language",
        "alice:1:/realms",
        "alice:1:/realms/demo2/clients",
        "alice:1:/realms/master/users",
      ]);
    });

    it("in the master realm drops everything: it holds the admins' rights", async () => {
      expect(await left("/realms/master/users/7/roles")).toEqual([]);
    });

    it("to a realm itself, or a new realm, drops everything: the realm list is on every page", async () => {
      expect(await left("/realms/demo")).toEqual([]);
      expect(await left("/realms")).toEqual([]);
      expect(await left("/realms/demo?force=1")).toEqual([]);
    });
  });

  it("stays bounded", async () => {
    const load = async (): Promise<R> => ({ ok: true });
    for (let i = 0; i < 1_100; i++) await cached(`k${i}`, load);
    expect(cacheSize()).toBeLessThanOrEqual(1_000);
  });
});
