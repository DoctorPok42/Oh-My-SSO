import { beforeEach, describe, expect, it, vi } from "vitest";
import { CACHE_TTL_MS, cached, cacheSize, clearCache } from "@/lib/cache";

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

  it("stays bounded", async () => {
    const load = async (): Promise<R> => ({ ok: true });
    for (let i = 0; i < 1_100; i++) await cached(`k${i}`, load);
    expect(cacheSize()).toBeLessThanOrEqual(1_000);
  });
});
