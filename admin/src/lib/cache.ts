import "server-only";

// A small in-memory cache of Admin API reads, for what (almost) every page
// asks for and rarely changes: GET /me, the realm switcher's list, and the
// reference lists offered in drawers (roles, groups, client scopes,
// permissions). The main table of a page is never cached: it is what the
// admin came to see, it must be fresh.
//
// Rules:
//  - one entry per signed-in session and per path. The key is the admin and
//    the sign-in time: a new sign-in, or a step-up (it signs in again),
//    starts with nothing cached;
//  - 30 seconds at most;
//  - emptied entirely by every change that went through (any successful
//    POST, PUT, PATCH or DELETE to the Admin API, see api() in api.ts): what
//    an admin changes, every admin sees on their next page;
//  - errors are never kept (the next page asks again);
//  - concurrent identical reads share one call (single flight).
//
// The cache lives in this Node.js process (globalThis: shared by pages,
// Server Actions and route handlers). Run one console instance, or sticky
// sessions (already required by the token refresh, see oidc.ts).

export const CACHE_TTL_MS = 30_000;
const MAX_ENTRIES = 1_000;

type Entry = { at: number; value: Promise<unknown> };

const g = globalThis as typeof globalThis & { __omssoApiCache?: Map<string, Entry> };
const store: Map<string, Entry> = (g.__omssoApiCache ??= new Map());

/**
 * The value of `load()` for `key`, from the cache when it is younger than
 * CACHE_TTL_MS. A result `{ ok: false }` or a rejected promise is dropped as
 * soon as it settles.
 */
export function cached<T extends { ok: boolean }>(key: string, load: () => Promise<T>, now = Date.now()): Promise<T> {
  const hit = store.get(key);
  if (hit && now - hit.at < CACHE_TTL_MS) return hit.value as Promise<T>;

  const value = load();
  store.set(key, { at: now, value });
  const drop = () => {
    if (store.get(key)?.value === value) store.delete(key);
  };
  value.then((r) => (r.ok ? undefined : drop()), drop);
  if (store.size > MAX_ENTRIES) evict(now);
  return value;
}

/** Empties the cache: after any change, sign-in or sign-out. */
export function clearCache(): void {
  store.clear();
}

/** Number of entries (tests). */
export function cacheSize(): number {
  return store.size;
}

// Expired entries first; if still too many, the oldest (a Map iterates in
// insertion order).
function evict(now: number) {
  for (const [k, e] of store) if (now - e.at >= CACHE_TTL_MS) store.delete(k);
  for (const k of store.keys()) {
    if (store.size <= MAX_ENTRIES) break;
    store.delete(k);
  }
}
