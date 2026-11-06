import "server-only";

// A small in-memory cache of the Admin API's reads: what a console page shows
// (its table included), and what every page asks for (GET /me, the language,
// the realm list). The item of a drawer is never cached: it is what the admin
// is about to edit.
//
// It is the second of two caches. Next.js's router keeps a page it has shown
// for 30 seconds in the browser (next.config.ts), and router.refresh() (after
// every change, components/console/use-action.ts) empties that. This one
// serves what the router does not keep: a reload, a new tab, a drawer opening
// or closing (the page renders again, table included), and the configuration
// pages for 30 seconds more.
//
// Rules:
//  - one entry per signed-in session and per path, query included. The key is
//    the admin and the sign-in time: a new sign-in, or a step-up (it signs in
//    again), starts with nothing cached, and an admin never sees what another
//    one's permissions allow;
//  - how long depends on who else writes the data (ttlOf). A change made
//    outside this console (a sign-in on idp, the account console, the CLI,
//    a configuration file) shows when the entry expires:
//       5 s   dashboard, sessions, audit log: every sign-in changes them;
//             the infrastructure's status
//      10 s   users: their last sign-in, their status
//      30 s   the admin: GET /me, the language, the realm list
//      60 s   the rest: the realm's configuration
//  - a change that went through this console (any successful POST, PUT, PATCH
//    or DELETE, see api() in api.ts) shows at once, for every admin
//    (invalidate):
//       in a realm           everything read from that realm
//       in the master realm  everything: it holds the admins and their rights
//       a realm itself       everything: the realm list is on every page
//  - errors are never kept (the next page asks again);
//  - concurrent identical reads share one call (single flight).
//
// The cost of serving a page from here: a session revoked at the IdP is only
// noticed at the first read that is not cached, so for at most TTL an admin
// can read again what this same session has just read. The Admin API still
// checks everything else, and every change.
//
// The cache lives in this Node.js process (globalThis: shared by pages,
// Server Actions and route handlers). Run one console instance, or sticky
// sessions (already required by the token refresh, see oidc.ts).

export const CONFIG_TTL_MS = 60_000;
export const CACHE_TTL_MS = 30_000;
export const USERS_TTL_MS = 10_000;
export const LIVE_TTL_MS = 5_000;
const MAX_ENTRIES = 1_000;

type Entry = { at: number; value: Promise<unknown> };

const g = globalThis as typeof globalThis & { __omssoApiCache?: Map<string, Entry> };
const store: Map<string, Entry> = (g.__omssoApiCache ??= new Map());

/**
 * The value of `load()` for `key`, from the cache when it is younger than
 * its TTL (ttlOf). A result `{ ok: false }` or a rejected promise is dropped as
 * soon as it settles.
 */
export function cached<T extends { ok: boolean }>(key: string, load: () => Promise<T>, now = Date.now()): Promise<T> {
  const hit = store.get(key);
  if (hit && now - hit.at < ttlOf(key)) return hit.value as Promise<T>;

  const value = load();
  store.set(key, { at: now, value });
  const drop = () => {
    if (store.get(key)?.value === value) store.delete(key);
  };
  value.then((r) => (r.ok ? undefined : drop()), drop);
  if (store.size > MAX_ENTRIES) evict(now);
  return value;
}

/** "/realms/demo/users?q=a" from a key ("<sub>:<sign-in time>:<path>"). */
function pathOf(key: string): string {
  const i = key.indexOf(":/");
  return i < 0 ? "" : key.slice(i + 1);
}

/** How long an entry lives: see the rules at the top of this file. */
export function ttlOf(key: string): number {
  const path = pathOf(key);
  if (path === "/infrastructure") return LIVE_TTL_MS;
  if (/^\/realms\/[^/]+\/(dashboard|sessions|audit-logs)(\?|$)/.test(path)) return LIVE_TTL_MS;
  if (/^\/realms\/[^/]+\/users(\?|$)/.test(path)) return USERS_TTL_MS;
  return /^\/realms\/[^/?]+/.test(path) ? CONFIG_TTL_MS : CACHE_TTL_MS;
}

/** A change went through at `path`: drops what it may have made stale, for every admin. */
export function invalidate(path: string): void {
  const realm = /^\/realms\/([^/?]+)\/[^?]/.exec(path)?.[1];
  if (!realm || realm === "master") return clearCache();
  const prefix = `/realms/${realm}`;
  for (const key of store.keys()) {
    const read = pathOf(key);
    if (read === prefix || read.startsWith(`${prefix}/`) || read.startsWith(`${prefix}?`)) store.delete(key);
  }
}

/** Empties the cache: a change that reaches everything, or a session that ended. */
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
  for (const [k, e] of store) if (now - e.at >= ttlOf(k)) store.delete(k);
  for (const k of store.keys()) {
    if (store.size <= MAX_ENTRIES) break;
    store.delete(k);
  }
}
