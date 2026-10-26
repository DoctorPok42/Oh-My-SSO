import "server-only";
import { headers } from "next/headers";
import { cache } from "react";
import { redirect } from "next/navigation";
import { getSession } from "@/lib/auth";
import { cached, clearCache } from "@/lib/cache";
import { env } from "@/lib/env";
import { ApiError, type ApiResult } from "@/lib/api-error";
import type { ApiErrorBody, Me } from "@/lib/types";

// The only way to the Admin API: from this server (BFF), with the admin's
// access token taken from the encrypted session cookie. The browser never
// talks to the Admin API, and never sees a token.

type Query = Record<string, string | number | boolean | undefined | null>;

/** A call slower than this is logged. */
const SLOW_CALL_MS = 500;

export type ApiInit = {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  query?: Query;
};

/** Builds "/realms/demo/clients?protocol=oidc", every dynamic part URL-encoded. */
export function apiPath(segments: (string | number)[], query?: Query): string {
  const path =
    "/" +
    segments
      .map((s) => {
        const v = String(s);
        // "." and ".." survive encodeURIComponent and would be resolved by
        // fetch(): "/realms/../me". Server Action arguments come from the
        // browser, so they are checked.
        if (v === "" || v === "." || v === "..")
          throw new ApiError(400, { error: "invalid_request", message: "Invalid identifier." });
        return encodeURIComponent(v);
      })
      .join("/");
  const q = toQuery(query);
  return q ? `${path}?${q}` : path;
}

function toQuery(query?: Query): string {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(query ?? {})) {
    if (v !== undefined && v !== null && v !== "") qs.set(k, String(v));
  }
  return qs.toString();
}

export async function api<T>(path: string, init: ApiInit = {}): Promise<T> {
  const session = await getSession();
  if (!session) throw new ApiError(401, { error: "unauthenticated", message: "Sign in again." });

  const h = await headers();
  const reqHeaders: Record<string, string> = {
    Accept: "application/json",
    Authorization: `Bearer ${session.accessToken}`,
    // Who the admin is, for the audit log only (the Admin API never trusts
    // these for a security decision): see internal/adminapi/auth.go.
    "X-Admin-Client-IP": clientIp(h),
    "X-Admin-Client-User-Agent": (h.get("user-agent") ?? "").slice(0, 512),
  };
  let body: string | undefined;
  if (init.body !== undefined) {
    reqHeaders["Content-Type"] = "application/json";
    body = JSON.stringify(init.body);
  }
  const q = toQuery(init.query);
  const url = `${env().ADMIN_API_URL}/api/v1${path}${q ? (path.includes("?") ? "&" : "?") + q : ""}`;

  const started = performance.now();
  let res: Response;
  try {
    res = await fetch(url, {
      method: init.method ?? "GET",
      headers: reqHeaders,
      body,
      cache: "no-store",
      signal: AbortSignal.timeout(15_000),
    });
  } catch (err) {
    console.error("admin api unreachable", url, err);
    throw new ApiError(502, {
      error: "api_unreachable",
      message: "The Admin API (idp-admin) did not answer. Is it running, and is ADMIN_API_URL right?",
    });
  }
  const method = init.method ?? "GET";
  if (res.ok && method !== "GET") {
    // A change went through: the cached reads (cache.ts) may be stale.
    clearCache();
  }
  if (res.status === 204) return undefined as T;
  const data: unknown = await res.json().catch(() => null);
  const ms = Math.round(performance.now() - started);
  if (ms >= SLOW_CALL_MS) {
    // Shown in the console's terminal: the first place to look when a page
    // is slow (idp-admin logs its own side with ADMIN_API_LOG_REQUESTS=true).
    console.warn(`[admin api] slow call: ${method} ${path} took ${ms} ms (HTTP ${res.status})`);
  }
  if (!res.ok) {
    const err = (data ?? {}) as Partial<ApiErrorBody>;
    throw new ApiError(res.status, {
      ...err,
      error: err.error ?? `http_${res.status}`,
      message: err.message ?? `The Admin API answered HTTP ${res.status}.`,
    });
  }
  return data as T;
}

/**
 * The browser's IP for the audit log. Behind a reverse proxy the first
 * X-Forwarded-For entry; it is informative only.
 */
function clientIp(h: Headers): string {
  const xff = h.get("x-forwarded-for")?.split(",")[0]?.trim();
  return xff || h.get("x-real-ip") || "";
}

/**
 * For Server Components (reads). A dead session ends on a page that offers to
 * sign in again (not an automatic redirect: no loop if the IdP keeps
 * refusing); any other error is returned to be shown in place.
 */
export async function load<T>(path: string, init?: ApiInit): Promise<ApiResult<T>> {
  try {
    return { ok: true, data: await api<T>(path, init) };
  } catch (err) {
    if (err instanceof ApiError) {
      if (err.status === 401) {
        // The session ended: nothing cached for it may be shown any more.
        clearCache();
        const h = await headers();
        redirect(`/auth/expired?returnTo=${encodeURIComponent(h.get("x-pathname") ?? "/")}`);
      }
      return { ok: false, ...err.toJSON() };
    }
    throw err;
  }
}

/**
 * load(), through the 30-second cache (cache.ts): for GET /me, the realm list
 * and the reference lists of the drawers, never for a page's main table.
 */
export async function loadCached<T>(path: string): Promise<ApiResult<T>> {
  const session = await getSession();
  if (!session) return load<T>(path); // answers "sign in again"
  return cached(`${session.user.sub}:${session.createdAt}:${path}`, () => load<T>(path));
}

/** For Server Actions (writes): never throws, the client decides what to show. */
export async function act<T>(fn: () => Promise<T>): Promise<ApiResult<T>> {
  try {
    return { ok: true, data: await fn() };
  } catch (err) {
    if (err instanceof ApiError) return { ok: false, ...err.toJSON() };
    console.error("server action failed", err);
    return {
      ok: false,
      status: 500,
      error: "internal_error",
      message: "Something went wrong in the console, see its logs.",
    };
  }
}

/**
 * The signed-in admin (GET /me): once per request however many components
 * ask (React cache), and at most every 30 seconds per session (loadCached).
 */
export const getMe = cache(() => loadCached<Me>("/me"));
