import { NextResponse, type NextRequest } from "next/server";
import { buildCsp, newNonce } from "@/lib/csp";
import { env, isHttps } from "@/lib/env";
import { refreshSession } from "@/lib/oidc";
import {
  chunkedWrites,
  clearChunked,
  cookieNames,
  cookieOptions,
  isSession,
  readChunked,
  seal,
  SESSION_MAX_AGE,
  unseal,
  type CookieWrite,
  type Session,
} from "@/lib/session";

// Runs before every request (Next.js "proxy", formerly "middleware"):
//
//  1. a fresh CSP nonce for the page;
//  2. console pages need a session, otherwise -> /auth/login?returnTo=...;
//  3. an access token that expires within a minute is refreshed here, once,
//     and the new session cookie goes both to the browser (Set-Cookie) and to
//     the page being rendered (the request's Cookie header): Server Components
//     cannot set cookies themselves.
// https://nextjs.org/docs/app/api-reference/file-conventions/proxy

const PUBLIC_PATHS = ["/", "/healthz"];
const REFRESH_BEFORE_S = 60;

function isPublic(pathname: string): boolean {
  return PUBLIC_PATHS.includes(pathname) || pathname.startsWith("/auth/");
}

export async function proxy(req: NextRequest) {
  const e = env();
  const https = isHttps();
  const names = cookieNames(https);
  const { pathname, search } = req.nextUrl;

  const nonce = newNonce();
  const csp = buildCsp({
    nonce,
    idpOrigin: new URL(e.OIDC_ISSUER).origin,
    dev: process.env.NODE_ENV === "development",
    https,
  });
  const requestHeaders = new Headers(req.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("content-security-policy", csp);
  requestHeaders.set("x-pathname", pathname + search);

  let writes: CookieWrite[] = [];
  if (!isPublic(pathname)) {
    const all = req.cookies.getAll();
    const raw = readChunked(all, names.session);
    let session = await unseal<Session>(raw, e.SESSION_SECRET, "session");
    if (!isSession(session)) session = null;

    const now = Math.floor(Date.now() / 1000);
    if (session && session.accessTokenExpiresAt - now < REFRESH_BEFORE_S) {
      try {
        session = await refreshSession(session);
        const remaining = Math.max(60, SESSION_MAX_AGE - (now - session.createdAt));
        const value = await seal(session, e.SESSION_SECRET, "session", remaining);
        writes = chunkedWrites(
          names.session,
          value,
          cookieOptions(https, remaining),
          all.map((c) => c.name),
        );
      } catch (err) {
        console.warn("session refresh failed:", err instanceof Error ? err.message : err);
        session = null;
      }
    }

    if (!session) {
      const clear = clearChunked(
        names.session,
        cookieOptions(https, 0),
        all.map((c) => c.name),
      );
      // A Server Action (POST) cannot follow a redirect to the IdP: plain 401,
      // the page shows "session ended".
      const res =
        req.method === "GET" || req.method === "HEAD"
          ? NextResponse.redirect(new URL(`/auth/login?returnTo=${encodeURIComponent(pathname + search)}`, e.ADMIN_URL))
          : NextResponse.json({ error: "unauthenticated" }, { status: 401 });
      for (const w of clear) res.cookies.set(w.name, w.value, w.options);
      res.headers.set("Content-Security-Policy", csp);
      return res;
    }

    if (writes.length > 0) {
      // The page rendered by this request must see the new session too.
      const jar = new Map(all.map((c) => [c.name, c.value]));
      for (const w of writes) {
        if (w.options.maxAge === 0) jar.delete(w.name);
        else jar.set(w.name, w.value);
      }
      requestHeaders.set("cookie", [...jar].map(([k, v]) => `${k}=${v}`).join("; "));
    }
  }

  const res = NextResponse.next({ request: { headers: requestHeaders } });
  res.headers.set("Content-Security-Policy", csp);
  for (const w of writes) res.cookies.set(w.name, w.value, w.options);
  return res;
}

export const config = {
  // Everything but Next's static files.
  matcher: ["/((?!_next/static|_next/image|favicon.ico|icon.svg).*)"],
};
