import { NextResponse, type NextRequest } from "next/server";
import { env, isHttps } from "@/lib/env";
import { finishLogin } from "@/lib/oidc";
import { safeReturnTo } from "@/lib/return-to";
import {
  chunkedWrites,
  cookieNames,
  cookieOptions,
  SESSION_MAX_AGE,
  seal,
  unseal,
  type LoginState,
} from "@/lib/session";

// GET /auth/callback?code=...&state=... — the IdP sends the browser back here.
// openid-client checks state (CSRF), the PKCE verifier (stolen code), the
// nonce and the ID token's signature, issuer and audience, then the code is
// exchanged for tokens, server to server, with the client secret.
export async function GET(req: NextRequest) {
  const e = env();
  const https = isHttps();
  const names = cookieNames(https);
  const fail = (code: string) => {
    const res = NextResponse.redirect(new URL(`/?error=${code}`, e.ADMIN_URL));
    res.cookies.set(names.login, "", cookieOptions(https, 0));
    return res;
  };

  const params = req.nextUrl.searchParams;
  if (params.get("error")) {
    // e.g. access_denied: the account is not in the admins/auditors groups.
    console.warn("sign-in refused by the IdP:", params.get("error"), params.get("error_description"));
    return fail(params.get("error") === "access_denied" ? "access_denied" : "signin_failed");
  }
  const login = await unseal<LoginState>(req.cookies.get(names.login)?.value, e.SESSION_SECRET, "login");
  if (!login) return fail("signin_expired");

  // The URL the IdP redirected to, as the browser saw it (behind a proxy the
  // request's own host may differ).
  const callbackUrl = new URL(`${e.ADMIN_URL}/auth/callback${req.nextUrl.search}`);
  let session;
  try {
    session = await finishLogin(callbackUrl, login);
  } catch (err) {
    console.warn("sign-in failed at the callback:", err instanceof Error ? err.message : err);
    return fail("signin_failed");
  }

  const res = NextResponse.redirect(new URL(safeReturnTo(login.returnTo, "/"), e.ADMIN_URL));
  res.headers.set("Cache-Control", "no-store");
  res.cookies.set(names.login, "", cookieOptions(https, 0));
  const value = await seal(session, e.SESSION_SECRET, "session", SESSION_MAX_AGE);
  const existing = req.cookies.getAll().map((c) => c.name);
  for (const w of chunkedWrites(names.session, value, cookieOptions(https, SESSION_MAX_AGE), existing)) {
    res.cookies.set(w.name, w.value, w.options);
  }
  return res;
}
