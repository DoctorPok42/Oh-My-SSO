import "server-only";
import { NextResponse } from "next/server";
import { env, isHttps } from "@/lib/env";
import { startLogin } from "@/lib/oidc";
import { safeReturnTo } from "@/lib/return-to";
import { cookieNames, cookieOptions, LOGIN_STATE_MAX_AGE, seal } from "@/lib/session";

/**
 * Sends the browser to the IdP's sign-in page. state, nonce and the PKCE
 * verifier wait in a short-lived encrypted cookie, read back by /auth/callback.
 */
export async function redirectToIdP(returnToParam: string | null, stepUp: boolean): Promise<NextResponse> {
  const e = env();
  const returnTo = safeReturnTo(returnToParam, "/");
  try {
    const { url, state } = await startLogin(returnTo, stepUp);
    const res = NextResponse.redirect(url);
    const https = isHttps();
    res.cookies.set(
      cookieNames(https).login,
      await seal(state, e.SESSION_SECRET, "login", LOGIN_STATE_MAX_AGE),
      cookieOptions(https, LOGIN_STATE_MAX_AGE),
    );
    res.headers.set("Cache-Control", "no-store");
    return res;
  } catch (err) {
    console.error("cannot start sign-in:", err);
    return NextResponse.redirect(new URL("/?error=idp_unreachable", e.ADMIN_URL));
  }
}
