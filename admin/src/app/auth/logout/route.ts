import { NextResponse, type NextRequest } from "next/server";
import { env, isHttps } from "@/lib/env";
import { revokeRefreshToken } from "@/lib/oidc";
import { clearChunked, cookieNames, cookieOptions, isSession, readChunked, unseal, type Session } from "@/lib/session";

// POST /auth/logout (a form button, never a GET link: a link could be
// triggered by another site — logout CSRF). Deletes the local session cookie
// and revokes the refresh token, but keeps the IdP session for silent sign-in.
export async function POST(req: NextRequest) {
  const e = env();
  // Same-origin form only. Browsers send Origin on every POST ("null" under
  // some referrer policies); Sec-Fetch-Site is the fallback.
  const origin = req.headers.get("origin");
  const sameOrigin =
    origin && origin !== "null"
      ? origin === new URL(e.ADMIN_URL).origin
      : req.headers.get("sec-fetch-site") === "same-origin";
  if (!sameOrigin) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }
  const https = isHttps();
  const names = cookieNames(https);
  const all = req.cookies.getAll();
  const session = await unseal<Session>(readChunked(all, names.session), e.SESSION_SECRET, "session");
  const valid = isSession(session) ? session : null;

  await revokeRefreshToken(valid?.refreshToken);
  // 303: the browser follows with a GET.
  const res = NextResponse.redirect(new URL("/", e.ADMIN_URL), 303);
  for (const w of clearChunked(
    names.session,
    cookieOptions(https, 0),
    all.map((c) => c.name),
  )) {
    res.cookies.set(w.name, w.value, w.options);
  }
  res.headers.set("Cache-Control", "no-store");
  return res;
}
