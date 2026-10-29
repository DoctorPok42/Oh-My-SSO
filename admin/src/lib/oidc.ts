import * as client from "openid-client";
import { env } from "@/lib/env";
import type { LoginState, Session } from "@/lib/session";

// The console is an OpenID Connect "relying party" of the master realm, with
// the confidential client "sso-admin" created by `idp-admin bootstrap`.
// Library: openid-client v6 (certified OpenID RP): https://github.com/panva/openid-client
//
// Flow: Authorization Code + PKCE (RFC 7636) + state + nonce, the secret sent
// with HTTP Basic (client_secret_basic, the client's registered method).

export const SCOPES = "openid profile email offline_access";
export const CALLBACK_PATH = "/auth/callback";

let configPromise: Promise<client.Configuration> | undefined;

/** The IdP's metadata (discovery document), fetched once and cached. */
export function oidcConfig(): Promise<client.Configuration> {
  if (!configPromise) {
    const e = env();
    const issuer = new URL(e.OIDC_ISSUER);
    configPromise = client
      .discovery(
        issuer,
        e.OIDC_CLIENT_ID,
        undefined,
        client.ClientSecretBasic(e.OIDC_CLIENT_SECRET),
        // Plain http is refused by default; allowed only for a local IdP.
        issuer.protocol === "http:" ? { execute: [client.allowInsecureRequests] } : undefined,
      )
      .catch((err: unknown) => {
        configPromise = undefined; // retry on the next request
        throw err;
      });
  }
  return configPromise;
}

export function redirectUri(): string {
  return env().ADMIN_URL + CALLBACK_PATH;
}

/**
 * Starts a sign-in. Step-up ("confirm it's you") is the same flow with
 * prompt=login and max_age=0: the IdP asks for the password and the second
 * factor again even if its session is alive (OIDC Core §3.1.2.1).
 */
export async function startLogin(returnTo: string, stepUp: boolean): Promise<{ url: URL; state: LoginState }> {
  const config = await oidcConfig();
  const codeVerifier = client.randomPKCECodeVerifier();
  const state: LoginState = {
    state: client.randomState(),
    nonce: client.randomNonce(),
    codeVerifier,
    returnTo,
    stepUp,
  };
  const params: Record<string, string> = {
    redirect_uri: redirectUri(),
    scope: SCOPES,
    code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
    code_challenge_method: "S256",
    state: state.state,
    nonce: state.nonce,
  };
  if (stepUp) {
    params.prompt = "login";
    params.max_age = "0";
  }
  return { url: client.buildAuthorizationUrl(config, params), state };
}

/** Ends a sign-in: checks state, nonce and PKCE, exchanges the code for tokens. */
export async function finishLogin(callbackUrl: URL, login: LoginState): Promise<Session> {
  const config = await oidcConfig();
  const tokens = await client.authorizationCodeGrant(config, callbackUrl, {
    pkceCodeVerifier: login.codeVerifier,
    expectedState: login.state,
    expectedNonce: login.nonce,
    idTokenExpected: true,
  });
  const claims = tokens.claims();
  if (!claims) throw new Error("the IdP returned no ID token");
  const now = Math.floor(Date.now() / 1000);
  return {
    v: 1,
    accessToken: tokens.access_token,
    accessTokenExpiresAt: now + (tokens.expiresIn() ?? 300),
    refreshToken: tokens.refresh_token,
    idToken: tokens.id_token,
    user: {
      sub: claims.sub,
      name: str(claims.name) || str(claims.preferred_username) || str(claims.email) || claims.sub,
      email: str(claims.email),
    },
    createdAt: now,
  };
}

function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}

//
// The IdP rotates refresh tokens and treats a reused one as stolen: it revokes
// the whole family (RFC 9700 §4.14.2). The browser often sends several
// requests at once (page + prefetches), all with the same, soon-to-expire
// cookie. So one refresh per refresh token: concurrent callers share the same
// promise, and callers that arrive a little later (with the old cookie, before
// the browser stored the new one) get the same result from this short cache.
//
// Limit: this cache lives in one Node.js process. Run one console instance, or
// sticky sessions in front of several.

const inflight = new Map<string, { at: number; result: Promise<Session> }>();
const REUSE_WINDOW_MS = 5 * 60_000;

export function refreshSession(session: Session): Promise<Session> {
  const token = session.refreshToken;
  if (!token) return Promise.reject(new Error("no refresh token"));
  const now = Date.now();
  for (const [k, v] of inflight) if (now - v.at > REUSE_WINDOW_MS) inflight.delete(k);
  const hit = inflight.get(token);
  if (hit) return hit.result;
  const result = (async () => {
    const config = await oidcConfig();
    const tokens = await client.refreshTokenGrant(config, token);
    const nowS = Math.floor(Date.now() / 1000);
    return {
      ...session,
      accessToken: tokens.access_token,
      accessTokenExpiresAt: nowS + (tokens.expiresIn() ?? 300),
      refreshToken: tokens.refresh_token ?? token,
      idToken: tokens.id_token ?? session.idToken,
    } satisfies Session;
  })();
  inflight.set(token, { at: now, result });
  result.catch(() => undefined); // the caller handles the error
  return result;
}


/** RP-initiated logout URL (OIDC RP-Initiated Logout 1.0): ends the IdP session too. */
export async function endSessionUrl(idToken: string | undefined): Promise<string> {
  const e = env();
  try {
    const config = await oidcConfig();
    if (!idToken || !config.serverMetadata().end_session_endpoint) return e.ADMIN_URL + "/";
    return client
      .buildEndSessionUrl(config, { id_token_hint: idToken, post_logout_redirect_uri: e.ADMIN_URL + "/" })
      .toString();
  } catch {
    return e.ADMIN_URL + "/";
  }
}

/** Revokes the refresh token (RFC 7009), best effort: the logout ends the session anyway. */
export async function revokeRefreshToken(token: string | undefined): Promise<void> {
  if (!token) return;
  try {
    const config = await oidcConfig();
    if (config.serverMetadata().revocation_endpoint) {
      await client.tokenRevocation(config, token, { token_type_hint: "refresh_token" });
    }
  } catch {
    // ignore: the IdP may be down; the session cookie is deleted anyway
  }
}
