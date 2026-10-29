import { EncryptJWT, jwtDecrypt } from "jose";

// The admin's session lives in an encrypted cookie (BFF pattern): the
// browser holds an opaque blob it can neither read nor change; only this
// server, with SESSION_SECRET, can open it. The tokens inside never reach
// JavaScript in the browser.
//
// Format: JWE compact serialization, "dir" + A256GCM (RFC 7516): AES-256-GCM
// encrypts and authenticates at once, so a modified cookie is rejected.
// https://github.com/panva/jose/blob/main/docs/jwt/encrypt/classes/EncryptJWT.md

export type Session = {
  v: 1;
  accessToken: string;
  /** Epoch seconds. */
  accessTokenExpiresAt: number;
  refreshToken?: string;
  /** Kept for logout: the IdP requires id_token_hint (logout CSRF protection). */
  idToken?: string;
  user: { sub: string; name: string; email: string };
  /** Epoch seconds: sign-in time. The cookie never outlives SESSION_MAX_AGE. */
  createdAt: number;
};

/** Short-lived state of one sign-in round trip (PKCE, state, nonce). */
export type LoginState = {
  state: string;
  nonce: string;
  codeVerifier: string;
  returnTo: string;
  stepUp: boolean;
};

/** A session never lasts more than 7 days, whatever the refresh token says. */
export const SESSION_MAX_AGE = 7 * 24 * 60 * 60;
/** Ten minutes to sign in at the IdP. */
export const LOGIN_STATE_MAX_AGE = 10 * 60;


const keys = new Map<string, Promise<CryptoKey>>();

/**
 * Derives the AES-256 key from SESSION_SECRET with HKDF-SHA-256 (RFC 5869),
 * one key per purpose: the login-state cookie cannot be replayed as a session.
 */
export function deriveKey(secret: string, purpose: "session" | "login"): Promise<CryptoKey> {
  const id = `${purpose}:${secret}`;
  let key = keys.get(id);
  if (!key) {
    key = (async () => {
      const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), "HKDF", false, [
        "deriveKey",
      ]);
      return crypto.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: new TextEncoder().encode("oh-my-sso admin console"),
          info: new TextEncoder().encode(`cookie:${purpose}`),
        },
        material,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"],
      );
    })();
    keys.set(id, key);
  }
  return key;
}


export async function seal(
  payload: Session | LoginState,
  secret: string,
  purpose: "session" | "login",
  maxAge: number,
) {
  const key = await deriveKey(secret, purpose);
  return new EncryptJWT({ ...payload })
    .setProtectedHeader({ alg: "dir", enc: "A256GCM", typ: purpose })
    .setIssuedAt()
    .setExpirationTime(Math.floor(Date.now() / 1000) + maxAge)
    .encrypt(key);
}

/** Opens a sealed value; null when missing, expired, tampered with or sealed for another purpose. */
export async function unseal<T>(
  value: string | undefined,
  secret: string,
  purpose: "session" | "login",
): Promise<T | null> {
  if (!value) return null;
  try {
    const key = await deriveKey(secret, purpose);
    const { payload, protectedHeader } = await jwtDecrypt(value, key, {
      keyManagementAlgorithms: ["dir"],
      contentEncryptionAlgorithms: ["A256GCM"],
    });
    if (protectedHeader.typ !== purpose) return null;
    return payload as T;
  } catch {
    return null;
  }
}

export function isSession(v: unknown): v is Session {
  const s = v as Session | null;
  return (
    !!s &&
    s.v === 1 &&
    typeof s.accessToken === "string" &&
    typeof s.accessTokenExpiresAt === "number" &&
    typeof s.createdAt === "number" &&
    !!s.user &&
    typeof s.user.sub === "string"
  );
}

//
// A sealed session (three JWTs inside) can exceed the ~4 KB a browser keeps per
// cookie, so it is split into numbered chunks: omsso_admin.0, omsso_admin.1...

export const CHUNK_SIZE = 3800;
const MAX_CHUNKS = 6;

export type CookieOptions = {
  httpOnly: boolean;
  secure: boolean;
  sameSite: "lax" | "strict";
  path: string;
  maxAge: number;
};

export type CookieWrite = { name: string; value: string; options: CookieOptions };

/**
 * Cookie names. Over HTTPS the "__Host-" prefix makes the browser refuse the
 * cookie unless it is Secure, has Path=/ and no Domain: no sub-domain can set
 * or overwrite it (cookie tossing).
 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#cookie_prefixes
 */
export function cookieNames(https: boolean) {
  const prefix = https ? "__Host-" : "";
  return { session: `${prefix}omsso_admin`, login: `${prefix}omsso_admin_login`, theme: "omsso_theme" };
}

export function cookieOptions(https: boolean, maxAge: number): CookieOptions {
  // SameSite=Lax, not Strict: the IdP's redirect back to /auth/callback is a
  // cross-site navigation, and the cookie must come along on what follows.
  return { httpOnly: true, secure: https, sameSite: "lax", path: "/", maxAge };
}

/** Reads a chunked cookie back. */
export function readChunked(all: { name: string; value: string }[], name: string): string | undefined {
  const byName = new Map(all.map((c) => [c.name, c.value]));
  let out = "";
  for (let i = 0; i < MAX_CHUNKS; i++) {
    const part = byName.get(`${name}.${i}`);
    if (part === undefined) break;
    out += part;
  }
  return out || undefined;
}

/**
 * The Set-Cookie writes for a value: its chunks, plus the deletion of chunks
 * left over from a longer previous value (`existing`: cookie names the
 * browser sent).
 */
export function chunkedWrites(
  name: string,
  value: string,
  options: CookieOptions,
  existing: string[] = [],
): CookieWrite[] {
  const parts: string[] = [];
  for (let i = 0; i < value.length; i += CHUNK_SIZE) parts.push(value.slice(i, i + CHUNK_SIZE));
  if (parts.length > MAX_CHUNKS) throw new Error("session cookie too large");
  const writes: CookieWrite[] = parts.map((part, i) => ({ name: `${name}.${i}`, value: part, options }));
  const written = new Set(writes.map((w) => w.name));
  for (const old of chunkNames(existing, name)) {
    if (!written.has(old)) writes.push({ name: old, value: "", options: { ...options, maxAge: 0 } });
  }
  return writes;
}

/** Writes that delete every chunk the browser sent (sign-out). */
export function clearChunked(name: string, options: CookieOptions, existing: string[]): CookieWrite[] {
  return chunkNames(existing, name).map((n) => ({ name: n, value: "", options: { ...options, maxAge: 0 } }));
}

function chunkNames(existing: string[], name: string): string[] {
  return existing.filter((n) => n.startsWith(`${name}.`) && /^\d+$/.test(n.slice(name.length + 1)));
}
