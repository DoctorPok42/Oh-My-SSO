import "server-only";
import { z } from "zod";

// Server-side configuration, read once from the environment and validated:
// a typo in .env.local fails at the first request with a clear message,
// instead of a confusing OIDC error later. None of these values is ever sent
// to the browser (no NEXT_PUBLIC_ prefix).
//
// Values come from `idp-admin bootstrap` (OIDC_*), see .env.example.

const url = z.url({ protocol: /^https?$/ }).transform((v) => v.replace(/\/+$/, ""));

const schema = z.object({
  // Issuer of the master realm: <PUBLIC_URL of idp>/r/master.
  OIDC_ISSUER: url,
  OIDC_CLIENT_ID: z.string().min(1).default("sso-admin"),
  OIDC_CLIENT_SECRET: z.string().min(16, "OIDC_CLIENT_SECRET: paste the secret printed by `idp-admin bootstrap`"),
  // Public URL of this console, as the browser sees it (redirect URI:
  // ADMIN_URL/auth/callback, registered by the bootstrap).
  ADMIN_URL: url,
  // Admin API (cmd/idp-admin), reachable from this server only.
  ADMIN_API_URL: url.default("http://localhost:8090"),
  // Encrypts the session cookie. 32 random bytes at least: `openssl rand -base64 32`.
  SESSION_SECRET: z.string().min(32, "SESSION_SECRET must be at least 32 characters: openssl rand -base64 32"),
  // Realm opened after sign-in.
  DEFAULT_REALM: z
    .string()
    .regex(/^[a-z0-9][a-z0-9-]{0,62}$/)
    .default("master"),
});

export type Env = z.infer<typeof schema>;

let cached: Env | undefined;

export function env(): Env {
  if (cached) return cached;
  const parsed = schema.safeParse(process.env);
  if (!parsed.success) {
    const lines = parsed.error.issues.map((i) => `  - ${i.path.join(".") || "env"}: ${i.message}`);
    throw new Error(`Invalid admin console configuration (see admin/.env.example):\n${lines.join("\n")}`);
  }
  cached = parsed.data;
  return cached;
}

/** True when the console is served over HTTPS (production): Secure cookies, HSTS. */
export function isHttps(): boolean {
  return env().ADMIN_URL.startsWith("https://");
}
