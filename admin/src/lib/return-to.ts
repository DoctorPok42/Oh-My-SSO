// After sign-in the admin goes back where they were. That "where" travels in
// a URL parameter, so it is attacker-controlled: only a local path is
// accepted, otherwise /auth/login?returnTo=https://evil.example would turn the
// console into an open redirect (CWE-601).
// https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html

export function safeReturnTo(value: string | null | undefined, fallback = "/"): string {
  if (!value || value.length > 2048) return fallback;
  // One leading slash, then not a second one or a backslash ("//evil.example"
  // and "/\evil.example" are protocol-relative URLs for browsers).
  if (!value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\")) return fallback;
  // No control characters (tab and newline are stripped by URL parsers).
  if (/[\u0000-\u001f\u007f]/.test(value)) return fallback;
  try {
    const u = new URL(value, "http://console.invalid");
    if (u.origin !== "http://console.invalid") return fallback;
    // Never back into the auth endpoints (loops).
    if (u.pathname.startsWith("/auth/")) return fallback;
    return u.pathname + u.search + u.hash;
  } catch {
    return fallback;
  }
}
