// Content Security Policy: the browser runs only the scripts this server
// sent, marked with a nonce that changes on every request. An injected
// <script> (XSS) has no valid nonce and is refused.
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP
// https://nextjs.org/docs/app/guides/content-security-policy

export function buildCsp(opts: { nonce: string; idpOrigin: string; dev: boolean; https: boolean }): string {
  const { nonce, idpOrigin, dev, https } = opts;
  const directives: [string, ...string[]][] = [
    ["default-src", "'self'"],
    // 'strict-dynamic': scripts loaded by a trusted (nonced) script are
    // trusted too (Next.js chunks). React needs eval in development only.
    ["script-src", "'self'", `'nonce-${nonce}'`, "'strict-dynamic'", ...(dev ? ["'unsafe-eval'"] : [])],
    // Inline styles: server-rendered style="" attributes (progress bars), the
    // toast library and the top bar's <style> (nextjs-toploader). CSS cannot
    // run code; the risk accepted is small.
    ["style-src", "'self'", "'unsafe-inline'"],
    ["img-src", "'self'", "data:", "blob:"],
    ["font-src", "'self'"],
    ["connect-src", "'self'", ...(dev ? ["ws:"] : [])],
    // Sign-out is a form POST that ends with a redirect to the IdP:
    // form-action also covers that redirect.
    ["form-action", "'self'", idpOrigin],
    ["frame-ancestors", "'none'"],
    ["base-uri", "'self'"],
    ["object-src", "'none'"],
  ];
  if (https) directives.push(["upgrade-insecure-requests"]);
  return directives.map((d) => d.join(" ")).join("; ");
}

/** 128 random bits, base64. */
export function newNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return btoa(String.fromCharCode(...bytes));
}
