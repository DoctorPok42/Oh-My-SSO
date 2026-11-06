import type { NextConfig } from "next";

// https://nextjs.org/docs/app/api-reference/config/next-config-js
const nextConfig: NextConfig = {
  // A self-contained server in .next/standalone (small Docker image).
  // https://nextjs.org/docs/app/api-reference/config/next-config-js/output
  output: "standalone",
  poweredByHeader: false,
  // Next 16 writes an AGENTS.md for coding assistants on every `next dev`: not here.
  agentRules: false,
  reactStrictMode: true,
  experimental: {
    // The router keeps a page reached by a link for about 30 seconds by
    // itself; with this, also the page the browser loaded first (the
    // dashboard, after signing in). Going back to it asks the server nothing.
    // Every change made in the console empties this cache (router.refresh(),
    // components/console/use-action.ts), and a reload always asks the server.
    // The server's own cache: src/lib/cache.ts.
    // https://nextjs.org/docs/app/api-reference/config/next-config-js/staleTimes
    staleTimes: { dynamic: 30 },
  },
  // Headers for every response. The Content-Security-Policy is set per
  // request in src/proxy.ts (it carries a nonce).
  async headers() {
    const https = (process.env.ADMIN_URL ?? "").startsWith("https://");
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          // Never leak console URLs to other sites, but keep same-origin
          // requests normal: with "no-referrer", browsers send "Origin: null"
          // on form POSTs, which defeats the sign-out's origin check.
          { key: "Referrer-Policy", value: "same-origin" },
          { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=(), usb=()" },
          ...(https ? [{ key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains" }] : []),
        ],
      },
    ];
  },
};

export default nextConfig;
