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
  // One copy for every route: the IdP's metadata read at start-up works with it
  // alone (src/lib/oidc.ts).
  serverExternalPackages: ["openid-client"],
  experimental: {
    // The browser keeps a page it has shown for 30 seconds: going back to a
    // tab asks the server nothing. Without this, every visit asks it again.
    // Every change made in the console empties this cache (router.refresh(),
    // components/console/use-action.ts), and a reload always asks the server.
    // The server's own cache: src/lib/cache.ts.
    // https://nextjs.org/docs/app/api-reference/config/next-config-js/staleTimes
    staleTimes: { dynamic: 30 },
    // Default 1 MB: too small for the largest CSV file of users (1 MB, more
    // once it is inside a Server Action's call).
    // https://nextjs.org/docs/app/api-reference/config/next-config-js/serverActions
    serverActions: { bodySizeLimit: "3mb" },
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
