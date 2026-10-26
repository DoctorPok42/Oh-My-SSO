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
