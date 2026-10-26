import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// Unit tests (pure functions: cookies, redirects, CSP, formatting...).
// The end-to-end tests run with Playwright (e2e/, playwright.config.ts).
export default defineConfig({
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
      // "server-only" throws when imported outside React Server Components.
      "server-only": fileURLToPath(new URL("./tests/server-only-stub.ts", import.meta.url)),
    },
  },
  test: {
    include: ["tests/**/*.test.ts"],
    environment: "node",
  },
});
