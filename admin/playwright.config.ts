import { defineConfig, devices } from "@playwright/test";

// End-to-end tests: a real browser against the whole stack (idp, idp-admin,
// this console), started by e2e/run.sh (`make admin-e2e`).
// https://playwright.dev/docs/test-configuration

const baseURL = process.env.E2E_BASE_URL ?? "http://localhost:3100";
const port = new URL(baseURL).port || "3100";

export default defineConfig({
  testDir: "./e2e",
  // One administrator account, flows that build on each other: in order.
  workers: 1,
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  timeout: 120_000,
  expect: { timeout: 10_000 },
  reporter: [["list"], ["html", { open: "never" }]],
  globalSetup: "./e2e/global-setup.ts",
  use: {
    baseURL,
    storageState: "e2e/.state/admin.json",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    // A Chromium already on the machine (CI images, sandboxes) instead of
    // `npx playwright install chromium`.
    launchOptions: process.env.PLAYWRIGHT_CHROMIUM_PATH
      ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_PATH }
      : undefined,
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  // The console itself: production build, run like the Docker image does
  // (standalone server + its static files).
  webServer: {
    command:
      "npm run build && cp -r .next/static .next/standalone/.next/ && cp -r public .next/standalone/ && " +
      `PORT=${port} HOSTNAME=127.0.0.1 node .next/standalone/server.js`,
    url: `${baseURL}/healthz`,
    reuseExistingServer: !process.env.CI,
    timeout: 240_000,
    stdout: "pipe",
  },
});
