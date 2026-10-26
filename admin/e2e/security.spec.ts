import { expect, test } from "@playwright/test";

// What the BFF must guarantee, whatever the screens look like.

test.describe("without a session", () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test("console pages send the browser to the IdP", async ({ page }) => {
    await page.goto("/r/master/dashboard");
    await expect(page).toHaveURL(/\/r\/master\/oidc\/login/);
  });

  test("the front door offers to sign in", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("link", { name: "Sign in" })).toHaveAttribute("href", "/auth/login");
  });

  test("returnTo cannot point to another site (open redirect)", async ({ page }) => {
    await page.goto("/auth/expired?returnTo=https://evil.example/");
    await expect(page.getByRole("link", { name: "Sign in again" })).toHaveAttribute("href", "/auth/login?returnTo=%2F");
  });

  test("a Server Action without a session is refused", async ({ request }) => {
    const res = await request.post("/r/master/clients", {
      headers: { "Next-Action": "0".repeat(40), "Content-Type": "text/plain;charset=UTF-8" },
      data: "[]",
      maxRedirects: 0,
    });
    expect(res.status()).toBe(401);
  });

  test("sign-out only accepts a form of the console itself (logout CSRF)", async ({ request }) => {
    const res = await request.post("/auth/logout", { headers: { Origin: "https://evil.example" }, maxRedirects: 0 });
    expect(res.status()).toBe(403);
  });

  test("a forged session cookie is ignored", async ({ page, context, baseURL }) => {
    await context.addCookies([{ name: "omsso_admin.0", value: "eyJhbGciOiJkaXIifQ.forged", url: baseURL! }]);
    await page.goto("/r/master/dashboard");
    await expect(page).toHaveURL(/\/oidc\/login/);
  });
});

test("security headers and a fresh CSP nonce on every page", async ({ request }) => {
  const a = await request.get("/", { maxRedirects: 0 });
  const b = await request.get("/", { maxRedirects: 0 });
  const csp = a.headers()["content-security-policy"]!;
  expect(csp).toMatch(/script-src 'self' 'nonce-[A-Za-z0-9+/=]+' 'strict-dynamic'/);
  expect(csp).toContain("frame-ancestors 'none'");
  expect(b.headers()["content-security-policy"]).not.toBe(csp);
  expect(a.headers()["x-frame-options"]).toBe("DENY");
  expect(a.headers()["x-content-type-options"]).toBe("nosniff");
  expect(a.headers()["referrer-policy"]).toBe("same-origin");
});
