import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Session } from "@/lib/session";

// The IdP revokes the whole token family when a refresh token is used twice
// (replay detection). Several requests arriving together with the same
// cookie must therefore cause ONE refresh.

const refreshTokenGrant = vi.fn();
vi.mock("openid-client", () => ({
  discovery: vi.fn(async () => ({ serverMetadata: () => ({}) })),
  ClientSecretBasic: vi.fn(),
  allowInsecureRequests: vi.fn(),
  refreshTokenGrant: (...args: unknown[]) => refreshTokenGrant(...args),
}));

process.env.OIDC_ISSUER = "http://localhost:8080/r/master";
process.env.OIDC_CLIENT_SECRET = "0123456789abcdef0123456789";
process.env.ADMIN_URL = "http://localhost:3000";
process.env.SESSION_SECRET = "s".repeat(40);

const { refreshSession } = await import("@/lib/oidc");

const base: Session = {
  v: 1,
  accessToken: "old-access",
  accessTokenExpiresAt: 0,
  refreshToken: "refresh-1",
  idToken: "id",
  user: { sub: "u", name: "n", email: "e" },
  createdAt: 0,
};

describe("refreshSession", () => {
  beforeEach(() => {
    refreshTokenGrant.mockReset();
  });

  it("refreshes once for concurrent requests with the same token", async () => {
    let release!: () => void;
    refreshTokenGrant.mockImplementation(
      () =>
        new Promise((resolve) => {
          release = () => resolve({ access_token: "new-access", refresh_token: "refresh-2", expiresIn: () => 300 });
        }),
    );
    const calls = [refreshSession(base), refreshSession(base), refreshSession(base)];
    await vi.waitFor(() => expect(refreshTokenGrant).toHaveBeenCalledTimes(1));
    release();
    const results = await Promise.all(calls);
    expect(new Set(results.map((r) => r.refreshToken))).toEqual(new Set(["refresh-2"]));
    expect(results[0]!.accessToken).toBe("new-access");
    expect(results[0]!.idToken).toBe("id"); // kept for logout when the IdP sends none

    // A late request with the old cookie still gets the same result.
    expect((await refreshSession(base)).refreshToken).toBe("refresh-2");
    expect(refreshTokenGrant).toHaveBeenCalledTimes(1);
  });

  it("does not cache a different token", async () => {
    refreshTokenGrant.mockResolvedValue({ access_token: "a", refresh_token: "r", expiresIn: () => 60 });
    await refreshSession({ ...base, refreshToken: "other" });
    expect(refreshTokenGrant).toHaveBeenCalledTimes(1);
  });

  it("fails without a refresh token", async () => {
    await expect(refreshSession({ ...base, refreshToken: undefined })).rejects.toThrow();
  });
});
