import { describe, expect, it, vi } from "vitest";

vi.mock("next/headers", () => ({ headers: vi.fn(), cookies: vi.fn() }));
const { apiPath } = await import("@/lib/api");

describe("apiPath", () => {
  it("encodes every segment and drops empty query values", () => {
    expect(apiPath(["realms", "my realm", "clients", "a/b"], { protocol: "oidc", q: "", offset: 0 })).toBe(
      "/realms/my%20realm/clients/a%2Fb?protocol=oidc&offset=0",
    );
  });

  it("refuses dot segments (fetch would resolve them: /realms/../me)", () => {
    for (const bad of ["..", ".", ""]) {
      expect(() => apiPath(["realms", bad, "clients"])).toThrow();
    }
  });
});
