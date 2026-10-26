import { describe, expect, it } from "vitest";
import {
  chunkedWrites,
  CHUNK_SIZE,
  clearChunked,
  cookieNames,
  cookieOptions,
  isSession,
  readChunked,
  seal,
  unseal,
  type LoginState,
  type Session,
} from "@/lib/session";

const SECRET = "a-test-secret-that-is-long-enough-1234567890";

const session: Session = {
  v: 1,
  accessToken: "eyJ.access.token",
  accessTokenExpiresAt: 2_000_000_000,
  refreshToken: "refresh",
  idToken: "eyJ.id.token",
  user: { sub: "u1", name: "Root", email: "root@example.test" },
  createdAt: 1_900_000_000,
};

describe("seal / unseal (encrypted cookie)", () => {
  it("round-trips a session", async () => {
    const sealed = await seal(session, SECRET, "session", 60);
    expect(sealed.split(".")).toHaveLength(5); // JWE compact: header.key.iv.ciphertext.tag
    expect(sealed).not.toContain("access");
    const opened = await unseal<Session>(sealed, SECRET, "session");
    expect(opened).toMatchObject(session);
    expect(isSession(opened)).toBe(true);
  });

  it("refuses another secret", async () => {
    const sealed = await seal(session, SECRET, "session", 60);
    expect(await unseal(sealed, SECRET + "x", "session")).toBeNull();
  });

  it("refuses a modified cookie", async () => {
    const sealed = await seal(session, SECRET, "session", 60);
    const parts = sealed.split(".");
    const ct = parts[3]!;
    parts[3] = (ct[0] === "A" ? "B" : "A") + ct.slice(1);
    expect(await unseal(parts.join("."), SECRET, "session")).toBeNull();
  });

  it("refuses a login-state cookie used as a session (one key per purpose)", async () => {
    const login: LoginState = { state: "s", nonce: "n", codeVerifier: "v", returnTo: "/", stepUp: false };
    const sealed = await seal(login, SECRET, "login", 60);
    expect(await unseal(sealed, SECRET, "session")).toBeNull();
    expect(await unseal<LoginState>(sealed, SECRET, "login")).toMatchObject(login);
  });

  it("refuses an expired cookie", async () => {
    const sealed = await seal(session, SECRET, "session", -120);
    expect(await unseal(sealed, SECRET, "session")).toBeNull();
  });

  it("treats garbage and absence as no session", async () => {
    expect(await unseal(undefined, SECRET, "session")).toBeNull();
    expect(await unseal("not-a-jwe", SECRET, "session")).toBeNull();
    expect(isSession({ v: 2 })).toBe(false);
  });
});

describe("chunked cookies", () => {
  const opts = cookieOptions(true, 3600);

  it("splits a long value and reads it back", () => {
    const value = "x".repeat(CHUNK_SIZE * 2 + 10);
    const writes = chunkedWrites("c", value, opts);
    expect(writes.map((w) => w.name)).toEqual(["c.0", "c.1", "c.2"]);
    expect(readChunked(writes, "c")).toBe(value);
  });

  it("deletes chunks left over from a longer value", () => {
    const writes = chunkedWrites("c", "short", opts, ["c.0", "c.1", "c.2", "other"]);
    expect(writes).toEqual([
      { name: "c.0", value: "short", options: opts },
      { name: "c.1", value: "", options: { ...opts, maxAge: 0 } },
      { name: "c.2", value: "", options: { ...opts, maxAge: 0 } },
    ]);
  });

  it("clears only the chunks the browser has", () => {
    expect(clearChunked("c", opts, ["c.0", "c.x", "cc.0"]).map((w) => w.name)).toEqual(["c.0"]);
  });

  it("stops at the first missing chunk", () => {
    expect(
      readChunked(
        [
          { name: "c.0", value: "a" },
          { name: "c.2", value: "c" },
        ],
        "c",
      ),
    ).toBe("a");
    expect(readChunked([], "c")).toBeUndefined();
  });

  it("uses the __Host- prefix and Secure only over HTTPS", () => {
    expect(cookieNames(true).session).toBe("__Host-omsso_admin");
    expect(cookieNames(false).session).toBe("omsso_admin");
    expect(cookieOptions(true, 1)).toMatchObject({ httpOnly: true, secure: true, sameSite: "lax", path: "/" });
    expect(cookieOptions(false, 1).secure).toBe(false);
  });
});
