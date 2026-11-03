import { describe, expect, it } from "vitest";
import { actionLabel, actorName, isNotification } from "@/lib/labels";

describe("audit labels", () => {
  it("uses the catalogue's label, else words the code", () => {
    const catalog = new Map([["user.locked", "Account locked"]]);
    expect(actionLabel("user.locked", catalog)).toBe("Account locked");
    expect(actionLabel("client.secret_rotated")).toBe("Client · secret rotated");
  });

  it("names the actor, or the kind of actor when nobody is signed in", () => {
    expect(actorName({ actor_type: "admin", actor: { id: "a1", username: "root" } })).toBe("root");
    expect(actorName({ actor_type: "admin", actor: { id: "a1", username: "" } })).toBe("a1");
    expect(actorName({ actor_type: "system", actor: null })).toBe("system");
    expect(actorName({ actor_type: "anonymous", actor: null })).toBe("anonymous");
  });

  it("tells e-mails apart", () => {
    expect(isNotification("notification.sent")).toBe(true);
    expect(isNotification("user.invited")).toBe(false);
  });
});
