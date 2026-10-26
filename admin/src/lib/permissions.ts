import type { Me } from "@/lib/types";

// What the signed-in admin may do, from GET /me ("client:write"...). The
// console hides what is not allowed; the Admin API checks again anyway.

export type Resource =
  | "realm"
  | "client"
  | "client_scope"
  | "session"
  | "audit_log"
  | "user"
  | "access"
  | "signing_key"
  | "mfa_policy"
  | "settings"
  | "timeout";

export function can(me: Pick<Me, "permissions"> | null | undefined, resource: Resource, action = "read"): boolean {
  return !!me?.permissions.includes(`${resource}:${action}`);
}

/** The write permission of each resource (sessions are revoked, keys rotated). */
export const WRITE_ACTION: Record<Resource, string> = {
  realm: "write",
  client: "write",
  client_scope: "write",
  session: "revoke",
  audit_log: "write",
  user: "write",
  access: "write",
  signing_key: "rotate",
  mfa_policy: "write",
  settings: "write",
  timeout: "write",
};

export function canWrite(me: Pick<Me, "permissions"> | null | undefined, resource: Resource): boolean {
  return can(me, resource, WRITE_ACTION[resource]);
}

/** A second factor verified recently enough: changes go through without a new sign-in. */
export function stepUpFresh(me: Pick<Me, "step_up_fresh_until"> | null | undefined, now = Date.now()): boolean {
  if (!me?.step_up_fresh_until) return false;
  return new Date(me.step_up_fresh_until).getTime() - now > 15_000;
}
