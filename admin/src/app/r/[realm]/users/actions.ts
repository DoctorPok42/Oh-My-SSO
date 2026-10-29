"use server";

import { act, api, apiPath } from "@/lib/api";
import type { Access, InviteResult, Permission, UserDetail } from "@/lib/types";

// --- users ------------------------------------------------------------------------

export async function inviteUser(
  realm: string,
  body: {
    username: string;
    email: string;
    profile: Record<string, string>;
    group_ids: string[];
    role_ids: string[];
    send_email: boolean;
  },
) {
  return act(() => api<InviteResult>(apiPath(["realms", realm, "users"]), { method: "POST", body }));
}

/** Profile keys are merged; a null value removes the key. */
export async function updateUser(
  realm: string,
  id: string,
  body: { username?: string; email?: string; status?: string; profile?: Record<string, string | null> },
) {
  return act(() => api<UserDetail>(apiPath(["realms", realm, "users", id]), { method: "PATCH", body }));
}

export async function setUserGroups(realm: string, id: string, groupIds: string[]) {
  return act(() =>
    api<UserDetail>(apiPath(["realms", realm, "users", id, "groups"]), {
      method: "PUT",
      body: { group_ids: groupIds },
    }),
  );
}

export async function setUserRoles(realm: string, id: string, roleIds: string[]) {
  return act(() =>
    api<UserDetail>(apiPath(["realms", realm, "users", id, "roles"]), { method: "PUT", body: { role_ids: roleIds } }),
  );
}

export async function deleteUser(realm: string, id: string) {
  return act(() => api<void>(apiPath(["realms", realm, "users", id]), { method: "DELETE" }));
}

export async function resetUserMfa(realm: string, id: string, reason: string) {
  return act(() =>
    api<{ methods_deleted: number; backup_codes_deleted: number }>(
      apiPath(["realms", realm, "users", id, "mfa", "reset"]),
      {
        method: "POST",
        body: { reason },
      },
    ),
  );
}

export async function unlockUser(realm: string, id: string) {
  return act(() => api<void>(apiPath(["realms", realm, "users", id, "unlock"]), { method: "POST" }));
}

export async function resendActivation(realm: string, id: string, sendEmail: boolean) {
  return act(() =>
    api<InviteResult>(apiPath(["realms", realm, "users", id, "activation-link"]), {
      method: "POST",
      body: { send_email: sendEmail },
    }),
  );
}

export async function revokeUserSessions(realm: string, id: string) {
  return act(() => api<void>(apiPath(["realms", realm, "users", id, "sessions"]), { method: "DELETE" }));
}

/** The next sign-in on that device asks for the second factor again. */
export async function revokeTrustedDevice(realm: string, id: string, deviceId: string) {
  return act(() =>
    api<void>(apiPath(["realms", realm, "users", id, "trusted-devices", deviceId]), { method: "DELETE" }),
  );
}

export async function revokeTrustedDevices(realm: string, id: string) {
  return act(() => api<void>(apiPath(["realms", realm, "users", id, "trusted-devices"]), { method: "DELETE" }));
}

// --- roles and groups --------------------------------------------------------------

export type AccessBody = {
  name?: string;
  description?: string;
  active?: boolean;
  permission_ids?: string[];
  client_scope_ids?: string[];
};

const KINDS = ["roles", "groups"];

export async function saveAccess(realm: string, kind: "roles" | "groups", id: string | null, body: AccessBody) {
  // Arguments of a Server Action come from the browser: checked like any input.
  if (!KINDS.includes(kind)) return act(() => Promise.reject(new Error("bad kind")));
  return act(() =>
    id
      ? api<Access>(apiPath(["realms", realm, kind, id]), { method: "PATCH", body })
      : api<Access>(apiPath(["realms", realm, kind]), { method: "POST", body }),
  );
}

export async function deleteAccess(realm: string, kind: "roles" | "groups", id: string) {
  if (!KINDS.includes(kind)) return act(() => Promise.reject(new Error("bad kind")));
  return act(() => api<void>(apiPath(["realms", realm, kind, id]), { method: "DELETE" }));
}

// --- permissions ---------------------------------------------------------------------

export async function createPermission(realm: string, body: { resource: string; action: string; description: string }) {
  return act(() => api<Permission>(apiPath(["realms", realm, "permissions"]), { method: "POST", body }));
}

export async function deletePermission(realm: string, id: string) {
  return act(() => api<void>(apiPath(["realms", realm, "permissions", id]), { method: "DELETE" }));
}
