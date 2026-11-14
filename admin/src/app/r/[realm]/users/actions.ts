"use server";

import { act, api, apiPath, getBulkLimit } from "@/lib/api";
import { collectIds, type BulkBody, type BulkJob } from "@/lib/bulk";
import { invalidate } from "@/lib/cache";
import type {
  Access,
  InviteResult,
  List,
  Permission,
  UserDetail,
  UserImport,
  UserImportLinks,
  UserImportPreview,
} from "@/lib/types";

/** A whole file is checked in these calls: up to a thousand lines. */
const IMPORT_TIMEOUT_MS = 60_000;

export async function bulkUsers(realm: string, body: BulkBody) {
  return act(() => api<BulkJob>(apiPath(["realms", realm, "users", "bulk"]), { method: "POST", body }));
}

export async function bulkAccess(realm: string, kind: "roles" | "groups", body: BulkBody) {
  return act(() => api<BulkJob>(apiPath(["realms", realm, kind, "bulk"]), { method: "POST", body }));
}

/** A pasted list of usernames or e-mails. */
export async function addGroupMembers(realm: string, id: string, identifiers: string[]) {
  return act(() =>
    api<BulkJob>(apiPath(["realms", realm, "groups", id, "members", "bulk"]), {
      method: "POST",
      body: { identifiers },
    }),
  );
}

/** "Select the results of the filter". */
export async function matchingUserIds(
  realm: string,
  filter: { q?: string; status?: string; locked?: boolean },
  exclude: string[],
) {
  const { locked, ...rest } = filter;
  return act(async () =>
    collectIds(
      (offset, limit) =>
        api<List<{ id: string }>>(
          apiPath(["realms", realm, "users"], { ...rest, locked: locked ? "true" : undefined, offset, limit }),
        ),
      exclude,
      undefined,
      await getBulkLimit(realm),
    ),
  );
}

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

/** What a CSV file would do: nothing is written. */
export async function previewUserImport(realm: string, csv: string) {
  return act(() =>
    api<UserImportPreview>(apiPath(["realms", realm, "users", "imports", "preview"]), {
      method: "POST",
      body: { csv },
      timeoutMs: IMPORT_TIMEOUT_MS,
    }),
  );
}

export async function startUserImport(
  realm: string,
  body: { csv: string; file_name: string; send_email: boolean; notify_when_done: boolean },
) {
  return act(() =>
    api<UserImport>(apiPath(["realms", realm, "users", "imports"]), {
      method: "POST",
      body,
      timeoutMs: IMPORT_TIMEOUT_MS,
    }),
  );
}

export async function listUserImports(realm: string) {
  return act(() => api<{ items: UserImport[] }>(apiPath(["realms", realm, "users", "imports"])));
}

export async function getUserImport(realm: string, id: string) {
  return act(async () => {
    const job = await api<UserImport>(apiPath(["realms", realm, "users", "imports", id]));
    // The accounts were created outside any call of this console.
    if (job.status !== "running") invalidate(apiPath(["realms", realm, "users"]));
    return job;
  });
}

/** New links each time: they are not stored, and the previous ones stop working. */
export async function userImportLinks(realm: string, id: string) {
  return act(() =>
    api<UserImportLinks>(apiPath(["realms", realm, "users", "imports", id, "activation-links"]), {
      method: "POST",
      timeoutMs: IMPORT_TIMEOUT_MS,
    }),
  );
}

/** E-mails a new activation link to the accounts whose invitation did not get through. */
export async function resendImportInvitations(realm: string, id: string) {
  return act(() =>
    api<{ sent: number }>(apiPath(["realms", realm, "users", "imports", id, "resend-invitations"]), {
      method: "POST",
      timeoutMs: IMPORT_TIMEOUT_MS,
    }),
  );
}

/** Profile keys are merged; a null value removes the key. */
export async function updateUser(
  realm: string,
  id: string,
  body: {
    username?: string;
    email?: string;
    status?: string;
    profile?: Record<string, string | null>;
    email_verified?: boolean;
  },
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

/** E-mails the user a link that confirms their address. */
export async function sendEmailVerification(realm: string, id: string) {
  return act(() => api<UserDetail>(apiPath(["realms", realm, "users", id, "email-verification"]), { method: "POST" }));
}

/** Sends a failed (or waiting) e-mail again, with 24 h more to get through. */
export async function resendEmail(realm: string, id: string, emailId: string) {
  return act(() =>
    api<UserDetail>(apiPath(["realms", realm, "users", id, "emails", emailId, "resend"]), { method: "POST" }),
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

export async function createPermission(realm: string, body: { resource: string; action: string; description: string }) {
  return act(() => api<Permission>(apiPath(["realms", realm, "permissions"]), { method: "POST", body }));
}

export async function deletePermission(realm: string, id: string) {
  return act(() => api<void>(apiPath(["realms", realm, "permissions", id]), { method: "DELETE" }));
}
