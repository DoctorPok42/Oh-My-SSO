"use server";

import { act, api, apiPath } from "@/lib/api";
import type { BulkBody, BulkJob } from "@/lib/bulk";
import type { RealmMfaBody } from "@/lib/mfa-form";
import type { MfaPolicies } from "@/lib/types";

export async function setRealmMfa(realm: string, body: RealmMfaBody) {
  return act(() => api<MfaPolicies>(apiPath(["realms", realm, "mfa-policies", "realm"]), { method: "PUT", body }));
}

export async function setRoleMfa(
  realm: string,
  roleId: string,
  body: {
    required: boolean;
    allowed_methods: string[];
    enrollment_grace_days: number;
    step_up_for_sensitive_actions: boolean;
  },
) {
  return act(() =>
    api<MfaPolicies>(apiPath(["realms", realm, "mfa-policies", "roles", roleId]), { method: "PUT", body }),
  );
}

/** One setting of the MFA policy of many roles: require, optional, step_up_on, step_up_off, inherit. */
export async function bulkRoleMfa(realm: string, body: BulkBody) {
  return act(() =>
    api<BulkJob>(apiPath(["realms", realm, "mfa-policies", "roles", "bulk"]), {
      method: "POST",
      body,
    }),
  );
}

/** Back to the realm's default for this role. */
export async function deleteRoleMfa(realm: string, roleId: string) {
  return act(() => api<MfaPolicies>(apiPath(["realms", realm, "mfa-policies", "roles", roleId]), { method: "DELETE" }));
}
