"use server";

import { act, api, apiPath } from "@/lib/api";
import type { MfaPolicies } from "@/lib/types";

export async function setRealmMfa(
  realm: string,
  body: { required_globally?: boolean; step_up_max_age_minutes?: number },
) {
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

/** Back to the realm's default for this role. */
export async function deleteRoleMfa(realm: string, roleId: string) {
  return act(() => api<MfaPolicies>(apiPath(["realms", realm, "mfa-policies", "roles", roleId]), { method: "DELETE" }));
}
