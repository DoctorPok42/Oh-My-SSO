"use server";

import { act, api, apiPath } from "@/lib/api";
import type { RotateResult, SigningKey } from "@/lib/types";

export async function rotateKey(
  realm: string,
  body: { purpose: string; key_type: string; grace_hours: number; compromised: boolean; reason: string },
) {
  return act(() => api<RotateResult>(apiPath(["realms", realm, "signing-keys", "rotate"]), { method: "POST", body }));
}

export async function activateKey(realm: string, body: { purpose: string; grace_hours: number; reason: string }) {
  return act(() => api<RotateResult>(apiPath(["realms", realm, "signing-keys", "activate"]), { method: "POST", body }));
}

export async function retireExpiredKeys(realm: string) {
  return act(() =>
    api<{ keys: SigningKey[] }>(apiPath(["realms", realm, "signing-keys", "retire-expired"]), {
      method: "POST",
      body: {},
    }),
  );
}
