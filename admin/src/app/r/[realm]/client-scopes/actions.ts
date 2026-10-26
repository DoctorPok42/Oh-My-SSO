"use server";

import { act, api, apiPath } from "@/lib/api";
import type { ClaimMapper, ClientScope } from "@/lib/types";

export type ScopeBody = {
  name?: string;
  description?: string;
  protocol?: string;
  is_default?: boolean;
  claim_mappers?: ClaimMapper[];
};

export async function createScope(realm: string, body: ScopeBody) {
  return act(() => api<ClientScope>(apiPath(["realms", realm, "client-scopes"]), { method: "POST", body }));
}

export async function updateScope(realm: string, id: string, body: ScopeBody) {
  return act(() => api<ClientScope>(apiPath(["realms", realm, "client-scopes", id]), { method: "PATCH", body }));
}

export async function deleteScope(realm: string, id: string) {
  return act(() => api<void>(apiPath(["realms", realm, "client-scopes", id]), { method: "DELETE" }));
}
