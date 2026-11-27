"use server";

import { act, api, apiPath } from "@/lib/api";
import type { ApiResource } from "@/lib/types";

export type ApiResourceBody = {
  identifier?: string; // create only
  name?: string;
  description?: string;
  scope_ids?: string[];
};

export async function createApiResource(realm: string, body: ApiResourceBody) {
  return act(() => api<ApiResource>(apiPath(["realms", realm, "api-resources"]), { method: "POST", body }));
}

export async function updateApiResource(realm: string, id: string, body: ApiResourceBody) {
  return act(() => api<ApiResource>(apiPath(["realms", realm, "api-resources", id]), { method: "PATCH", body }));
}

export async function deleteApiResource(realm: string, id: string) {
  return act(() => api<void>(apiPath(["realms", realm, "api-resources", id]), { method: "DELETE" }));
}
