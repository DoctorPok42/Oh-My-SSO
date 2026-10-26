"use server";

import { act, api, apiPath } from "@/lib/api";
import type { CreateRealmResult, RealmDetail } from "@/lib/types";

export async function createRealm(body: { name: string; display_name: string }) {
  return act(() => api<CreateRealmResult>(apiPath(["realms"]), { method: "POST", body }));
}

export async function updateRealm(name: string, body: { display_name?: string; status?: "active" | "inactive" }) {
  return act(() => api<RealmDetail>(apiPath(["realms", name]), { method: "PATCH", body }));
}
