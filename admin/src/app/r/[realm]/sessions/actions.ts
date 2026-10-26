"use server";

import { act, api, apiPath } from "@/lib/api";

/** Signs the user out of this session: its tokens stop working at once. */
export async function revokeSession(realm: string, id: string) {
  return act(() => api<void>(apiPath(["realms", realm, "sessions", id]), { method: "DELETE" }));
}
