"use server";

import { act, api, apiPath, getBulkLimit } from "@/lib/api";
import { collectIds, type BulkBody, type BulkJob } from "@/lib/bulk";
import type { List } from "@/lib/types";

/** Signs the user out of this session: its tokens stop working at once. */
export async function revokeSession(realm: string, id: string) {
  return act(() => api<void>(apiPath(["realms", realm, "sessions", id]), { method: "DELETE" }));
}

export async function bulkSessions(realm: string, body: BulkBody) {
  return act(() =>
    api<BulkJob>(apiPath(["realms", realm, "sessions", "bulk"]), {
      method: "POST",
      body,
    }),
  );
}

/** "Select the results of the filter". */
export async function matchingSessionIds(
  realm: string,
  filter: { user?: string; client?: string; ip?: string },
  exclude: string[],
) {
  return act(async () =>
    collectIds(
      (offset, limit) =>
        api<List<{ id: string }>>(apiPath(["realms", realm, "sessions"], { ...filter, offset, limit })),
      exclude,
      undefined,
      await getBulkLimit(realm),
    ),
  );
}
