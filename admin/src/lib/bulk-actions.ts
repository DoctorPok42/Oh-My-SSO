"use server";

import { act, api, apiPath } from "@/lib/api";
import type { BulkJob } from "@/lib/bulk";
import { invalidate } from "@/lib/cache";

/** Where a bulk action stands, or its report. Only the admin who started it reads it. */
export async function getBulkJob(realm: string, id: string) {
  return act(async () => {
    const job = await api<BulkJob>(apiPath(["realms", realm, "bulk-jobs", id]));
    // The items were changed outside any call of this console: what it has
    // read of the realm since the start is stale.
    if (job.status !== "running") invalidate(apiPath(["realms", realm, "bulk-jobs", id]));
    return job;
  });
}
