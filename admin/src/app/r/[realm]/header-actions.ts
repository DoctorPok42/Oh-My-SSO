"use server";

import { act, api, apiPath } from "@/lib/api";
import type { AuditEntry, List } from "@/lib/types";

/** The bell: the realm's latest warnings and errors (loaded after the page, never blocking it). */
export async function recentAlerts(realm: string) {
  return act(() =>
    api<List<AuditEntry>>(
      apiPath(["realms", realm, "audit-logs"], { level: "suspicious,warning,error,critical", limit: 8 }),
    ),
  );
}
