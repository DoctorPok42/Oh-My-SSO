"use server";

import { act, api, apiPath } from "@/lib/api";
import type { TimeoutCreateBody } from "@/lib/timeout-form";
import type { Access, ClientSummary, List, Timeout, TimeoutTargetType, UserSummary } from "@/lib/types";

export async function createTimeout(realm: string, body: TimeoutCreateBody) {
  return act(() => api<Timeout>(apiPath(["realms", realm, "timeouts"]), { method: "POST", body }));
}

/** reason and/or ends_at ("" removes the end). */
export async function updateTimeout(realm: string, id: string, body: { reason?: string; ends_at?: string }) {
  return act(() => api<Timeout>(apiPath(["realms", realm, "timeouts", id]), { method: "PATCH", body }));
}

export async function liftTimeout(realm: string, id: string) {
  return act(() => api<Timeout>(apiPath(["realms", realm, "timeouts", id, "lift"]), { method: "POST" }));
}

export type TargetOption = { id: string; name: string; hint: string };

const MAX_OPTIONS = 8;

/**
 * The targets matching q, for the form's search. Users are searched by the
 * Admin API (there can be many); groups and clients are few, filtered here.
 */
export async function searchTimeoutTargets(realm: string, type: TimeoutTargetType, q: string) {
  const query = q.trim().toLowerCase();
  return act(async (): Promise<TargetOption[]> => {
    if (type === "user") {
      const list = await api<List<UserSummary>>(apiPath(["realms", realm, "users"], { q: query, limit: MAX_OPTIONS }));
      return list.items.map((u) => ({
        id: u.id,
        name: u.username,
        hint: [u.name, u.email].filter(Boolean).join(" · "),
      }));
    }
    if (type === "group") {
      const list = await api<List<Access>>(apiPath(["realms", realm, "groups"]));
      return list.items
        .filter((g) => !query || g.name.toLowerCase().includes(query))
        .slice(0, MAX_OPTIONS)
        .map((g) => ({ id: g.id, name: g.name, hint: `${g.members} member${g.members === 1 ? "" : "s"}` }));
    }
    const list = await api<List<ClientSummary>>(apiPath(["realms", realm, "clients"], { limit: 200 }));
    return list.items
      .filter((c) => {
        if (!query) return true;
        return [c.name, c.client_id, c.entity_id].some((v) => v?.toLowerCase().includes(query));
      })
      .slice(0, MAX_OPTIONS)
      .map((c) => ({ id: c.id, name: c.name, hint: c.client_id || c.entity_id || "" }));
  });
}
