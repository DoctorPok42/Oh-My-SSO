"use server";

import { act, api, apiPath, getBulkLimit } from "@/lib/api";
import { BULK_TIMEOUT_MS, collectIds, type BulkBody, type BulkResult } from "@/lib/bulk";
import type { Client, ClientBody, ClientCreated, ClientSummary, List } from "@/lib/types";

// Server Actions: functions the browser calls like an API, run here on the
// server (POST to the page, protected against cross-site calls by Next.js).
// They only forward to the Admin API, which checks permissions and step-up.
// https://nextjs.org/docs/app/getting-started/updating-data

export async function bulkClients(realm: string, body: BulkBody) {
  return act(() =>
    api<BulkResult>(apiPath(["realms", realm, "clients", "bulk"]), {
      method: "POST",
      body,
      timeoutMs: BULK_TIMEOUT_MS,
    }),
  );
}

/** "Select the results of the filter": not those the configuration manages. */
export async function matchingClientIds(realm: string, protocol: string | undefined, exclude: string[]) {
  return act(async () =>
    collectIds(
      (offset, limit) => api<List<ClientSummary>>(apiPath(["realms", realm, "clients"], { protocol, offset, limit })),
      exclude,
      (c) => c.managed_by !== "config",
      await getBulkLimit(realm),
    ),
  );
}

export async function exportClients(realm: string, ids: string[]) {
  return act(() => api<{ items: Client[] }>(apiPath(["realms", realm, "clients", "export"], { ids: ids.join(",") })));
}

export async function createClient(realm: string, body: ClientBody) {
  return act(() => api<ClientCreated>(apiPath(["realms", realm, "clients"]), { method: "POST", body }));
}

export async function updateClient(realm: string, id: string, body: ClientBody) {
  return act(() => api<Client>(apiPath(["realms", realm, "clients", id]), { method: "PATCH", body }));
}

export async function deleteClient(realm: string, id: string) {
  return act(() => api<void>(apiPath(["realms", realm, "clients", id]), { method: "DELETE" }));
}

export async function rotateClientSecret(realm: string, id: string) {
  return act(() => api<{ secret: string }>(apiPath(["realms", realm, "clients", id, "secret"]), { method: "POST" }));
}

export async function addCertificate(
  realm: string,
  id: string,
  cert: { pem: string; not_before: string | null; not_after: string | null },
) {
  return act(() =>
    api<Client>(apiPath(["realms", realm, "clients", id, "certificates"]), { method: "POST", body: cert }),
  );
}

export async function removeCertificate(realm: string, id: string, fingerprint: string) {
  return act(() =>
    api<Client>(apiPath(["realms", realm, "clients", id, "certificates", fingerprint]), { method: "DELETE" }),
  );
}
