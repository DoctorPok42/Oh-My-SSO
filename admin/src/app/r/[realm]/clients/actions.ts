"use server";

import { act, api, apiPath } from "@/lib/api";
import type { Client, ClientBody, ClientCreated } from "@/lib/types";

// Server Actions: functions the browser calls like an API, run here on the
// server (POST to the page, protected against cross-site calls by Next.js).
// They only forward to the Admin API, which checks permissions and step-up.
// https://nextjs.org/docs/app/getting-started/updating-data

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
