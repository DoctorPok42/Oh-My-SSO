"use client";

import type { ReactNode } from "react";
import { toast } from "sonner";
import { BulkProvider, type BulkAction } from "@/components/console/bulk";
import { useT } from "@/i18n/client";
import { downloadText } from "@/lib/user-import";
import { bulkClients, exportClients, matchingClientIds } from "./actions";

export function ClientsBulk({
  realm,
  protocol,
  page,
  total,
  writable,
  children,
}: {
  realm: string;
  protocol?: string;
  page: string[];
  total: number;
  /** client:write. Without it, the export is all that is left. */
  writable: boolean;
  children: ReactNode;
}) {
  const { t, tn } = useT();
  const actions: BulkAction[] = [];
  if (writable) {
    actions.push(
      {
        id: "suspend",
        label: t("bulk.users.suspend", "Suspend"),
        title: (n) => tn("bulk.clients.suspend_title", n, "Suspend {count} client?", "Suspend {count} clients?"),
        description: t(
          "bulk.clients.suspend_text",
          "Suspended clients can no longer sign anyone in. Clients managed by the configuration are left out.",
        ),
        run: (ids) => bulkClients(realm, { action: "suspend", ids }),
      },
      {
        id: "reactivate",
        label: t("bulk.users.reactivate", "Reactivate"),
        title: (n) =>
          tn("bulk.clients.reactivate_title", n, "Reactivate {count} client?", "Reactivate {count} clients?"),
        description: t("bulk.clients.reactivate_text", "These clients can sign people in again."),
        run: (ids) => bulkClients(realm, { action: "reactivate", ids }),
      },
    );
  }
  actions.push({
    id: "export",
    label: t("bulk.clients.export", "Export configuration"),
    direct: async (ids) => {
      const r = await exportClients(realm, ids);
      if (!r.ok) {
        toast.error(r.message);
        return;
      }
      downloadText(`clients-${realm}.json`, JSON.stringify(r.data.items, null, 2), "application/json");
    },
  });
  if (writable) {
    actions.push({
      id: "delete",
      label: t("bulk.users.delete", "Delete"),
      danger: true,
      confirmWord: t("bulk.word_delete", "delete"),
      title: (n) => tn("bulk.clients.delete_title", n, "Delete {count} client?", "Delete {count} clients?"),
      description: t(
        "bulk.clients.delete_text",
        "These clients are permanently deleted: the applications stop working and their tokens are revoked.",
      ),
      run: (ids) => bulkClients(realm, { action: "delete", ids }),
    });
  }
  return (
    <BulkProvider
      scope={`clients:${realm}:${protocol ?? ""}`}
      realm={realm}
      page={page}
      total={total}
      actions={actions}
      countLabel={(n) => tn("bulk.clients.selected", n, "{count} client selected", "{count} clients selected")}
      doneLabel={(n) => tn("bulk.clients.done", n, "{count} client updated", "{count} clients updated")}
      matching={(exclude) => matchingClientIds(realm, protocol, exclude)}
    >
      {children}
    </BulkProvider>
  );
}
