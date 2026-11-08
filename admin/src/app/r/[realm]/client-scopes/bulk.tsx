"use client";

import type { ReactNode } from "react";
import { BulkProvider } from "@/components/console/bulk";
import { useT } from "@/i18n/client";
import { bulkScopes } from "./actions";

export function ScopesBulk({ realm, page, children }: { realm: string; page: string[]; children: ReactNode }) {
  const { t, tn } = useT();
  return (
    <BulkProvider
      scope={`client-scopes:${realm}`}
      realm={realm}
      page={page}
      total={page.length}
      countLabel={(n) => tn("bulk.scopes.selected", n, "{count} scope selected", "{count} scopes selected")}
      doneLabel={(n) => tn("bulk.scopes.done", n, "{count} scope deleted", "{count} scopes deleted")}
      actions={[
        {
          id: "delete",
          label: t("bulk.users.delete", "Delete"),
          danger: true,
          confirmWord: t("bulk.word_delete", "delete"),
          title: (n) => tn("bulk.scopes.delete_title", n, "Delete {count} scope?", "Delete {count} scopes?"),
          description: t("bulk.scopes.delete_text", "These client scopes are permanently deleted."),
          run: (ids) => bulkScopes(realm, { action: "delete", ids }),
        },
      ]}
    >
      {children}
    </BulkProvider>
  );
}
