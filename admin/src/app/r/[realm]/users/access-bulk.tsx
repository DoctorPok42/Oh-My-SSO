"use client";

import type { ReactNode } from "react";
import { BulkProvider, type BulkAction } from "@/components/console/bulk";
import { useT } from "@/i18n/client";
import { bulkAccess } from "./actions";

export function AccessBulk({
  realm,
  kind,
  page,
  children,
}: {
  realm: string;
  kind: "roles" | "groups";
  page: string[];
  children: ReactNode;
}) {
  const { t, tn } = useT();
  const roles = kind === "roles";
  const actions: BulkAction[] = [];
  if (roles) {
    actions.push({
      id: "duplicate",
      label: t("bulk.roles.duplicate", "Duplicate"),
      title: (n) => tn("bulk.roles.duplicate_title", n, "Duplicate {count} role?", "Duplicate {count} roles?"),
      description: t(
        "bulk.roles.duplicate_text",
        'A copy named "<name>-copy" gets the same permissions and client scopes, and no member.',
      ),
      run: (ids) => bulkAccess(realm, kind, { action: "duplicate", ids }),
    });
  }
  actions.push({
    id: "delete",
    label: t("bulk.users.delete", "Delete"),
    danger: true,
    confirmWord: t("bulk.word_delete", "delete"),
    title: (n) =>
      roles
        ? tn("bulk.roles.delete_title", n, "Delete {count} role?", "Delete {count} roles?")
        : tn("bulk.groups.delete_title", n, "Delete {count} group?", "Delete {count} groups?"),
    description: roles
      ? t(
          "bulk.roles.delete_text",
          "These roles are permanently deleted. A role still assigned to someone, or managed by the configuration, is skipped.",
        )
      : t(
          "bulk.groups.delete_text",
          "These groups are permanently deleted: their members lose what they grant. Groups managed by the configuration are left out.",
        ),
    run: (ids) => bulkAccess(realm, kind, { action: "delete", ids }),
  });
  return (
    <BulkProvider
      scope={`${kind}:${realm}`}
      realm={realm}
      page={page}
      total={page.length}
      actions={actions}
      countLabel={(n) =>
        roles
          ? tn("bulk.roles.selected", n, "{count} role selected", "{count} roles selected")
          : tn("bulk.groups.selected", n, "{count} group selected", "{count} groups selected")
      }
      doneLabel={(n) =>
        roles
          ? tn("bulk.roles.done", n, "{count} role updated", "{count} roles updated")
          : tn("bulk.groups.done", n, "{count} group deleted", "{count} groups deleted")
      }
    >
      {children}
    </BulkProvider>
  );
}
