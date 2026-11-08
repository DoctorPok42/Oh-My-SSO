"use client";

import type { ReactNode } from "react";
import { BulkProvider } from "@/components/console/bulk";
import { useT } from "@/i18n/client";
import { bulkSessions, matchingSessionIds } from "./actions";

export function SessionsBulk({
  realm,
  scope,
  filter,
  page,
  total,
  ownId,
  children,
}: {
  realm: string;
  scope: string;
  filter: { user?: string; client?: string; ip?: string };
  page: string[];
  total: number;
  /** The session this console runs on: never revoked by a bulk action. */
  ownId?: string;
  children: ReactNode;
}) {
  const { t, tn } = useT();
  return (
    <BulkProvider
      scope={scope}
      realm={realm}
      page={page}
      total={total}
      countLabel={(n) => tn("bulk.sessions.selected", n, "{count} session selected", "{count} sessions selected")}
      doneLabel={(n) => tn("bulk.sessions.done", n, "{count} session revoked", "{count} sessions revoked")}
      matching={(exclude) => matchingSessionIds(realm, filter, ownId ? [...exclude, ownId] : exclude)}
      actions={[
        {
          id: "revoke",
          label: t("bulk.sessions.revoke", "Revoke"),
          danger: true,
          title: (n) => tn("bulk.sessions.revoke_title", n, "Revoke {count} session?", "Revoke {count} sessions?"),
          description: t(
            "bulk.sessions.revoke_text",
            "These sessions end now: the applications lose their tokens, and the users must sign in again. Your own session is never part of a bulk action.",
          ),
          run: (ids) => bulkSessions(realm, { action: "revoke", ids }),
        },
      ]}
    >
      {children}
    </BulkProvider>
  );
}
