"use client";

import type { ReactNode } from "react";
import { BulkProvider } from "@/components/console/bulk";
import { useT } from "@/i18n/client";
import { bulkTimeouts, matchingTimeoutIds } from "./actions";

export function TimeoutsBulk({
  realm,
  status,
  page,
  total,
  children,
}: {
  realm: string;
  status: string;
  page: string[];
  total: number;
  children: ReactNode;
}) {
  const { t, tn } = useT();
  return (
    <BulkProvider
      scope={`timeouts:${realm}:${status}`}
      realm={realm}
      page={page}
      total={total}
      countLabel={(n) => tn("bulk.timeouts.selected", n, "{count} timeout selected", "{count} timeouts selected")}
      doneLabel={(n) => tn("bulk.timeouts.done", n, "{count} timeout lifted", "{count} timeouts lifted")}
      matching={(exclude) => matchingTimeoutIds(realm, status, exclude)}
      actions={[
        {
          id: "lift",
          label: t("bulk.timeouts.lift", "Lift"),
          title: (n) => tn("bulk.timeouts.lift_title", n, "Lift {count} timeout?", "Lift {count} timeouts?"),
          description: t("bulk.timeouts.lift_text", "What these timeouts blocked can sign in again."),
          run: (ids) => bulkTimeouts(realm, { action: "lift", ids }),
        },
      ]}
    >
      {children}
    </BulkProvider>
  );
}
