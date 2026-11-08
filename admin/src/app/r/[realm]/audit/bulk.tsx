"use client";

import type { ReactNode } from "react";
import { toast } from "sonner";
import { BulkProvider } from "@/components/console/bulk";
import { useT } from "@/i18n/client";

/** The log cannot change: the selection can only be exported. */
export function AuditBulk({
  realm,
  base,
  page,
  children,
}: {
  realm: string;
  base: string;
  page: string[];
  children: ReactNode;
}) {
  const { t, tn } = useT();
  // POST: the ids of a large selection do not fit in a URL (export/route.ts).
  const download = (format: "csv" | "json") => async (ids: string[]) => {
    const res = await fetch(`${base}/export`, {
      method: "POST",
      body: new URLSearchParams({ format, ids: ids.join(",") }),
    }).catch(() => null);
    if (res?.redirected) {
      window.location.href = res.url; // the session ended: sign in again
      return;
    }
    if (!res?.ok) {
      const body = (await res?.json().catch(() => null)) as { message?: string } | null;
      toast.error(body?.message ?? t("audit.export.failed", "The export failed. Try again."));
      return;
    }
    const name = /filename="?([^";]+)"?/.exec(res.headers.get("content-disposition") ?? "")?.[1];
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = name ?? `audit.${format}`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000); // after the download started
  };
  return (
    <BulkProvider
      scope={`audit:${realm}`}
      realm={realm}
      page={page}
      total={page.length}
      countLabel={(n) => tn("bulk.audit.selected", n, "{count} entry selected", "{count} entries selected")}
      doneLabel={(n) => String(n)}
      actions={[
        { id: "csv", label: t("bulk.audit.csv", "Export as CSV"), direct: download("csv") },
        { id: "json", label: t("bulk.audit.json", "Export as JSON"), direct: download("json") },
      ]}
    >
      {children}
    </BulkProvider>
  );
}
