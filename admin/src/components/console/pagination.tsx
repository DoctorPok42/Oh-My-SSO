"use client";

import { NavLink } from "@/components/console/nav-link";
import { buttonVariants } from "@/components/ui/button";
import { useT } from "@/i18n/client";
import { pageLabel } from "@/lib/format";
import { cn } from "@/lib/utils";

// "1–20 of 43   Previous  Next" under a table. Pages are URL parameters
// (offset), so Back/Forward and shared links work. The pages read the
// offset with offsetParam (lib/pagination.ts): a "use client" module like
// this one may only give components to the server.
export function Pagination({
  basePath,
  params,
  offset,
  limit,
  count,
  total,
}: {
  basePath: string;
  params: Record<string, string | undefined>;
  offset: number;
  limit: number;
  count: number;
  total: number;
}) {
  const href = (o: number) => {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v) q.set(k, v);
    if (o > 0) q.set("offset", String(o));
    else q.delete("offset");
    const s = q.toString();
    return s ? `${basePath}?${s}` : basePath;
  };
  const tr = useT();
  const { t } = tr;
  const hasPrev = offset > 0;
  const hasNext = offset + count < total;
  const btn = cn(buttonVariants({ variant: "secondary", size: "xs" }));
  return (
    <div className="flex items-center justify-between border-t border-border px-4 py-3 text-[13px] text-text-muted">
      <span>{pageLabel(offset, count, total, tr)}</span>
      <div className="flex gap-2">
        {hasPrev ? (
          <NavLink className={btn} href={href(Math.max(0, offset - limit))}>
            {t("pagination.previous", "Previous")}
          </NavLink>
        ) : (
          <span className={cn(btn, "pointer-events-none opacity-50")} aria-disabled>
            {t("pagination.previous", "Previous")}
          </span>
        )}
        {hasNext ? (
          <NavLink className={btn} href={href(offset + limit)}>
            {t("pagination.next", "Next")}
          </NavLink>
        ) : (
          <span className={cn(btn, "pointer-events-none opacity-50")} aria-disabled>
            {t("pagination.next", "Next")}
          </span>
        )}
      </div>
    </div>
  );
}
