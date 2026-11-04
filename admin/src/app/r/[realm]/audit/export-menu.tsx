"use client";

import { ChevronDown, Download } from "lucide-react";
import { buttonVariants } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useT } from "@/i18n/client";
import { cn } from "@/lib/utils";

// "Export": the entries matching the current filters (the From / To fields
// give the period), or the whole log, as CSV or JSON. A plain download link
// to the console's own route (./export/route.ts), which streams the file
// from the Admin API.
export function ExportMenu({ base, filters }: { base: string; filters: Record<string, string | undefined> }) {
  const href = (format: "csv" | "json", filtered: boolean) => {
    const q = new URLSearchParams({ format });
    if (filtered) for (const [k, v] of Object.entries(filters)) if (v) q.set(k, v);
    return `${base}/export?${q.toString()}`;
  };
  const { t } = useT();
  const filtered = Object.values(filters).some(Boolean);
  const period =
    filters.from || filters.to
      ? `${filters.from ?? t("audit.export.start", "the start")} → ${filters.to ?? t("audit.export.today", "today")}`
      : t("audit.export.any_date", "any date");
  return (
    <DropdownMenu>
      <DropdownMenuTrigger className={cn("group", buttonVariants({ variant: "secondary", size: "sm" }))}>
        <Download className="size-4" />
        {t("audit.export.label", "Export")}
        <ChevronDown className="size-3.5 transition-transform group-data-[state=open]:rotate-180" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuLabel>
          {filtered
            ? t("audit.export.filtered", "Entries matching the filters ({period})", { period })
            : t("audit.export.all", "Every entry of the realm")}
        </DropdownMenuLabel>
        <DropdownMenuItem asChild>
          <a href={href("csv", true)} download>
            {t("audit.export.csv", "CSV (spreadsheet)")}
          </a>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <a href={href("json", true)} download>
            JSON
          </a>
        </DropdownMenuItem>
        {filtered && (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuLabel>{t("audit.export.whole", "Whole log, without filters")}</DropdownMenuLabel>
            <DropdownMenuItem asChild>
              <a href={href("csv", false)} download>
                {t("audit.export.csv", "CSV (spreadsheet)")}
              </a>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <a href={href("json", false)} download>
                JSON
              </a>
            </DropdownMenuItem>
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
