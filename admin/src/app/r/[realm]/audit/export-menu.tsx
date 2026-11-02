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
  const filtered = Object.values(filters).some(Boolean);
  const period = filters.from || filters.to ? `${filters.from ?? "the start"} → ${filters.to ?? "today"}` : "any date";
  return (
    <DropdownMenu>
      <DropdownMenuTrigger className={cn(buttonVariants({ variant: "secondary", size: "sm" }))}>
        <Download className="size-4" />
        Export
        <ChevronDown className="size-3.5" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuLabel>
          {filtered ? `Entries matching the filters (${period})` : "Every entry of the realm"}
        </DropdownMenuLabel>
        <DropdownMenuItem asChild>
          <a href={href("csv", true)} download>
            CSV (spreadsheet)
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
            <DropdownMenuLabel>Whole log, without filters</DropdownMenuLabel>
            <DropdownMenuItem asChild>
              <a href={href("csv", false)} download>
                CSV (spreadsheet)
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
