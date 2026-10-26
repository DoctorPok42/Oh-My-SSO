"use client";

import { ChevronRight, Mail } from "lucide-react";
import { Fragment, useState } from "react";
import { StatusBadge } from "@/components/console/status-badge";
import { TableCell, TableRow } from "@/components/ui/table";
import { actionLabel, isNotification } from "@/lib/labels";
import type { AuditEntry } from "@/lib/types";
import { cn } from "@/lib/utils";

// One line per entry; a click shows its details (the JSON the server
// recorded: changed fields, reasons, targets...).
export function AuditRows({ items, times }: { items: AuditEntry[]; times: Record<string, string> }) {
  const [open, setOpen] = useState<string | null>(null);
  return (
    <>
      {items.map((a) => {
        const expanded = open === a.id;
        return (
          <Fragment key={a.id}>
            <TableRow className="cursor-pointer" onClick={() => setOpen(expanded ? null : a.id)}>
              <TableCell className="font-mono text-[12px] whitespace-nowrap text-text-secondary">
                {times[a.id]}
              </TableCell>
              <TableCell>
                {a.actor ? (
                  <span className={cn(a.actor.admin && "font-medium")}>
                    {a.actor.username}
                    {a.actor.admin && <span className="ml-1 text-[11px] text-text-muted">(admin)</span>}
                  </span>
                ) : (
                  <span className="text-text-muted">system</span>
                )}
              </TableCell>
              <TableCell>
                <button
                  type="button"
                  aria-expanded={expanded}
                  className="inline-flex items-center gap-1.5 text-left"
                  onClick={(e) => {
                    e.stopPropagation();
                    setOpen(expanded ? null : a.id);
                  }}
                >
                  <ChevronRight
                    className={cn("size-3.5 text-text-muted transition-transform", expanded && "rotate-90")}
                  />
                  {isNotification(a.action) && <Mail className="size-3.5 text-text-muted" aria-label="e-mail" />}
                  <span className="font-mono text-[12px]">{a.action}</span>
                </button>
                <p className="ml-5 text-[12px] text-text-muted">{actionLabel(a.action)}</p>
              </TableCell>
              <TableCell className="text-[12px] text-text-secondary">
                {a.resource_type ? (
                  <>
                    {a.resource_type}
                    <span
                      className="block max-w-[180px] truncate font-mono text-[11px] text-text-muted"
                      title={a.resource_id}
                    >
                      {a.resource_id}
                    </span>
                  </>
                ) : (
                  "—"
                )}
              </TableCell>
              <TableCell className="font-mono text-[12px] text-text-secondary">{a.ip_address || "—"}</TableCell>
              <TableCell>
                <div className="flex flex-wrap gap-1">
                  <StatusBadge status={a.status} />
                  {a.level !== "info" && a.level !== "debug" && <StatusBadge status={a.level} />}
                </div>
              </TableCell>
            </TableRow>
            {expanded && (
              <TableRow className="bg-surface-alt hover:bg-surface-alt!">
                <TableCell colSpan={6}>
                  <dl className="grid gap-x-6 gap-y-2 text-[12px] sm:grid-cols-[140px_1fr]">
                    <dt className="text-text-muted">Entry ID</dt>
                    <dd className="font-mono">{a.id}</dd>
                    <dt className="text-text-muted">User agent</dt>
                    <dd className="break-all">{a.user_agent || "—"}</dd>
                    <dt className="text-text-muted">Details</dt>
                    <dd>
                      <pre className="overflow-x-auto rounded-md border border-border bg-surface p-3 font-mono text-[12px]">
                        {JSON.stringify(a.details, null, 2)}
                      </pre>
                    </dd>
                  </dl>
                </TableCell>
              </TableRow>
            )}
          </Fragment>
        );
      })}
    </>
  );
}
