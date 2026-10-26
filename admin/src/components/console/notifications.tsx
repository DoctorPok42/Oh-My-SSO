"use client";

import { Bell, Mail } from "lucide-react";
import { NavLink } from "@/components/console/nav-link";
import { useCallback, useEffect, useState } from "react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { formatRelative } from "@/lib/format";
import { actionLabel, isNotification } from "@/lib/labels";
import type { AuditEntry } from "@/lib/types";
import { cn } from "@/lib/utils";
import { recentAlerts } from "@/app/r/[realm]/header-actions";

// The bell: the realm's latest warnings and errors from the audit log
// (GET /audit-logs?level=suspicious,warning,error,critical). Loaded once the
// page is shown, and again each time the menu opens: it never slows a page.
export function Notifications({ realm, enabled }: { realm: string; enabled: boolean }) {
  const [items, setItems] = useState<AuditEntry[] | null>(enabled ? [] : null);
  const auditHref = `/r/${encodeURIComponent(realm)}/audit`;
  const refresh = useCallback(() => {
    if (!enabled) return;
    recentAlerts(realm)
      .then((r) => setItems(r.ok ? r.data.items : []))
      .catch(() => undefined);
  }, [realm, enabled]);
  useEffect(refresh, [refresh]);
  const urgent = (items ?? []).filter((i) => i.level === "error" || i.level === "critical").length;
  return (
    <DropdownMenu onOpenChange={(open) => open && refresh()}>
      <DropdownMenuTrigger className="relative grid size-9 place-items-center rounded-md text-text-secondary outline-none hover:bg-surface-alt hover:text-text-primary focus-visible:ring-[3px] focus-visible:ring-accent-soft">
        <Bell className="size-[18px]" aria-hidden />
        <span className="sr-only">Security notifications</span>
        {items && items.length > 0 && (
          <span
            className={cn(
              "absolute top-1.5 right-1.5 size-2 rounded-full ring-2 ring-surface",
              urgent ? "bg-danger" : "bg-warning",
            )}
          />
        )}
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-80">
        <DropdownMenuLabel>Warnings and errors</DropdownMenuLabel>
        {items === null && <p className="px-3 py-3 text-[13px] text-text-muted">You cannot read the audit log.</p>}
        {items?.length === 0 && <p className="px-3 py-3 text-[13px] text-text-muted">Nothing to report.</p>}
        {items?.map((i) => (
          <DropdownMenuItem key={i.id} asChild>
            <NavLink href={`${auditHref}?action=${encodeURIComponent(i.action)}`} className="items-start">
              {isNotification(i.action) && <Mail className="mt-0.5" />}
              <span className="min-w-0 flex-1">
                <span className="block truncate font-medium">{actionLabel(i.action)}</span>
                <span className="block text-[12px] text-text-muted">
                  {i.actor?.username ?? "system"} · {formatRelative(i.timestamp)}
                </span>
              </span>
              <span
                className={cn(
                  "text-[11px] font-semibold",
                  i.level === "error" || i.level === "critical" ? "text-danger" : "text-warning",
                )}
              >
                {i.level}
              </span>
            </NavLink>
          </DropdownMenuItem>
        ))}
        {items !== null && (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuItem asChild>
              <NavLink href={auditHref}>Open the audit log</NavLink>
            </DropdownMenuItem>
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
