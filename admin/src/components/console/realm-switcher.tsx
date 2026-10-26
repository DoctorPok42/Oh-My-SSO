"use client";

import { Check, ChevronDown, Settings2 } from "lucide-react";
import { usePathname } from "next/navigation";
import { useNavigate } from "@/components/console/navigation-progress";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import type { Realm } from "@/lib/types";

// The realm being administered, in the header ("Nova Industries ▾"). Picking
// another one keeps the current tab: /r/demo/users -> /r/nova/users.
export function RealmSwitcher({ realms, current }: { realms: Realm[]; current: Realm | undefined }) {
  const router = useNavigate(); // the progress bar shows while the other realm loads
  const pathname = usePathname();
  const tabPath = pathname.split("/").slice(3).join("/") || "dashboard";
  const target = (name: string) => `/r/${encodeURIComponent(name)}/${tabPath === "realms" ? "dashboard" : tabPath}`;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger className="inline-flex max-w-[150px] min-w-0 items-center sm:max-w-[220px] gap-1.5 rounded-md px-2 py-1.5 text-[14px] font-semibold text-text-primary outline-none hover:bg-surface-alt focus-visible:ring-[3px] focus-visible:ring-accent-soft">
        <span className="truncate">{current?.display_name ?? "Choose a realm"}</span>
        <ChevronDown className="size-4 shrink-0 text-text-muted" aria-hidden />
        <span className="sr-only">Switch realm</span>
      </DropdownMenuTrigger>
      <DropdownMenuContent className="w-64">
        <DropdownMenuLabel>Realms</DropdownMenuLabel>
        {realms.map((r) => (
          <DropdownMenuItem key={r.id} onSelect={() => router.push(target(r.name))}>
            <span className="flex size-4 items-center">
              {r.name === current?.name && <Check className="text-accent!" />}
            </span>
            <span className="min-w-0 flex-1">
              <span className="block truncate">{r.display_name}</span>
              <span className="block font-mono text-[11px] text-text-muted">{r.name}</span>
            </span>
            {r.status !== "active" && <span className="text-[11px] text-warning">disabled</span>}
          </DropdownMenuItem>
        ))}
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => router.push(`/r/${encodeURIComponent(current?.name ?? "master")}/realms`)}>
          <Settings2 />
          Manage realms
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
