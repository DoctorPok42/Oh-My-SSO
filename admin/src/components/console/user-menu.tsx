"use client";

import { LogOut, ShieldCheck, ShieldAlert } from "lucide-react";
import { useRef } from "react";
import { useStepUp } from "@/components/console/step-up";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { initials } from "@/lib/format";

// Avatar menu: who is signed in, whether changes are unlocked (step-up),
// sign out. Sign-out is a POST form (see app/auth/logout/route.ts).
export function UserMenu({ name, email, role }: { name: string; email: string; role: string }) {
  const form = useRef<HTMLFormElement>(null);
  const stepUp = useStepUp();
  const until = stepUp.freshUntil?.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return (
    <>
      <form ref={form} action="/auth/logout" method="post" className="hidden" />
      <DropdownMenu>
        <DropdownMenuTrigger className="grid size-9 place-items-center rounded-full bg-accent-soft text-[13px] font-semibold text-accent outline-none focus-visible:ring-[3px] focus-visible:ring-accent">
          {initials(name)}
          <span className="sr-only">Account menu</span>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-64">
          <div className="px-3 py-2.5">
            <p className="truncate text-[14px] font-semibold">{name}</p>
            <p className="truncate text-[12px] text-text-muted">{email}</p>
            <p className="mt-1 text-[12px] text-text-secondary">{role}</p>
          </div>
          <DropdownMenuSeparator />
          {stepUp.fresh ? (
            <DropdownMenuItem disabled className="opacity-100!">
              <ShieldCheck className="text-success!" />
              Changes unlocked until {until}
            </DropdownMenuItem>
          ) : (
            <DropdownMenuItem onSelect={() => stepUp.request("edit")}>
              <ShieldAlert className="text-warning!" />
              Confirm it&apos;s you to make changes
            </DropdownMenuItem>
          )}
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => form.current?.requestSubmit()}>
            <LogOut />
            Sign out
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </>
  );
}
