"use client";

import { LogOut, ShieldCheck, ShieldAlert, User } from "lucide-react";
import { useRef } from "react";
import { useStepUp } from "@/components/console/step-up";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useT } from "@/i18n/client";
import { initials } from "@/lib/format";

// Avatar menu: who is signed in, whether changes are unlocked (step-up),
// their own profile (the account console of the master realm, where the
// language of this console is chosen too), sign out. Sign-out is a POST form
// (see app/auth/logout/route.ts).
export function UserMenu({
  name,
  email,
  role,
  accountUrl,
}: {
  name: string;
  email: string;
  role: string;
  accountUrl: string;
}) {
  const form = useRef<HTMLFormElement>(null);
  const stepUp = useStepUp();
  const { t, locale } = useT();
  const until = stepUp.freshUntil?.toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit" });
  return (
    <>
      <form ref={form} action="/auth/logout" method="post" className="hidden" />
      <DropdownMenu>
        <DropdownMenuTrigger className="grid size-9 place-items-center rounded-full bg-accent-soft text-[13px] font-semibold text-accent outline-none focus-visible:ring-[3px] focus-visible:ring-accent">
          {initials(name)}
          <span className="sr-only">{t("user_menu.label", "Account menu")}</span>
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
              {t("user_menu.unlocked_until", "Changes unlocked until {until}", { until: until ?? "" })}
            </DropdownMenuItem>
          ) : (
            <DropdownMenuItem onSelect={() => stepUp.request("edit")}>
              <ShieldAlert className="text-warning!" />
              {t("user_menu.confirm", "Confirm it's you to make changes")}
            </DropdownMenuItem>
          )}
          <DropdownMenuSeparator />
          <DropdownMenuItem asChild>
            <a href={accountUrl} target="_blank" rel="noopener">
              <User />
              {t("user_menu.account", "My profile")}
            </a>
          </DropdownMenuItem>
          <DropdownMenuItem
            onSelect={() => form.current?.requestSubmit()}
            className="text-danger data-[highlighted]:bg-danger-soft data-[highlighted]:text-danger [&_svg]:text-danger"
          >
            <LogOut />
            {t("user_menu.sign_out", "Sign out")}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </>
  );
}
