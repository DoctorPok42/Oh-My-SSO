"use client";

import { Ban } from "lucide-react";
import { NavLink } from "@/components/console/nav-link";
import { buttonVariants } from "@/components/ui/button";
import { useT } from "@/i18n/client";
import type { TimeoutTargetType } from "@/lib/types";
import { cn } from "@/lib/utils";

/**
 * "Suspend…" in the user, group and client drawers: opens the Timeouts
 * page's form with this target already chosen. Shown only to admins who may
 * create timeouts (timeout:write); the Admin API checks again anyway.
 */
export function SuspendLink({
  realm,
  type,
  id,
  name,
  className,
}: {
  realm: string;
  type: TimeoutTargetType;
  id: string;
  name: string;
  className?: string;
}) {
  const { t } = useT();
  const q = new URLSearchParams({ new: "1", target_type: type, target_id: id, target_name: name });
  return (
    <NavLink
      href={`/r/${encodeURIComponent(realm)}/timeouts?${q.toString()}`}
      className={cn(buttonVariants({ variant: "danger", size: "sm" }), className)}
      title={t("suspend.title", "Block sign-ins for a while (timeout)")}
    >
      <Ban className="size-3.5" />
      {t("suspend.label", "Suspend…")}
    </NavLink>
  );
}
