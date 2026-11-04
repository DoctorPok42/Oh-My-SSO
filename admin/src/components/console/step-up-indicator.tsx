"use client";

import { Lock, LockOpen } from "lucide-react";
import { useStepUp } from "@/components/console/step-up";
import { Tooltip } from "@/components/ui/tooltip";
import { useT } from "@/i18n/client";
import { cn } from "@/lib/utils";

// Header padlock: open (green) while changes are unlocked, closed otherwise;
// a click on the closed one offers the step-up.
export function StepUpIndicator() {
  const s = useStepUp();
  const { t, locale } = useT();
  const until = s.freshUntil?.toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit" });
  return (
    <Tooltip
      content={
        s.fresh
          ? t("user_menu.unlocked_until", "Changes unlocked until {until}", { until: until ?? "" })
          : t("step_up.read_only", "Read-only: confirm it's you to make changes")
      }
    >
      <button
        type="button"
        onClick={() => !s.fresh && s.request("edit")}
        className={cn(
          "grid size-9 place-items-center rounded-md outline-none hover:bg-surface-alt focus-visible:ring-[3px] focus-visible:ring-accent-soft",
          s.fresh ? "text-success" : "text-text-muted",
        )}
      >
        {s.fresh ? <LockOpen className="size-[18px]" /> : <Lock className="size-[18px]" />}
        <span className="sr-only">
          {s.fresh ? t("step_up.unlocked", "Changes unlocked") : t("step_up.confirm", "Confirm it's you")}
        </span>
      </button>
    </Tooltip>
  );
}
