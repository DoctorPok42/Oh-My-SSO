"use client";

import { isMsg, type Msg } from "@/i18n";
import { useT } from "@/i18n/client";
import { cn } from "@/lib/utils";

// DS page title: 22px / 600; subtitle 14px text-secondary; actions on the right.
// title and description may be texts to translate (PAGES, lib/pages.ts).
export function PageHeader({
  title,
  description,
  actions,
  className,
}: {
  title: string | Msg;
  description?: React.ReactNode | Msg;
  actions?: React.ReactNode;
  className?: string;
}) {
  const { tm } = useT();
  return (
    <div className={cn("mb-6 flex flex-wrap items-start justify-between gap-4", className)}>
      <div className="min-w-0">
        <h1 className="text-[22px] font-semibold">{isMsg(title) ? tm(title) : title}</h1>
        {description && (
          <p className="mt-1 text-[14px] text-text-secondary">{isMsg(description) ? tm(description) : description}</p>
        )}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}
