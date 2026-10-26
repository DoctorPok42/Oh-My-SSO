"use client";

import { Check, Copy } from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/utils";

function CopyButton({ value, label = "Copy", className }: { value: string; label?: string; className?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        } catch {
          // clipboard refused (insecure context): the value stays selectable
        }
      }}
      className={cn(
        "inline-flex h-7 shrink-0 items-center gap-1.5 rounded-sm border border-border px-2.5 text-[12px] font-semibold text-text-secondary transition-colors hover:border-border-strong hover:text-text-primary",
        className,
      )}
    >
      {done ? <Check className="size-3.5 text-success" /> : <Copy className="size-3.5" />}
      {done ? "Copied" : label}
    </button>
  );
}

/** A value to copy (URL, ID): mono, selectable, with its Copy button. */
function CopyField({ value, className }: { value: string; className?: string }) {
  return (
    <div
      className={cn("flex items-center gap-2 rounded-sm border border-border bg-surface-alt py-1 pr-1 pl-3", className)}
    >
      <code className="min-w-0 flex-1 truncate font-mono text-[12px] text-text-secondary" title={value}>
        {value}
      </code>
      <CopyButton value={value} />
    </div>
  );
}

export { CopyButton, CopyField };
