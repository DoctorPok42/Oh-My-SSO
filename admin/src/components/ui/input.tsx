import type * as React from "react";
import { cn } from "@/lib/utils";

// DS "Input": 10×12, radius 8, focus = accent border + 3px accent-soft ring,
// error = danger border (aria-invalid), disabled = neutral-soft.
export const fieldClass =
  "w-full rounded-md border border-input-border bg-input-bg px-3 text-[14px] text-text-primary outline-none transition-[border-color,box-shadow] placeholder:text-text-muted focus:border-accent focus:ring-[3px] focus:ring-accent-soft disabled:cursor-not-allowed disabled:bg-neutral-soft disabled:text-text-muted aria-invalid:border-danger read-only:bg-surface-alt";

function Input({ className, ...props }: React.ComponentProps<"input">) {
  return <input data-slot="input" className={cn(fieldClass, "h-10", className)} {...props} />;
}

function Textarea({ className, ...props }: React.ComponentProps<"textarea">) {
  return <textarea data-slot="textarea" className={cn(fieldClass, "min-h-20 py-2.5", className)} {...props} />;
}

export { Input, Textarea };
