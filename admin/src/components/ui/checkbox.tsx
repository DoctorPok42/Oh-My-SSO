"use client";

import { Checkbox as CheckboxPrimitive } from "radix-ui";
import { Check } from "lucide-react";
import type * as React from "react";
import { cn } from "@/lib/utils";

function Checkbox({ className, ...props }: React.ComponentProps<typeof CheckboxPrimitive.Root>) {
  return (
    <CheckboxPrimitive.Root
      data-slot="checkbox"
      className={cn(
        "peer size-4 shrink-0 rounded-[4px] border border-input-border bg-input-bg transition-colors outline-none focus-visible:ring-[3px] focus-visible:ring-accent-soft disabled:cursor-not-allowed disabled:opacity-50 data-[state=checked]:border-accent data-[state=checked]:bg-accent data-[state=checked]:text-on-accent",
        className,
      )}
      {...props}
    >
      <CheckboxPrimitive.Indicator className="flex items-center justify-center">
        <Check className="size-3" strokeWidth={3} />
      </CheckboxPrimitive.Indicator>
    </CheckboxPrimitive.Root>
  );
}

/** A checkbox with its label on the right, the whole line clickable. */
function CheckboxField({
  id,
  label,
  hint,
  ...props
}: React.ComponentProps<typeof CheckboxPrimitive.Root> & { id: string; label: React.ReactNode; hint?: string }) {
  return (
    <div className="flex items-start gap-2.5">
      <Checkbox id={id} className="mt-0.5" {...props} />
      <label htmlFor={id} className="cursor-pointer text-[14px] text-text-primary">
        {label}
        {hint && <span className="block text-[12px] text-text-muted">{hint}</span>}
      </label>
    </div>
  );
}

export { Checkbox, CheckboxField };
