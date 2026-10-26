"use client";

import { Label as LabelPrimitive } from "radix-ui";
import type * as React from "react";
import { cn } from "@/lib/utils";

// DS "Label de champ": 13px / 600, text-secondary, 6px below.
function Label({ className, ...props }: React.ComponentProps<typeof LabelPrimitive.Root>) {
  return (
    <LabelPrimitive.Root
      data-slot="label"
      className={cn("mb-1.5 flex items-center gap-1.5 text-[13px] font-semibold text-text-secondary", className)}
      {...props}
    />
  );
}

export { Label };
