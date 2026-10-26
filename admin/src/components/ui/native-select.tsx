import { ChevronDown } from "lucide-react";
import type * as React from "react";
import { cn } from "@/lib/utils";
import { fieldClass } from "@/components/ui/input";

// A real <select>, styled like the inputs: works in plain forms, with the
// keyboard and screen readers, on every device.
function NativeSelect({ className, children, ...props }: React.ComponentProps<"select">) {
  return (
    <div className="relative">
      <select
        data-slot="native-select"
        className={cn(fieldClass, "h-10 cursor-pointer appearance-none pr-9", className)}
        {...props}
      >
        {children}
      </select>
      <ChevronDown className="pointer-events-none absolute top-1/2 right-3 size-4 -translate-y-1/2 text-text-muted" />
    </div>
  );
}

export { NativeSelect };
