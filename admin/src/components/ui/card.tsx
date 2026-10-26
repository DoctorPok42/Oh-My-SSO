import type * as React from "react";
import { cn } from "@/lib/utils";

// DS "Carte": surface, border, radius 12, padding 24; title 15px / 600.
function Card({ className, ...props }: React.ComponentProps<"section">) {
  return (
    <section
      data-slot="card"
      className={cn("rounded-xl border border-border bg-surface p-6 shadow-elevation", className)}
      {...props}
    />
  );
}

function CardHeader({ className, ...props }: React.ComponentProps<"div">) {
  return <div className={cn("mb-4 flex items-start justify-between gap-4", className)} {...props} />;
}

function CardTitle({ className, ...props }: React.ComponentProps<"h2">) {
  return <h2 className={cn("text-[15px] font-semibold text-text-primary", className)} {...props} />;
}

function CardDescription({ className, ...props }: React.ComponentProps<"p">) {
  return <p className={cn("mt-1 text-[13px] text-text-secondary", className)} {...props} />;
}

export { Card, CardDescription, CardHeader, CardTitle };
