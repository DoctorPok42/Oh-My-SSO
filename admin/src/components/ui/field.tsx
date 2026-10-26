import type * as React from "react";
import { cn } from "@/lib/utils";
import { Label } from "@/components/ui/label";

// One form row: label, control, help text or error (DS: help 12px muted,
// error 12px danger). `htmlFor` ties the label to the control.
function Field({
  label,
  htmlFor,
  hint,
  error,
  optional,
  className,
  children,
}: {
  label: React.ReactNode;
  htmlFor?: string;
  hint?: React.ReactNode;
  error?: string;
  optional?: boolean;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div className={cn("space-y-0", className)}>
      <Label htmlFor={htmlFor}>
        {label}
        {optional && <span className="font-normal text-text-muted">(optional)</span>}
      </Label>
      {children}
      {error ? (
        <p role="alert" className="mt-1.5 text-[12px] text-danger">
          {error}
        </p>
      ) : hint ? (
        <p className="mt-1.5 text-[12px] text-text-muted">{hint}</p>
      ) : null}
    </div>
  );
}

export { Field };
