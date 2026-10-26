import { AlertTriangle, CheckCircle2, Info, Lock, XCircle } from "lucide-react";
import type * as React from "react";
import { cn } from "@/lib/utils";

// DS "Bannières": {x}-soft background, {x} text, radius 8, 10×12, 13px.
const icons = { info: Info, success: CheckCircle2, warning: AlertTriangle, danger: XCircle, neutral: Lock };
const tones = {
  info: "bg-info-soft text-info",
  success: "bg-success-soft text-success",
  warning: "bg-warning-soft text-warning",
  danger: "bg-danger-soft text-danger",
  neutral: "bg-neutral-soft text-neutral",
};

function Banner({
  tone = "info",
  className,
  children,
  ...props
}: React.ComponentProps<"div"> & { tone?: keyof typeof tones }) {
  const Icon = icons[tone];
  return (
    <div
      role={tone === "danger" ? "alert" : "status"}
      className={cn("flex items-start gap-2 rounded-md px-3 py-2.5 text-[13px] leading-5", tones[tone], className)}
      {...props}
    >
      <Icon className="mt-0.5 size-4 shrink-0" aria-hidden />
      <div className="min-w-0 flex-1">{children}</div>
    </div>
  );
}

export { Banner };
