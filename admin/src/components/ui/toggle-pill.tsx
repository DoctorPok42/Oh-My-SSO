"use client";

import { cn } from "@/lib/utils";

// DS "Toggle pill (booléen)": on = accent-soft / accent, off = neutral-soft /
// neutral. A switch for screen readers (role="switch", aria-checked).
function TogglePill({
  checked,
  onCheckedChange,
  onLabel = "On",
  offLabel = "Off",
  disabled,
  label,
  className,
}: {
  checked: boolean;
  onCheckedChange?: (v: boolean) => void;
  onLabel?: string;
  offLabel?: string;
  disabled?: boolean;
  /** Accessible name when no visible label points at it. */
  label?: string;
  className?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onCheckedChange?.(!checked)}
      className={cn(
        "inline-flex h-6 min-w-12 items-center justify-center rounded-full px-2.5 text-[11px] font-semibold transition-colors outline-none focus-visible:ring-[3px] focus-visible:ring-accent-soft disabled:cursor-not-allowed disabled:opacity-60",
        checked ? "bg-accent-soft text-accent" : "bg-neutral-soft text-neutral",
        onCheckedChange && !disabled ? "cursor-pointer" : "cursor-default",
        className,
      )}
    >
      {checked ? onLabel : offLabel}
    </button>
  );
}

export { TogglePill };
