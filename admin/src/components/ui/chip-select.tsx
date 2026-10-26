"use client";

import { Check } from "lucide-react";
import { cn } from "@/lib/utils";

// DS "Chip multi-sélection" (roles, groups, scopes...): selected = accent
// border and text on accent-soft; not selected = border, text-secondary.
function ChipSelect({
  options,
  value,
  onChange,
  disabled,
  label,
  empty = "Nothing to choose from yet.",
}: {
  options: { id: string; name: string; hint?: string }[];
  value: string[];
  onChange: (next: string[]) => void;
  disabled?: boolean;
  label: string;
  empty?: string;
}) {
  if (options.length === 0) return <p className="text-[13px] text-text-muted">{empty}</p>;
  return (
    <div role="group" aria-label={label} className="flex flex-wrap gap-2">
      {options.map((o) => {
        const on = value.includes(o.id);
        return (
          <button
            key={o.id}
            type="button"
            aria-pressed={on}
            title={o.hint}
            disabled={disabled}
            onClick={() => onChange(on ? value.filter((v) => v !== o.id) : [...value, o.id])}
            className={cn(
              "inline-flex items-center gap-1 rounded-full border px-3 py-1 text-[12px] font-medium transition-colors outline-none focus-visible:ring-[3px] focus-visible:ring-accent-soft disabled:cursor-not-allowed disabled:opacity-60",
              on
                ? "border-accent bg-accent-soft text-accent"
                : "border-border text-text-secondary hover:border-border-strong hover:text-text-primary",
            )}
          >
            {on && <Check className="size-3" strokeWidth={3} />}
            {o.name}
          </button>
        );
      })}
    </div>
  );
}

/** Read-only chips (effective rights, methods...). */
function Chips({ items, empty = "None" }: { items: { id: string; name: string; title?: string }[]; empty?: string }) {
  if (items.length === 0) return <span className="text-[13px] text-text-muted">{empty}</span>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((i) => (
        <span
          key={i.id}
          title={i.title}
          className="inline-flex items-center rounded-full border border-border px-2.5 py-0.5 text-[12px] text-text-secondary"
        >
          {i.name}
        </span>
      ))}
    </div>
  );
}

export { Chips, ChipSelect };
