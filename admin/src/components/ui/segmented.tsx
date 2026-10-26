import { NavLink } from "@/components/console/nav-link";
import { cn } from "@/lib/utils";

// DS "Sous-onglets / segmented": 6×14, radius 8; active = accent-soft
// background, accent border and text. As links (filters in the URL) or as
// buttons (a choice inside a form).
const item =
  "inline-flex items-center gap-1.5 rounded-md border px-3.5 py-1.5 text-[13px] font-medium transition-colors outline-none focus-visible:ring-[3px] focus-visible:ring-accent-soft";
const on = "border-accent bg-accent-soft text-accent";
const off = "border-transparent text-text-secondary hover:text-text-primary";

function SegmentedLinks({
  items,
  label,
}: {
  items: { href: string; label: string; active: boolean; count?: number }[];
  label: string;
}) {
  return (
    <nav aria-label={label} className="flex flex-wrap gap-1">
      {items.map((i) => (
        <NavLink
          key={i.href}
          href={i.href}
          aria-current={i.active ? "page" : undefined}
          className={cn(item, i.active ? on : off)}
        >
          {i.label}
          {i.count !== undefined && <span className="text-[11px] opacity-75">{i.count}</span>}
        </NavLink>
      ))}
    </nav>
  );
}

function Segmented<T extends string>({
  options,
  value,
  onChange,
  label,
  disabled,
}: {
  options: { value: T; label: string }[];
  value: T;
  onChange: (v: T) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <div role="radiogroup" aria-label={label} className="flex flex-wrap gap-1">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={o.value === value}
          disabled={disabled}
          onClick={() => onChange(o.value)}
          className={cn(
            item,
            o.value === value ? on : cn(off, "border-border"),
            "disabled:cursor-not-allowed disabled:opacity-60",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export { Segmented, SegmentedLinks };
