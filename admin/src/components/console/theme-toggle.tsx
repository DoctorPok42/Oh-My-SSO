"use client";

import { Monitor, Moon, Sun } from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/utils";
import { saveTheme, themeClass, type Theme } from "@/lib/theme";

// Light / Dark / System. Applied at once on <html>, remembered for a year in
// a cookie so the server renders the same theme next time.
export function ThemeToggle({ initial }: { initial: Theme }) {
  const [theme, setTheme] = useState<Theme>(initial);
  const choose = (t: Theme) => {
    setTheme(t);
    const html = document.documentElement;
    html.classList.remove("light", "dark");
    const cls = themeClass(t);
    if (cls) html.classList.add(cls);
    saveTheme(t);
  };
  const options = [
    { value: "light" as const, label: "Light", Icon: Sun },
    { value: "dark" as const, label: "Dark", Icon: Moon },
    { value: "system" as const, label: "System", Icon: Monitor },
  ];
  return (
    <div role="radiogroup" aria-label="Theme" className="flex rounded-md border border-border p-0.5">
      {options.map(({ value, label, Icon }) => (
        <button
          key={value}
          type="button"
          role="radio"
          aria-checked={theme === value}
          title={label}
          onClick={() => choose(value)}
          className={cn(
            "grid size-7 place-items-center rounded-sm transition-colors",
            theme === value ? "bg-accent-soft text-accent" : "text-text-muted hover:text-text-primary",
          )}
        >
          <Icon className="size-3.5" aria-hidden />
          <span className="sr-only">{label}</span>
        </button>
      ))}
    </div>
  );
}
