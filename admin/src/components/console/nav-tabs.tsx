"use client";

import { NavLink } from "@/components/console/nav-link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";

// DS "Onglets primaires": 16×4, 2px bottom border (accent when active);
// active = text-primary 600, inactive = text-secondary 500.
export function NavTabs({ realm, tabs }: { realm: string; tabs: { slug: string; label: string }[] }) {
  const pathname = usePathname();
  const base = `/r/${encodeURIComponent(realm)}/`;
  return (
    <nav aria-label="Sections" className="border-b border-border bg-surface">
      <div className="mx-auto flex max-w-[1360px] gap-5 overflow-x-auto px-4 [scrollbar-width:none] sm:px-6">
        {tabs.map((t) => {
          const href = base + t.slug;
          const active = pathname === href || pathname.startsWith(href + "/");
          return (
            <NavLink
              key={t.slug}
              href={href}
              aria-current={active ? "page" : undefined}
              className={cn(
                "-mb-px border-b-2 px-1 py-4 text-[14px] whitespace-nowrap transition-colors",
                active
                  ? "border-accent font-semibold text-text-primary"
                  : "border-transparent font-medium text-text-secondary hover:text-text-primary",
              )}
            >
              {t.label}
            </NavLink>
          );
        })}
      </div>
    </nav>
  );
}
