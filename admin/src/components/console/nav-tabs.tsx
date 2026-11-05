"use client";

import {
  AppWindow,
  Ban,
  KeyRound,
  ListChecks,
  Lock,
  Mail,
  Monitor,
  Settings2,
  ShieldCheck,
  Timer,
  User,
  Users,
  type LucideIcon,
} from "lucide-react";
import { usePathname, useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { NavLink } from "@/components/console/nav-link";
import { Badge } from "@/components/ui/badge";
import { useT } from "@/i18n/client";
import { activeNav, type NavIcon } from "@/lib/nav";
import { cn } from "@/lib/utils";

// The icons the rest of the console already uses for the same things (Ban:
// "Suspend…", Monitor: devices, KeyRound: keys, Settings2: "Manage realms").
const ICONS: Record<NavIcon, LucideIcon> = {
  clients: AppWindow,
  scopes: ListChecks,
  sessions: Monitor,
  timeouts: Ban,
  users: User,
  roles: ShieldCheck,
  groups: Users,
  permissions: KeyRound,
  general: Settings2,
  security: Lock,
  sessionPolicy: Timer,
  email: Mail,
};

/** A section of lib/nav.ts, readable by this admin and translated (ConsoleLayout). */
export type NavTabsSection = {
  id: string;
  label: string;
  pages: { slug: string; tab?: string; href: string; label: string; icon?: NavIcon }[];
};

/** True once the header has scrolled away: the sentinel sits right under it. */
function useHeaderGone() {
  const sentinel = useRef<HTMLDivElement>(null);
  const [gone, setGone] = useState(false);
  useEffect(() => {
    if (!sentinel.current) return;
    const observer = new IntersectionObserver(([entry]) => setGone(!entry!.isIntersecting));
    observer.observe(sentinel.current);
    return () => observer.disconnect();
  }, []);
  return { sentinel, gone };
}

// The console's two menus. Primary tabs: 14px, 2px bottom border, accent when
// active. Under them, the pages of the active section: 13px with an icon, the
// active one in text-primary so that the two levels read apart. The second
// menu shows even with a single page (the admin may read only that one).
// Once the header is gone, its realm badge shows here: acting on the wrong
// realm is the costly mistake, so the realm stays in view.
export function NavTabs({
  sections,
  realm,
  realmSystem,
}: {
  sections: NavTabsSection[];
  realm: string;
  realmSystem?: boolean;
}) {
  const { t } = useT();
  const { sentinel, gone } = useHeaderGone();
  const slug = usePathname().split("/")[3] ?? "";
  const tab = useSearchParams().get("tab");
  const { section, page } = activeNav(sections, slug, tab);
  const subPages = section?.pages.filter((p) => p.icon) ?? [];
  return (
    <>
      <div ref={sentinel} className="-mb-px h-px" aria-hidden />
      {/* Both menus stick to the top of the window as one block (the header
          scrolls away): no need to know the height of the first to place the second. */}
      <div className="sticky top-0 z-30 bg-surface">
        <nav aria-label={t("tabs.label", "Sections")} className="border-b border-border bg-surface">
          <div className="mx-auto flex max-w-[1360px] items-center gap-4 px-4 sm:px-6">
            <div className="flex min-w-0 flex-1 gap-6 overflow-x-auto [scrollbar-width:none]">
              {sections.map((s) => {
                const active = s.id === section?.id;
                return (
                  <NavLink
                    key={s.id}
                    href={s.pages[0]!.href}
                    aria-current={active ? "true" : undefined}
                    className={cn(
                      "-mb-px border-b-2 py-3.5 text-[14px] whitespace-nowrap transition-colors",
                      active
                        ? "border-accent font-semibold text-accent"
                        : "border-transparent font-medium text-text-secondary hover:text-text-primary",
                    )}
                  >
                    {s.label}
                  </NavLink>
                );
              })}
            </div>
            {gone && (
              <Badge tone={realmSystem ? "neutral" : "accent"} className="max-w-40 font-mono" title={realm}>
                <span className="truncate">{t("header.realm", "Realm: {realm}", { realm })}</span>
              </Badge>
            )}
          </div>
        </nav>
        {subPages.length > 0 && (
          <nav aria-label={t("tabs.sub_label", "Sub-sections")} className="border-b border-border bg-surface">
            <div className="mx-auto flex max-w-[1360px] gap-7 overflow-x-auto px-4 [scrollbar-width:none] sm:px-6">
              {subPages.map((p) => {
                const active = p === page;
                const Icon = ICONS[p.icon!];
                return (
                  <NavLink
                    key={p.href}
                    href={p.href}
                    aria-current={active ? "page" : undefined}
                    className={cn(
                      "-mb-px inline-flex items-center gap-1.5 border-b-2 py-[11px] text-[13px] whitespace-nowrap transition-colors",
                      active
                        ? "border-text-primary font-semibold text-text-primary"
                        : "border-transparent font-medium text-text-secondary hover:text-text-primary",
                    )}
                  >
                    <Icon className="size-3.5 shrink-0" aria-hidden />
                    {p.label}
                  </NavLink>
                );
              })}
            </div>
          </nav>
        )}
      </div>
    </>
  );
}
