import { NavLink } from "@/components/console/nav-link";
import { Logo } from "@/components/console/logo";
import { Notifications } from "@/components/console/notifications";
import { RealmSwitcher } from "@/components/console/realm-switcher";
import { SearchBox } from "@/components/console/search-box";
import { StepUpIndicator } from "@/components/console/step-up-indicator";
import { ThemeToggle } from "@/components/console/theme-toggle";
import { UserMenu } from "@/components/console/user-menu";
import { Badge } from "@/components/ui/badge";
import type { Theme } from "@/lib/theme";
import type { Me, Realm } from "@/lib/types";

// DS header, 60 px: logo · realm switcher · realm badge · search · theme ·
// padlock (step-up) · bell · avatar.
export function Header({
  me,
  realms,
  realm,
  theme,
  canReadAudit,
}: {
  me: Me;
  realms: Realm[];
  realm: string;
  theme: Theme;
  canReadAudit: boolean;
}) {
  const current = realms.find((r) => r.name === realm);
  const role = me.permissions.some((p) => !p.endsWith(":read")) ? "Administrator" : "Auditor (read-only)";
  return (
    <header className="sticky top-0 z-40 border-b border-border bg-surface">
      <div className="mx-auto flex h-[60px] max-w-[1360px] items-center gap-2 px-4 sm:gap-3 sm:px-6">
        <NavLink href={`/r/${encodeURIComponent(realm)}/dashboard`} className="shrink-0 sm:mr-2" aria-label="Dashboard">
          <Logo wordmarkClassName="hidden sm:inline" />
        </NavLink>
        <span className="hidden h-6 w-px bg-border sm:block" aria-hidden />
        <RealmSwitcher realms={realms} current={current} />
        <Badge tone={current?.system ? "neutral" : "accent"} className="hidden font-mono sm:inline-flex">
          Realm: {realm}
        </Badge>
        <div className="ml-auto flex shrink-0 items-center gap-1 sm:gap-2">
          <SearchBox realm={realm} />
          <div className="hidden md:block">
            <ThemeToggle initial={theme} />
          </div>
          <StepUpIndicator />
          <Notifications realm={realm} enabled={canReadAudit} />
          <UserMenu name={me.user.name} email={me.user.email} role={role} />
        </div>
      </div>
    </header>
  );
}
