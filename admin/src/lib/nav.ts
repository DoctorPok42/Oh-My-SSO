import { m, type Msg } from "@/i18n";
import { PAGES } from "@/lib/pages";
import { can, type Resource } from "@/lib/permissions";
import type { Me } from "@/lib/types";

// The console's two menus, in one place. Each page names the resource an
// admin must be able to read: a section shows as soon as one of its pages is
// readable, and then with those pages only. This only hides links: the Admin
// API checks every call anyway.

export type NavIcon =
  | "clients"
  | "scopes"
  | "sessions"
  | "timeouts"
  | "users"
  | "roles"
  | "groups"
  | "permissions"
  | "general"
  | "security"
  | "sessionPolicy"
  | "email";

export type NavPage = {
  /** /r/<realm>/<slug>; `tab` adds ?tab=<tab> (no tab: the page's default one). */
  slug: string;
  tab?: string;
  label: Msg;
  resource: Resource;
  /** A page with an icon shows in the second menu. */
  icon?: NavIcon;
};

export type NavSection = { id: string; label: Msg; pages: NavPage[] };

export const NAV: readonly NavSection[] = [
  {
    id: "dashboard",
    label: PAGES.dashboard.title,
    pages: [{ slug: "dashboard", label: PAGES.dashboard.title, resource: "realm" }],
  },
  {
    id: "applications",
    label: m("nav.applications", "Applications"),
    pages: [
      { slug: "clients", label: PAGES.clients.title, resource: "client", icon: "clients" },
      { slug: "client-scopes", label: PAGES.clientScopes.title, resource: "client_scope", icon: "scopes" },
    ],
  },
  {
    id: "access",
    label: m("nav.access", "Access"),
    pages: [
      { slug: "sessions", label: PAGES.sessions.title, resource: "session", icon: "sessions" },
      { slug: "timeouts", label: PAGES.timeouts.title, resource: "timeout", icon: "timeouts" },
    ],
  },
  {
    id: "audit",
    label: PAGES.audit.title,
    pages: [{ slug: "audit", label: PAGES.audit.title, resource: "audit_log" }],
  },
  {
    id: "users",
    label: m("nav.users", "Users & Roles"),
    pages: [
      { slug: "users", label: PAGES.users.title, resource: "user", icon: "users" },
      { slug: "users", tab: "roles", label: PAGES.roles.title, resource: "access", icon: "roles" },
      { slug: "users", tab: "groups", label: PAGES.groups.title, resource: "access", icon: "groups" },
      { slug: "users", tab: "permissions", label: PAGES.permissions.title, resource: "access", icon: "permissions" },
    ],
  },
  {
    id: "signing-keys",
    label: PAGES.signingKeys.title,
    pages: [{ slug: "signing-keys", label: PAGES.signingKeys.title, resource: "signing_key" }],
  },
  {
    id: "mfa",
    label: PAGES.mfa.title,
    pages: [{ slug: "mfa", label: PAGES.mfa.title, resource: "mfa_policy" }],
  },
  {
    id: "settings",
    label: m("nav.settings", "Settings"),
    pages: [
      { slug: "settings", label: PAGES.settingsGeneral.title, resource: "settings", icon: "general" },
      {
        slug: "settings",
        tab: "security",
        label: PAGES.settingsSecurity.title,
        resource: "settings",
        icon: "security",
      },
      {
        slug: "settings",
        tab: "sessions",
        label: PAGES.settingsSessions.title,
        resource: "settings",
        icon: "sessionPolicy",
      },
      { slug: "settings", tab: "email", label: PAGES.settingsEmail.title, resource: "settings", icon: "email" },
    ],
  },
];

/** The sections this admin may see, each with its readable pages only. */
export function readableNav(me: Pick<Me, "permissions">): NavSection[] {
  return NAV.flatMap((section) => {
    const pages = section.pages.filter((p) => can(me, p.resource));
    return pages.length > 0 ? [{ ...section, pages }] : [];
  });
}

/**
 * Where to send an admin who landed on a page they may not read: the first
 * readable page of `sectionId`, or of the console. Undefined when there is
 * none: the page then shows the Admin API's refusal.
 */
export function firstReadablePage(me: Pick<Me, "permissions">, sectionId?: string): NavPage | undefined {
  const sections = readableNav(me);
  const section = sectionId ? sections.find((s) => s.id === sectionId) : sections[0];
  return section?.pages[0];
}

export function pageHref(realm: string, page: Pick<NavPage, "slug" | "tab">): string {
  const path = `/r/${encodeURIComponent(realm)}/${page.slug}`;
  return page.tab ? `${path}?tab=${page.tab}` : path;
}

/** The section and the page of the menus for this URL, among those listed. */
export function activeNav<P extends Pick<NavPage, "slug" | "tab">, S extends { pages: P[] }>(
  sections: S[],
  slug: string,
  tab: string | null,
): { section?: S; page?: P } {
  const section = sections.find((s) => s.pages.some((p) => p.slug === slug));
  const pages = section?.pages.filter((p) => p.slug === slug) ?? [];
  // An unknown ?tab= shows the default tab, here as on the page itself.
  return { section, page: pages.find((p) => p.tab === (tab ?? undefined)) ?? pages[0] };
}
