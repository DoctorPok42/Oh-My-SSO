import { redirect } from "next/navigation";
import { cache, Suspense } from "react";
import { NavLink } from "@/components/console/nav-link";
import { BulkCell, BulkHead } from "@/components/console/bulk";
import { ErrorState } from "@/components/console/error-state";
import { PageHeader } from "@/components/console/page-header";
import { Pagination } from "@/components/console/pagination";
import { offsetParam } from "@/lib/pagination";
import { SearchForm } from "@/components/console/search-form";
import { ColumnHeads } from "@/components/console/skeletons";
import { ManagedBadge, StatusBadge } from "@/components/console/status-badge";
import { Badge } from "@/components/ui/badge";
import { buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { NativeSelect } from "@/components/ui/native-select";
import { Table, TableBody, TableCell, TableContainer, TableEmpty, TableHeader, TableRow } from "@/components/ui/table";
import { apiPath, getMe, load, loadCached } from "@/lib/api";
import type { ApiResult } from "@/lib/api-error";
import { BULK_ROW } from "@/lib/bulk";
import { formatRelative } from "@/lib/format";
import { firstReadablePage, pageHref } from "@/lib/nav";
import { COLUMNS, PAGES } from "@/lib/pages";
import { can, canWrite, type Resource } from "@/lib/permissions";
import type { Access, ClientScope, List, Me, Permission, Settings, UserDetail, UserSummary } from "@/lib/types";
import { cn } from "@/lib/utils";
import { AccessDrawer, AccessRowActions, NewAccessButton } from "./access-drawer";
import { AccessBulk } from "./access-bulk";
import { UsersBulk } from "./bulk";
import { ImportUsersButton } from "./import-drawer";
import { NewPermissionButton, PermissionDelete } from "./permissions";
import { InviteUserButton, UserDrawer, UserRowActions } from "./user-drawer";
import { m } from "@/i18n";
import { getI18n } from "@/i18n/server";

const LIMIT = 25;
type Tab = "users" | "roles" | "groups" | "permissions";
type Search = {
  tab?: string;
  q?: string;
  status?: string;
  offset?: string;
  new?: string;
  edit?: string;
  import?: string;
};

const parseTab = (tab?: string): Tab => (tab === "roles" || tab === "groups" || tab === "permissions" ? tab : "users");

export async function generateMetadata({ searchParams }: { searchParams: Promise<Search> }) {
  const { tm } = await getI18n();
  return { title: tm(PAGES[parseTab((await searchParams).tab)].title) };
}

// The roles (or groups) list feeds the table and the drawer: React's cache()
// makes it one call per request. https://react.dev/reference/react/cache
const loadAccess = cache((path: string) => loadCached<List<Access>>(path));

// The table arrives with the page (no skeleton around it, see
// navigation-progress.tsx). The drawer loads apart, everything it needs in
// parallel, and opens at the click.
export default async function UsersPage({
  params,
  searchParams,
}: {
  params: Promise<{ realm: string }>;
  searchParams: Promise<Search>;
}) {
  const { realm } = await params;
  const sp = await searchParams;
  const tab = parseTab(sp.tab);
  const base = `/r/${encodeURIComponent(realm)}/users`;
  const me = await getMe();
  // /users opens on the users, which an admin with access:read alone may not
  // see: on to the sub-page they may read, without a refused call to the API.
  if (me.ok && !can(me.data, tab === "users" ? "user" : "access")) {
    const readable = firstReadablePage(me.data, "users");
    if (readable) redirect(pageHref(realm, readable));
  }
  const { t } = await getI18n();

  let content: React.ReactNode;
  if (tab === "users") {
    const offset = offsetParam(sp.offset);
    const status =
      sp.status === "active" || sp.status === "inactive" || sp.status === "suspended" ? sp.status : undefined;
    content = (
      <>
        <Suspense fallback={null}>
          <UserDrawerSlot realm={realm} sp={sp} me={me} />
        </Suspense>
        <SearchForm action={base} className="mb-4 flex flex-wrap items-center gap-2" role="search">
          <Input
            name="q"
            defaultValue={sp.q}
            placeholder={t("users.search_placeholder", "Name, username or e-mail")}
            className="h-9 w-72"
            aria-label={t("search.label", "Search users")}
          />
          <div className="w-44">
            <NativeSelect
              name="status"
              defaultValue={status ?? ""}
              className="h-9"
              aria-label={t("columns.status", "Status")}
            >
              <option value="">{t("users.any_status", "Any status")}</option>
              <option value="active">{t("status.active", "Active")}</option>
              <option value="suspended">{t("status.suspended", "Suspended")}</option>
              <option value="inactive">{t("status.inactive", "Inactive")}</option>
            </NativeSelect>
          </div>
          <button type="submit" className={cn(buttonVariants({ variant: "secondary", size: "sm" }))}>
            {t("common.search", "Search")}
          </button>
          {(sp.q || status) && (
            <NavLink href={base} className="text-[13px] text-accent hover:underline">
              {t("common.clear", "Clear")}
            </NavLink>
          )}
        </SearchForm>
        <UsersTable realm={realm} base={base} q={sp.q} status={status} offset={offset} me={me} />
      </>
    );
  } else if (tab === "roles" || tab === "groups") {
    const writable = me.ok && canWrite(me.data, "access");
    content = (
      <>
        <AccessTab realm={realm} kind={tab} writable={writable} />
        <Suspense fallback={null}>
          <AccessDrawerSlot realm={realm} kind={tab} sp={sp} me={me} writable={writable} />
        </Suspense>
      </>
    );
  } else {
    content = <PermissionsTab realm={realm} writable={me.ok && canWrite(me.data, "access")} />;
  }

  let action: React.ReactNode = null;
  if (tab === "users" && me.ok && canWrite(me.data, "user"))
    action = (
      <>
        <ImportUsersButton realm={realm} opened={sp.import} />
        <InviteUserButton />
      </>
    );
  if ((tab === "roles" || tab === "groups") && me.ok && canWrite(me.data, "access"))
    action = <NewAccessButton kind={tab} />;
  if (tab === "permissions" && me.ok && canWrite(me.data, "access")) action = <NewPermissionButton realm={realm} />;

  return (
    <>
      <PageHeader {...PAGES[tab]} actions={action} />
      {content}
    </>
  );
}

/** The user drawer: the user, the groups and roles offered, the e-mail setting, in parallel. */
async function UserDrawerSlot({ realm, sp, me }: { realm: string; sp: Search; me: ApiResult<Me> }) {
  const path = (...s: string[]) => apiPath(["realms", realm, ...s]);
  const open = !!sp.new || !!sp.edit;
  const may = (r: Resource) => open && me.ok && can(me.data, r);
  const [detail, roles, groups, settings] = await Promise.all([
    sp.edit ? load<UserDetail>(path("users", sp.edit)) : null,
    may("access") ? loadCached<List<Access>>(path("roles")) : null,
    may("access") ? loadCached<List<Access>>(path("groups")) : null,
    may("settings") ? load<Settings>(path("settings")) : null,
  ]);
  return (
    <>
      {detail && !detail.ok && (
        <div className="mb-4">
          <ErrorState error={detail} />
        </div>
      )}
      <UserDrawer
        realm={realm}
        mode={sp.new ? "create" : detail?.ok ? "edit" : null}
        user={detail?.ok ? detail.data : null}
        writable={me.ok && canWrite(me.data, "user")}
        roles={roles?.ok ? roles.data.items : []}
        groups={groups?.ok ? groups.data.items : []}
        readAccess={me.ok && can(me.data, "access")}
        emailEnabled={!!settings?.ok && settings.data.email_enabled}
        // Not on yourself: the Admin API refuses it (you would lose the console).
        canSuspend={me.ok && canWrite(me.data, "timeout") && !(detail?.ok && detail.data.id === me.data.user.id)}
      />
    </>
  );
}

/** The role / group drawer: the item (from the list), the choices, and a group's members. */
async function AccessDrawerSlot({
  realm,
  kind,
  sp,
  me,
  writable,
}: {
  realm: string;
  kind: "roles" | "groups";
  sp: Search;
  me: ApiResult<Me>;
  writable: boolean;
}) {
  const path = (...s: string[]) => apiPath(["realms", realm, ...s]);
  const open = !!sp.new || !!sp.edit;
  const [list, permissions, scopes] = await Promise.all([
    sp.edit ? loadAccess(path(kind)) : null,
    open ? loadCached<List<Permission>>(path("permissions")) : null,
    open && me.ok && can(me.data, "client_scope") ? loadCached<List<ClientScope>>(path("client-scopes")) : null,
  ]);
  const editing = sp.edit && list?.ok ? list.data.items.find((i) => i.id === sp.edit) : undefined;
  const members =
    kind === "groups" && editing
      ? await load<List<UserSummary>>(apiPath(["realms", realm, "groups", editing.id, "members"], { limit: 50 }))
      : null;
  return (
    <AccessDrawer
      realm={realm}
      kind={kind}
      mode={sp.new ? "create" : editing ? "edit" : null}
      item={editing ?? null}
      permissions={permissions?.ok ? permissions.data.items : []}
      scopes={scopes?.ok ? scopes.data.items : []}
      members={members?.ok ? members.data.items : null}
      writable={writable}
      canAddMembers={me.ok && canWrite(me.data, "user")}
      // Not "admins" of master: the Admin API refuses it (the console would be lost).
      canSuspend={me.ok && canWrite(me.data, "timeout") && !(realm === "master" && editing?.name === "admins")}
    />
  );
}

async function UsersTable({
  realm,
  base,
  q,
  status,
  offset,
  me,
}: {
  realm: string;
  base: string;
  q: string | undefined;
  status: string | undefined;
  offset: number;
  me: ApiResult<Me>;
}) {
  const path = (...s: string[]) => apiPath(["realms", realm, ...s]);
  const write = me.ok && canWrite(me.data, "user");
  const revoke = me.ok && canWrite(me.data, "session");
  const bulk = write || revoke;
  const may = (r: Resource) => bulk && me.ok && can(me.data, r);
  const [list, roles, groups, settings] = await Promise.all([
    loadCached<List<UserSummary>>(apiPath(["realms", realm, "users"], { q, status, offset, limit: LIMIT })),
    may("access") ? loadCached<List<Access>>(path("roles")) : null,
    may("access") ? loadCached<List<Access>>(path("groups")) : null,
    may("settings") ? loadCached<Settings>(path("settings")) : null,
  ]);
  if (!list.ok) return <ErrorState error={list} />;
  const items = list.data.items;
  const tr = await getI18n();
  const { t } = tr;
  // In the master realm your own account is left out: the API refuses it.
  const ownId = realm === "master" && me.ok ? me.data.user.id : undefined;
  const refs = (l: ApiResult<List<Access>> | null) => (l?.ok ? l.data.items.map(({ id, name }) => ({ id, name })) : []);
  const table = (
    <TableContainer>
      <Table>
        <TableHeader>
          <TableRow>
            {bulk && <BulkHead />}
            <ColumnHeads columns={COLUMNS.users} />
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.length === 0 && (
            <TableEmpty colSpan={bulk ? 8 : 7}>
              {q || status ? t("users.no_match", "No user matches.") : t("users.empty", "No user yet: invite one.")}
            </TableEmpty>
          )}
          {items.map((u) => (
            <TableRow key={u.id} className={BULK_ROW}>
              {bulk && (
                <BulkCell
                  id={u.id}
                  label={u.username}
                  blocked={
                    u.id === ownId
                      ? t("users.own_account", "Your own account cannot be part of a bulk action")
                      : undefined
                  }
                />
              )}
              <TableCell>
                <p className="font-medium">{u.name || u.username}</p>
                <p className="font-mono text-[12px] text-text-muted">{u.username}</p>
              </TableCell>
              <TableCell className="text-text-secondary">{u.email}</TableCell>
              <TableCell>
                <div className="flex max-w-[220px] flex-wrap gap-1">
                  {u.groups.length === 0 && <span className="text-text-muted">—</span>}
                  {u.groups.map((g) => (
                    <Badge key={g.id} tone="neutral">
                      {g.name}
                    </Badge>
                  ))}
                </div>
              </TableCell>
              <TableCell>
                <Badge tone={u.mfa_enrolled ? "success" : "neutral"}>
                  {u.mfa_enrolled ? t("status.enrolled", "Enrolled") : t("chips.none", "None")}
                </Badge>
              </TableCell>
              <TableCell>
                <UserStatus user={u} />
              </TableCell>
              <TableCell className="whitespace-nowrap text-text-secondary">
                {formatRelative(u.last_login_at, undefined, tr)}
              </TableCell>
              <TableCell className="text-right">
                <UserRowActions id={u.id} />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <Pagination
        basePath={base}
        params={{ q, status }}
        offset={offset}
        limit={LIMIT}
        count={items.length}
        total={list.data.total}
      />
    </TableContainer>
  );
  if (!bulk) return table;
  return (
    <UsersBulk
      realm={realm}
      scope={`users:${realm}:${q ?? ""}:${status ?? ""}`}
      filter={{ q, status }}
      page={items.map((u) => u.id).filter((id) => id !== ownId)}
      total={list.data.total}
      ownId={ownId}
      write={write}
      revoke={revoke}
      // Unknown without settings:read: offered, the API skips what it cannot send.
      mail={settings?.ok ? settings.data.email_enabled : true}
      groups={refs(groups)}
      roles={refs(roles)}
    >
      {table}
    </UsersBulk>
  );
}

function UserStatus({ user }: { user: UserSummary }) {
  if (!user.has_password && user.status === "active") return <StatusBadge status="invited" />;
  return (
    <span className="flex flex-wrap gap-1">
      <StatusBadge status={user.status} />
      {user.locked && <StatusBadge status="locked" />}
      {user.must_change_password && <StatusBadge status="reset_required" />}
    </span>
  );
}

async function AccessTab({ realm, kind, writable }: { realm: string; kind: "roles" | "groups"; writable: boolean }) {
  const path = (...s: string[]) => apiPath(["realms", realm, ...s]);
  // The permissions' names, for the table (a reference list: cached).
  const [list, permissions] = await Promise.all([
    loadAccess(path(kind)),
    loadCached<List<Permission>>(path("permissions")),
  ]);
  if (!list.ok) return <ErrorState error={list} />;
  const items = list.data.items;
  const permName = new Map((permissions.ok ? permissions.data.items : []).map((p) => [p.id, p.name]));
  const { t } = await getI18n();
  const label = kind === "roles" ? m("columns.role", "Role") : m("columns.group", "Group");
  // A role managed by the configuration can still be duplicated; a group has nothing else to offer.
  const fixed = (a: Access) => kind === "groups" && a.managed_by === "config";
  const table = (
    <>
      <TableContainer>
        <Table>
          <TableHeader>
            <TableRow>
              {writable && <BulkHead />}
              <ColumnHeads columns={[label, ...COLUMNS.access.slice(1)]} />
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.length === 0 && (
              <TableEmpty colSpan={writable ? 7 : 6}>
                {kind === "roles" ? t("users.no_role", "No roles yet.") : t("users.no_group", "No groups yet.")}
              </TableEmpty>
            )}
            {items.map((a) => (
              <TableRow key={a.id} className={BULK_ROW}>
                {writable && (
                  <BulkCell
                    id={a.id}
                    label={a.name}
                    blocked={
                      fixed(a)
                        ? t("clients.managed_bulk", "Managed by the configuration: not part of bulk actions")
                        : undefined
                    }
                  />
                )}
                <TableCell>
                  <p className="flex items-center gap-2 font-medium">
                    {a.name}
                    <ManagedBadge managedBy={a.managed_by} />
                  </p>
                  {a.description && <p className="text-[12px] text-text-muted">{a.description}</p>}
                </TableCell>
                <TableCell className="text-text-secondary">{a.members}</TableCell>
                <TableCell className="max-w-[320px] text-[12px] text-text-secondary">
                  {a.permission_ids.length === 0
                    ? "—"
                    : a.permission_ids
                        .slice(0, 3)
                        .map((id) => permName.get(id) ?? id)
                        .join(", ") + (a.permission_ids.length > 3 ? ` +${a.permission_ids.length - 3}` : "")}
                </TableCell>
                <TableCell className="text-text-secondary">{a.client_scope_ids.length || "—"}</TableCell>
                <TableCell>
                  <StatusBadge status={a.status} />
                </TableCell>
                <TableCell className="text-right">
                  <AccessRowActions realm={realm} kind={kind} item={a} writable={writable} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </>
  );
  if (!writable) return table;
  return (
    <AccessBulk realm={realm} kind={kind} page={items.filter((a) => !fixed(a)).map((a) => a.id)}>
      {table}
    </AccessBulk>
  );
}

async function PermissionsTab({ realm, writable }: { realm: string; writable: boolean }) {
  const list = await loadCached<List<Permission>>(apiPath(["realms", realm, "permissions"]));
  if (!list.ok) return <ErrorState error={list} />;
  const items = list.data.items;
  const { t } = await getI18n();
  return (
    <TableContainer>
      <Table>
        <TableHeader>
          <TableRow>
            <ColumnHeads columns={COLUMNS.permissions} />
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.length === 0 && <TableEmpty colSpan={4}>{t("users.no_permission", "No permission yet.")}</TableEmpty>}
          {items.map((p) => (
            <TableRow key={p.id}>
              <TableCell className="font-mono text-[13px]">{p.name}</TableCell>
              <TableCell className="text-text-secondary">{p.description || "—"}</TableCell>
              <TableCell>
                <Badge tone={p.system ? "neutral" : "accent"}>
                  {p.system ? t("users.permission.system", "System") : t("users.permission.custom", "Custom")}
                </Badge>
              </TableCell>
              <TableCell className="text-right">
                {writable && !p.system && <PermissionDelete realm={realm} permission={p} />}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}
