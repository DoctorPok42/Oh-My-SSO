import { cache, Suspense } from "react";
import { NavLink } from "@/components/console/nav-link";
import { ErrorState } from "@/components/console/error-state";
import { PageHeader } from "@/components/console/page-header";
import { offsetParam, Pagination } from "@/components/console/pagination";
import { SearchForm } from "@/components/console/search-form";
import { TableSkeleton } from "@/components/console/skeletons";
import { ManagedBadge, StatusBadge } from "@/components/console/status-badge";
import { Badge } from "@/components/ui/badge";
import { buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { NativeSelect } from "@/components/ui/native-select";
import { SegmentedLinks } from "@/components/ui/segmented";
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableEmpty,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { apiPath, getMe, load, loadCached } from "@/lib/api";
import type { ApiResult } from "@/lib/api-error";
import { formatRelative } from "@/lib/format";
import { COLUMNS, PAGES } from "@/lib/pages";
import { can, canWrite, type Resource } from "@/lib/permissions";
import type { Access, ClientScope, List, Me, Permission, Settings, UserDetail, UserSummary } from "@/lib/types";
import { cn } from "@/lib/utils";
import { AccessDrawer, AccessRowActions, NewAccessButton } from "./access-drawer";
import { NewPermissionButton, PermissionDelete } from "./permissions";
import { InviteUserButton, UserDrawer, UserRowActions } from "./user-drawer";

export const metadata = { title: PAGES.users.title };

const LIMIT = 25;
type Tab = "users" | "roles" | "groups" | "permissions";
type Search = { tab?: string; q?: string; status?: string; offset?: string; new?: string; edit?: string };

// The roles (or groups) list feeds the table and the drawer: React's cache()
// makes it one call per request. https://react.dev/reference/react/cache
const loadAccess = cache((path: string) => load<List<Access>>(path));

// The title, the sub-tabs and the search show at once. Each table loads on
// its own (React Suspense) under a `key` made of what it shows: a new search,
// page or sub-tab = a new key = only the table shows a skeleton. The drawer
// loads apart, everything it needs in parallel, and opens at the click.
export default async function UsersPage({
  params,
  searchParams,
}: {
  params: Promise<{ realm: string }>;
  searchParams: Promise<Search>;
}) {
  const { realm } = await params;
  const sp = await searchParams;
  const tab: Tab = sp.tab === "roles" || sp.tab === "groups" || sp.tab === "permissions" ? sp.tab : "users";
  const base = `/r/${encodeURIComponent(realm)}/users`;
  const me = await getMe();
  const readAccess = me.ok && can(me.data, "access");

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
            placeholder="Name, username or e-mail"
            className="h-9 w-72"
            aria-label="Search users"
          />
          <div className="w-44">
            <NativeSelect name="status" defaultValue={status ?? ""} className="h-9" aria-label="Status">
              <option value="">Any status</option>
              <option value="active">Active</option>
              <option value="suspended">Suspended</option>
              <option value="inactive">Inactive</option>
            </NativeSelect>
          </div>
          <button type="submit" className={cn(buttonVariants({ variant: "secondary", size: "sm" }))}>
            Search
          </button>
          {(sp.q || status) && (
            <NavLink href={base} className="text-[13px] text-accent hover:underline">
              Clear
            </NavLink>
          )}
        </SearchForm>
        <Suspense key={`${sp.q}|${status}|${offset}`} fallback={<TableSkeleton columns={COLUMNS.users} rows={8} />}>
          <UsersTable realm={realm} base={base} q={sp.q} status={status} offset={offset} />
        </Suspense>
      </>
    );
  } else if (tab === "roles" || tab === "groups") {
    const writable = me.ok && canWrite(me.data, "access");
    const columns = [tab === "roles" ? "Role" : "Group", ...COLUMNS.access.slice(1)];
    content = (
      <>
        <Suspense key={tab} fallback={<TableSkeleton columns={columns} />}>
          <AccessTab realm={realm} kind={tab} writable={writable} />
        </Suspense>
        <Suspense fallback={null}>
          <AccessDrawerSlot realm={realm} kind={tab} sp={sp} me={me} writable={writable} />
        </Suspense>
      </>
    );
  } else {
    content = (
      <Suspense key={tab} fallback={<TableSkeleton columns={COLUMNS.permissions} />}>
        <PermissionsTab realm={realm} writable={me.ok && canWrite(me.data, "access")} />
      </Suspense>
    );
  }

  const tabs = [
    { href: base, label: "Users", active: tab === "users" },
    ...(readAccess
      ? [
          { href: `${base}?tab=roles`, label: "Roles", active: tab === "roles" },
          { href: `${base}?tab=groups`, label: "Groups", active: tab === "groups" },
          { href: `${base}?tab=permissions`, label: "Permissions", active: tab === "permissions" },
        ]
      : []),
  ];
  let action: React.ReactNode = null;
  if (tab === "users" && me.ok && canWrite(me.data, "user")) action = <InviteUserButton />;
  if ((tab === "roles" || tab === "groups") && me.ok && canWrite(me.data, "access"))
    action = <NewAccessButton kind={tab} />;
  if (tab === "permissions" && me.ok && canWrite(me.data, "access")) action = <NewPermissionButton realm={realm} />;

  return (
    <>
      <PageHeader {...PAGES.users} />
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <SegmentedLinks label="Users and access" items={tabs} />
        {action}
      </div>
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
}: {
  realm: string;
  base: string;
  q: string | undefined;
  status: string | undefined;
  offset: number;
}) {
  const list = await load<List<UserSummary>>(apiPath(["realms", realm, "users"], { q, status, offset, limit: LIMIT }));
  if (!list.ok) return <ErrorState error={list} />;
  const items = list.data.items;
  return (
    <TableContainer>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>Email</TableHead>
            <TableHead>Groups</TableHead>
            <TableHead>MFA</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Last login</TableHead>
            <TableHead>
              <span className="sr-only">Actions</span>
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.length === 0 && (
            <TableEmpty colSpan={7}>{q || status ? "No user matches." : "No user yet: invite one."}</TableEmpty>
          )}
          {items.map((u) => (
            <TableRow key={u.id}>
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
                <Badge tone={u.mfa_enrolled ? "success" : "neutral"}>{u.mfa_enrolled ? "Enrolled" : "None"}</Badge>
              </TableCell>
              <TableCell>
                <UserStatus user={u} />
              </TableCell>
              <TableCell className="whitespace-nowrap text-text-secondary">{formatRelative(u.last_login_at)}</TableCell>
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
}

function UserStatus({ user }: { user: UserSummary }) {
  if (!user.has_password && user.status === "active") return <StatusBadge status="invited" label="Invited" />;
  return (
    <span className="flex flex-wrap gap-1">
      <StatusBadge status={user.status} />
      {user.locked && <StatusBadge status="locked" label="Locked" />}
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
  const label = kind === "roles" ? "Role" : "Group";
  return (
    <>
      <TableContainer>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{label}</TableHead>
              <TableHead>Members</TableHead>
              <TableHead>Permissions</TableHead>
              <TableHead>Client scopes</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.length === 0 && <TableEmpty colSpan={6}>No {kind} yet.</TableEmpty>}
            {items.map((a) => (
              <TableRow key={a.id}>
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
}

async function PermissionsTab({ realm, writable }: { realm: string; writable: boolean }) {
  const list = await load<List<Permission>>(apiPath(["realms", realm, "permissions"]));
  if (!list.ok) return <ErrorState error={list} />;
  const items = list.data.items;
  return (
    <TableContainer>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Permission</TableHead>
            <TableHead>Description</TableHead>
            <TableHead>Type</TableHead>
            <TableHead>
              <span className="sr-only">Actions</span>
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.length === 0 && <TableEmpty colSpan={4}>No permission yet.</TableEmpty>}
          {items.map((p) => (
            <TableRow key={p.id}>
              <TableCell className="font-mono text-[13px]">{p.name}</TableCell>
              <TableCell className="text-text-secondary">{p.description || "—"}</TableCell>
              <TableCell>
                <Badge tone={p.system ? "neutral" : "accent"}>{p.system ? "System" : "Custom"}</Badge>
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
