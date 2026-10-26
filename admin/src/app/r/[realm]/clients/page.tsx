import { Suspense } from "react";
import { ErrorState } from "@/components/console/error-state";
import { PageHeader } from "@/components/console/page-header";
import { offsetParam, Pagination } from "@/components/console/pagination";
import { TableSkeleton } from "@/components/console/skeletons";
import { ManagedBadge, ProtocolBadge, StatusBadge } from "@/components/console/status-badge";
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
import { formatDate } from "@/lib/format";
import { MFA_METHODS } from "@/lib/labels";
import type { ApiResult } from "@/lib/api-error";
import { COLUMNS, PAGES } from "@/lib/pages";
import { can, canWrite, type Resource } from "@/lib/permissions";
import type { Access, Client, ClientScope, ClientSummary, List, Me } from "@/lib/types";
import { ClientDrawer, ClientRowActions, NewClientButton } from "./client-drawer";

export const metadata = { title: PAGES.clients.title };

const LIMIT = 20;

type Search = { protocol?: string; offset?: string; new?: string; edit?: string };

// The page is cut in three parts that load independently (React Suspense):
//  - the title and the filters: at once (GET /me comes from the console's cache);
//  - the table: its own Suspense whose `key` is the filter and the page
//    number. A new filter or page = a new key = the table alone shows a
//    skeleton while the rest stays in place;
//  - the drawer: the item and the lists it offers, all loaded in parallel.
// https://react.dev/reference/react/Suspense#resetting-suspense-boundaries-on-navigation
export default async function ClientsPage({
  params,
  searchParams,
}: Readonly<{
  params: Promise<{ realm: string }>;
  searchParams: Promise<Search>;
}>) {
  const { realm } = await params;
  const sp = await searchParams;
  const protocol = sp.protocol === "oidc" || sp.protocol === "saml2" ? sp.protocol : undefined;
  const offset = offsetParam(sp.offset);
  const base = `/r/${encodeURIComponent(realm)}/clients`;
  const me = await getMe();
  const writable = me.ok && canWrite(me.data, "client");

  return (
    <>
      <PageHeader {...PAGES.clients} actions={writable && <NewClientButton />} />
      <Suspense fallback={null}>
        <ClientDrawerSlot realm={realm} sp={sp} me={me} writable={writable} />
      </Suspense>
      <div className="mb-4">
        <SegmentedLinks
          label="Protocol"
          items={[
            { href: base, label: "All", active: !protocol },
            { href: `${base}?protocol=oidc`, label: "OIDC", active: protocol === "oidc" },
            { href: `${base}?protocol=saml2`, label: "SAML 2.0", active: protocol === "saml2" },
          ]}
        />
      </div>
      <Suspense key={`${protocol}|${offset}`} fallback={<TableSkeleton columns={COLUMNS.clients} />}>
        <ClientsTable realm={realm} base={base} protocol={protocol} offset={offset} writable={writable} />
      </Suspense>
    </>
  );
}

async function ClientsTable({
  realm,
  base,
  protocol,
  offset,
  writable,
}: {
  realm: string;
  base: string;
  protocol: string | undefined;
  offset: number;
  writable: boolean;
}) {
  const list = await load<List<ClientSummary>>(
    apiPath(["realms", realm, "clients"], { protocol, offset, limit: LIMIT }),
  );
  if (!list.ok) return <ErrorState error={list} />;
  const items = list.data.items;
  return (
    <TableContainer>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>Protocol</TableHead>
            <TableHead>Client / Entity ID</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Created</TableHead>
            <TableHead>
              <span className="sr-only">Actions</span>
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.length === 0 && (
            <TableEmpty colSpan={6}>
              {protocol ? "No client with this protocol." : "No client yet: create one to connect an application."}
            </TableEmpty>
          )}
          {items.map((c) => (
            <TableRow key={c.id}>
              <TableCell>
                <div className="flex items-center gap-2 font-medium">
                  {c.name}
                  <ManagedBadge managedBy={c.managed_by} />
                </div>
              </TableCell>
              <TableCell>
                <ProtocolBadge protocol={c.protocol} />
              </TableCell>
              <TableCell className="max-w-[320px] truncate font-mono text-[12px] text-text-secondary">
                {c.client_id || c.entity_id}
              </TableCell>
              <TableCell>
                <StatusBadge status={c.status} />
              </TableCell>
              <TableCell className="whitespace-nowrap text-text-secondary">{formatDate(c.created_at)}</TableCell>
              <TableCell className="text-right">
                <ClientRowActions realm={realm} client={c} writable={writable} />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <Pagination
        basePath={base}
        params={{ protocol }}
        offset={offset}
        limit={LIMIT}
        count={items.length}
        total={list.data.total}
      />
    </TableContainer>
  );
}

/**
 * The drawer (always mounted: it opens at the click, see components/console/drawer.tsx).
 * The item and the drawer's choices load together, and only what this admin
 * may read (a refused call is an "authorization denied" audit entry).
 */
async function ClientDrawerSlot({
  realm,
  sp,
  me,
  writable,
}: {
  realm: string;
  sp: Search;
  me: ApiResult<Me>;
  writable: boolean;
}) {
  const open = !!sp.new || !!sp.edit;
  const may = (r: Resource) => open && me.ok && can(me.data, r);
  const [detail, roles, groups, scopes] = await Promise.all([
    sp.edit ? load<Client>(apiPath(["realms", realm, "clients", sp.edit])) : null,
    may("access") ? loadCached<List<Access>>(apiPath(["realms", realm, "roles"])) : null,
    may("access") ? loadCached<List<Access>>(apiPath(["realms", realm, "groups"])) : null,
    may("client_scope") ? loadCached<List<ClientScope>>(apiPath(["realms", realm, "client-scopes"])) : null,
  ]);
  return (
    <>
      {detail && !detail.ok && (
        <div className="mb-4">
          <ErrorState error={detail} />
        </div>
      )}
      <ClientDrawer
        realm={realm}
        mode={sp.new ? "create" : detail?.ok ? "edit" : null}
        client={detail?.ok ? detail.data : null}
        writable={writable}
        roles={roles?.ok ? roles.data.items : []}
        groups={groups?.ok ? groups.data.items : []}
        scopes={scopes?.ok ? scopes.data.items : []}
        mfaMethods={MFA_METHODS}
        canReadAccess={me.ok && can(me.data, "access")}
      />
    </>
  );
}
