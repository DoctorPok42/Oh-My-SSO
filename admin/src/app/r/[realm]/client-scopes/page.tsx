import { cache, Suspense } from "react";
import { ErrorState } from "@/components/console/error-state";
import { PageHeader } from "@/components/console/page-header";
import { ColumnHeads, TableSkeleton } from "@/components/console/skeletons";
import { ProtocolBadge } from "@/components/console/status-badge";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableContainer, TableEmpty, TableHeader, TableRow } from "@/components/ui/table";
import { apiPath, getMe, load } from "@/lib/api";
import { COLUMNS, PAGES } from "@/lib/pages";
import { canWrite } from "@/lib/permissions";
import type { ClientScope, List } from "@/lib/types";
import { NewScopeButton, ScopeDrawer, ScopeRowActions } from "./scope-drawer";
import { getI18n } from "@/i18n/server";

export async function generateMetadata() {
  const { tm } = await getI18n();
  return { title: tm(PAGES.clientScopes.title) };
}

// The table and the drawer both need the list: React's cache() runs the call
// once per request, whoever asks first. https://react.dev/reference/react/cache
const loadScopes = cache((realm: string) => load<List<ClientScope>>(apiPath(["realms", realm, "client-scopes"])));

// The title shows at once; the table and the drawer load on their own
// (React Suspense), the drawer opening at the click (drawer.tsx).
export default async function ClientScopesPage({
  params,
  searchParams,
}: {
  params: Promise<{ realm: string }>;
  searchParams: Promise<{ new?: string; edit?: string }>;
}) {
  const { realm } = await params;
  const sp = await searchParams;
  const me = await getMe();
  const writable = me.ok && canWrite(me.data, "client_scope");

  return (
    <>
      <PageHeader {...PAGES.clientScopes} actions={writable && <NewScopeButton />} />
      <Suspense fallback={<TableSkeleton columns={COLUMNS.clientScopes} />}>
        <ScopesTable realm={realm} writable={writable} />
      </Suspense>
      <Suspense fallback={null}>
        <ScopeDrawerSlot realm={realm} sp={sp} writable={writable} />
      </Suspense>
    </>
  );
}

async function ScopesTable({ realm, writable }: { realm: string; writable: boolean }) {
  const list = await loadScopes(realm);
  if (!list.ok) return <ErrorState error={list} />;
  const items = list.data.items;
  const { t, tn } = await getI18n();
  return (
    <TableContainer>
      <Table>
        <TableHeader>
          <TableRow>
            <ColumnHeads columns={COLUMNS.clientScopes} />
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.length === 0 && <TableEmpty colSpan={6}>{t("scopes.empty", "No client scope yet.")}</TableEmpty>}
          {items.map((s) => (
            <TableRow key={s.id}>
              <TableCell>
                <p className="font-mono text-[13px] font-medium">{s.name}</p>
                {s.description && <p className="text-[12px] text-text-muted">{s.description}</p>}
              </TableCell>
              <TableCell>
                <ProtocolBadge protocol={s.protocol} />
              </TableCell>
              <TableCell>
                <Badge tone={s.is_default ? "accent" : "neutral"}>
                  {s.is_default ? t("scopes.default", "Default") : t("clients.scope.optional", "Optional")}
                </Badge>
              </TableCell>
              <TableCell className="text-text-secondary">{s.claim_mappers.length}</TableCell>
              <TableCell className="text-text-secondary">
                {tn("scopes.clients", s.clients, "{count} client", "{count} clients")}
              </TableCell>
              <TableCell className="text-right">
                <ScopeRowActions realm={realm} scope={s} writable={writable} />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

async function ScopeDrawerSlot({
  realm,
  sp,
  writable,
}: {
  realm: string;
  sp: { new?: string; edit?: string };
  writable: boolean;
}) {
  const list = sp.edit ? await loadScopes(realm) : null;
  const editing = sp.edit && list?.ok ? list.data.items.find((s) => s.id === sp.edit) : undefined;
  return (
    <ScopeDrawer
      realm={realm}
      mode={sp.new ? "create" : editing ? "edit" : null}
      scope={editing ?? null}
      writable={writable}
    />
  );
}
