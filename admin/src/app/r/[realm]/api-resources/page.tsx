import { cache, Suspense } from "react";
import { ErrorState } from "@/components/console/error-state";
import { PageHeader } from "@/components/console/page-header";
import { ColumnHeads } from "@/components/console/skeletons";
import { Badge } from "@/components/ui/badge";
import { OpenRow } from "@/components/console/drawer";
import { Table, TableBody, TableCell, TableContainer, TableEmpty, TableHeader, TableRow } from "@/components/ui/table";
import { apiPath, getMe, loadCached } from "@/lib/api";
import { COLUMNS, PAGES } from "@/lib/pages";
import { canWrite } from "@/lib/permissions";
import type { ApiResource, ClientScope, List } from "@/lib/types";
import { ApiResourceDrawer, ApiResourceRowActions, NewApiResourceButton } from "./resource-drawer";
import { getI18n } from "@/i18n/server";

export async function generateMetadata() {
  const { tm } = await getI18n();
  return { title: tm(PAGES.apiResources.title) };
}

// The table and the drawer both need the list (React's cache(): one call per
// request).
const loadResources = cache((realm: string) =>
  loadCached<List<ApiResource>>(apiPath(["realms", realm, "api-resources"])),
);

export default async function ApiResourcesPage({
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
      <PageHeader {...PAGES.apiResources} actions={writable && <NewApiResourceButton />} />
      <ResourcesTable realm={realm} writable={writable} />
      <Suspense fallback={null}>
        <DrawerSlot realm={realm} sp={sp} writable={writable} />
      </Suspense>
    </>
  );
}

async function ResourcesTable({ realm, writable }: { realm: string; writable: boolean }) {
  const list = await loadResources(realm);
  if (!list.ok) return <ErrorState error={list} />;
  const items = list.data.items;
  const { t } = await getI18n();
  return (
    <TableContainer>
      <Table>
        <TableHeader>
          <TableRow>
            <ColumnHeads columns={COLUMNS.apiResources} />
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.length === 0 && (
            <TableEmpty colSpan={4}>
              {t(
                "api_resources.empty",
                "No API resource yet. Declare an API so that clients can ask for tokens meant for it.",
              )}
            </TableEmpty>
          )}
          {items.map((r) => (
            <OpenRow id={r.id} key={r.id}>
              <TableCell>
                <p className="font-medium">{r.name}</p>
                {r.description && <p className="text-[12px] text-text-muted">{r.description}</p>}
              </TableCell>
              <TableCell className="font-mono text-[13px]">{r.identifier}</TableCell>
              <TableCell>
                <div className="flex flex-wrap gap-1">
                  {r.scopes.map((s) => (
                    <Badge key={s.id} tone="neutral">
                      {s.name}
                    </Badge>
                  ))}
                </div>
              </TableCell>
              <TableCell className="text-right">
                <ApiResourceRowActions realm={realm} resource={r} writable={writable} />
              </TableCell>
            </OpenRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

async function DrawerSlot({
  realm,
  sp,
  writable,
}: {
  realm: string;
  sp: { new?: string; edit?: string };
  writable: boolean;
}) {
  const open = Boolean(sp.new || sp.edit);
  const [list, scopes] = await Promise.all([
    sp.edit ? loadResources(realm) : null,
    open ? loadCached<List<ClientScope>>(apiPath(["realms", realm, "client-scopes"])) : null,
  ]);
  const editing = sp.edit && list?.ok ? list.data.items.find((r) => r.id === sp.edit) : undefined;
  // Only OIDC scopes go into access tokens.
  const options = scopes?.ok ? scopes.data.items.filter((s) => s.protocol !== "saml2") : [];
  return (
    <ApiResourceDrawer
      realm={realm}
      mode={sp.new ? "create" : editing ? "edit" : null}
      resource={editing ?? null}
      scopes={options}
      writable={writable}
    />
  );
}
