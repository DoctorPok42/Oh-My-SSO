import { NavLink } from "@/components/console/nav-link";
import { ErrorState } from "@/components/console/error-state";
import { PageHeader } from "@/components/console/page-header";
import { StatusBadge } from "@/components/console/status-badge";
import { Badge } from "@/components/ui/badge";
import { Banner } from "@/components/ui/banner";
import { Table, TableBody, TableCell, TableContainer, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { apiPath, getMe, load } from "@/lib/api";
import { formatDate } from "@/lib/format";
import { canWrite } from "@/lib/permissions";
import type { List, Realm } from "@/lib/types";
import { PAGES } from "@/lib/pages";
import { NewRealmButton, RealmRowActions } from "./realm-dialogs";

export const metadata = { title: PAGES.realms.title };

// Every realm of the instance (not only the one in the URL). Realms are never
// deleted from the console: disabling keeps users, keys and the audit trail.
export default async function RealmsPage() {
  const [me, list] = await Promise.all([getMe(), load<List<Realm>>(apiPath(["realms"]))]);
  if (!list.ok) return <ErrorState error={list} />;
  const writable = me.ok && canWrite(me.data, "realm");
  return (
    <>
      <PageHeader {...PAGES.realms} actions={writable && <NewRealmButton />} />
      <Banner tone="neutral" className="mb-4">
        The master realm holds the administrators of this console. It cannot be disabled, and no application of your
        organization should use it.
      </Banner>
      <TableContainer>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Display name</TableHead>
              <TableHead>Name</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Created</TableHead>
              <TableHead>
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.data.items.map((r) => (
              <TableRow key={r.id}>
                <TableCell>
                  <NavLink
                    href={`/r/${encodeURIComponent(r.name)}/dashboard`}
                    className="flex items-center gap-2 font-medium hover:underline"
                  >
                    {r.display_name}
                    {r.system && <Badge tone="neutral">System</Badge>}
                  </NavLink>
                </TableCell>
                <TableCell className="font-mono text-[12px] text-text-secondary">{r.name}</TableCell>
                <TableCell>
                  <StatusBadge status={r.status} label={r.status === "active" ? "Active" : "Disabled"} />
                </TableCell>
                <TableCell className="text-text-secondary">{formatDate(r.created_at)}</TableCell>
                <TableCell className="text-right">
                  <RealmRowActions realm={r} writable={writable} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </>
  );
}
