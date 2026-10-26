import { ErrorState } from "@/components/console/error-state";
import { PageHeader } from "@/components/console/page-header";
import { StatusBadge } from "@/components/console/status-badge";
import { Badge } from "@/components/ui/badge";
import { Banner } from "@/components/ui/banner";
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
import { apiPath, load } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { List, Timeout } from "@/lib/types";
import { PAGES } from "@/lib/pages";

export const metadata = { title: PAGES.timeouts.title };

const TARGETS: Record<string, string> = { user: "User", group: "Group", client: "Client" };

// Temporary restrictions on a user, a group or a client. Read-only in this
// version: they are listed, not created here yet.
export default async function TimeoutsPage({ params }: { params: Promise<{ realm: string }> }) {
  const { realm } = await params;
  const list = await load<List<Timeout>>(apiPath(["realms", realm, "timeouts"]));
  return (
    <>
      <PageHeader {...PAGES.timeouts} />
      <Banner tone="info" className="mb-4">
        Read-only for now: timeouts are listed here; creating and removing them from the console comes in a later
        version.
      </Banner>
      {!list.ok ? (
        <ErrorState error={list} />
      ) : (
        <TableContainer>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Target</TableHead>
                <TableHead>Start</TableHead>
                <TableHead>End</TableHead>
                <TableHead>Reason</TableHead>
                <TableHead>Created by</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {list.data.items.length === 0 && <TableEmpty colSpan={6}>No timeout.</TableEmpty>}
              {list.data.items.map((t) => (
                <TableRow key={t.id}>
                  <TableCell>
                    <span className="flex items-center gap-2">
                      <Badge tone="neutral">{TARGETS[t.target_type] ?? t.target_type}</Badge>
                      <span className="font-medium">{t.target.name}</span>
                    </span>
                  </TableCell>
                  <TableCell className="whitespace-nowrap text-text-secondary">{formatDateTime(t.starts_at)}</TableCell>
                  <TableCell className="whitespace-nowrap text-text-secondary">
                    {t.ends_at ? formatDateTime(t.ends_at) : "Indefinite"}
                  </TableCell>
                  <TableCell className="text-text-secondary">{t.reason || "—"}</TableCell>
                  <TableCell className="text-text-secondary">{t.created_by || "—"}</TableCell>
                  <TableCell>
                    <StatusBadge status={t.active ? "active" : "expired"} label={t.active ? "In force" : "Ended"} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </>
  );
}
