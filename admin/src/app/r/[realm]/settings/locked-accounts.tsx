import { ErrorState } from "@/components/console/error-state";
import { BulkCell, BulkHead } from "@/components/console/bulk";
import { Pagination } from "@/components/console/pagination";
import { Card, CardTitle } from "@/components/ui/card";
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
import { apiPath, loadCached } from "@/lib/api";
import { BULK_ROW } from "@/lib/bulk";
import { formatDateTime, formatRelative } from "@/lib/format";
import type { List, UserSummary } from "@/lib/types";
import { getI18n } from "@/i18n/server";
import { LockedBulk, UnlockButton } from "./locked-bulk";

const LIMIT = 25;

/** The accounts locked by the brute-force policy above them on the page. */
export async function LockedAccounts({
  realm,
  writable,
  offset,
}: {
  realm: string;
  /** user:write */
  writable: boolean;
  offset: number;
}) {
  const list = await loadCached<List<UserSummary>>(
    apiPath(["realms", realm, "users"], { locked: "true", offset, limit: LIMIT }),
  );
  const tr = await getI18n();
  const { t, locale } = tr;
  if (!list.ok) return <ErrorState error={list} />;
  const items = list.data.items;
  const table = (
    <TableContainer>
      <Table>
        <TableHeader>
          <TableRow>
            {writable && <BulkHead />}
            <TableHead>{t("settings.locked.account", "Account")}</TableHead>
            <TableHead>{t("settings.locked.failed", "Failed sign-ins")}</TableHead>
            <TableHead>{t("settings.locked.until", "Locked until")}</TableHead>
            <TableHead>
              <span className="sr-only">{t("columns.actions", "Actions")}</span>
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.length === 0 && (
            <TableEmpty colSpan={writable ? 5 : 4}>{t("settings.locked.empty", "No account is locked.")}</TableEmpty>
          )}
          {items.map((u) => (
            <TableRow key={u.id} className={BULK_ROW}>
              {writable && <BulkCell id={u.id} label={u.username} />}
              <TableCell>
                <p className="font-medium">{u.name || u.username}</p>
                <p className="font-mono text-[12px] text-text-muted">{u.email}</p>
              </TableCell>
              <TableCell className="text-text-secondary">{u.failed_logins}</TableCell>
              <TableCell
                className="whitespace-nowrap text-text-secondary"
                title={u.locked_until ? formatDateTime(u.locked_until, locale) : undefined}
              >
                {u.locked_until ? formatRelative(u.locked_until, undefined, tr) : "—"}
              </TableCell>
              <TableCell className="text-right">
                {writable && <UnlockButton realm={realm} id={u.id} name={u.username} />}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <Pagination
        basePath={`/r/${encodeURIComponent(realm)}/settings`}
        params={{ tab: "security" }}
        offset={offset}
        limit={LIMIT}
        count={items.length}
        total={list.data.total}
      />
    </TableContainer>
  );
  return (
    <Card className="mt-6">
      <CardTitle>{t("settings.locked.title", "Locked accounts")}</CardTitle>
      <p className="mt-1 mb-4 text-[13px] text-text-secondary">
        {t(
          "settings.locked.text",
          "Accounts locked by the brute-force policy. They unlock on their own when the lock ends.",
        )}
      </p>
      {writable ? (
        <LockedBulk realm={realm} page={items.map((u) => u.id)} total={list.data.total}>
          {table}
        </LockedBulk>
      ) : (
        table
      )}
    </Card>
  );
}
