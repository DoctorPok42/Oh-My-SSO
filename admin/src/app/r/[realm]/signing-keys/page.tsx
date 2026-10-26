import { ErrorState } from "@/components/console/error-state";
import { PageHeader } from "@/components/console/page-header";
import { StatusBadge } from "@/components/console/status-badge";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { CopyField } from "@/components/ui/copy-button";
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
import { apiPath, getMe, load } from "@/lib/api";
import { formatDateTime, formatRelative } from "@/lib/format";
import { KEY_PURPOSE_LABELS } from "@/lib/labels";
import { canWrite } from "@/lib/permissions";
import { PAGES } from "@/lib/pages";
import type { SigningKeys } from "@/lib/types";
import { KeyActions } from "./key-actions";

export const metadata = { title: PAGES.signingKeys.title };

export default async function SigningKeysPage({ params }: { params: Promise<{ realm: string }> }) {
  const { realm } = await params;
  const [me, keys] = await Promise.all([getMe(), load<SigningKeys>(apiPath(["realms", realm, "signing-keys"]))]);
  if (!keys.ok) return <ErrorState error={keys} />;
  const writable = me.ok && canWrite(me.data, "signing_key");
  const sorted = [...keys.data.keys].sort(
    (a, b) => order(a.status) - order(b.status) || b.created_at.localeCompare(a.created_at),
  );

  return (
    <>
      <PageHeader
        {...PAGES.signingKeys}
        actions={
          writable && (
            <KeyActions
              realm={realm}
              hasPendingSaml={keys.data.keys.some((k) => k.purpose === "saml_signing" && k.status === "pending")}
            />
          )
        }
      />
      <div className="mb-4 grid gap-4 md:grid-cols-2">
        <Card className="p-4">
          <p className="mb-2 text-[13px] font-semibold text-text-secondary">JWKS (public keys of OIDC tokens)</p>
          <CopyField value={keys.data.jwks_url} />
        </Card>
        <Card className="p-4">
          <p className="mb-2 text-[13px] font-semibold text-text-secondary">SAML metadata (signing certificate)</p>
          <CopyField value={keys.data.saml_metadata_url} />
        </Card>
      </div>
      <TableContainer>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Key ID</TableHead>
              <TableHead>Algorithm</TableHead>
              <TableHead>Used for</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Created</TableHead>
              <TableHead>Unpublished</TableHead>
              <TableHead>Key manager</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {sorted.length === 0 && <TableEmpty colSpan={7}>No key: this realm cannot sign anything yet.</TableEmpty>}
            {sorted.map((k) => (
              <TableRow key={k.kid}>
                <TableCell className="max-w-[260px] truncate font-mono text-[12px]" title={k.kid}>
                  {k.kid}
                </TableCell>
                <TableCell className="font-mono text-[12px]">{k.algorithm}</TableCell>
                <TableCell>
                  <Badge tone={k.purpose === "envelope_encryption" ? "neutral" : "info"}>
                    {KEY_PURPOSE_LABELS[k.purpose] ?? k.purpose}
                  </Badge>
                </TableCell>
                <TableCell>
                  <StatusBadge status={k.status} label={k.status === "rotating" ? "Rotating out" : undefined} />
                </TableCell>
                <TableCell className="whitespace-nowrap text-text-secondary" title={formatDateTime(k.created_at)}>
                  {formatRelative(k.created_at)}
                </TableCell>
                <TableCell className="whitespace-nowrap text-text-secondary">
                  {k.retired_at
                    ? `retired ${formatRelative(k.retired_at)}`
                    : k.retire_after
                      ? formatRelative(k.retire_after)
                      : "—"}
                </TableCell>
                <TableCell className="font-mono text-[12px] text-text-muted">{k.kms_backend}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </>
  );
}

function order(status: string): number {
  return ["active", "pending", "rotating", "retired"].indexOf(status);
}
