"use client";

import { useState } from "react";
import { BulkCell, BulkHead, BulkProvider, BulkSummary, useBulkLimit } from "@/components/console/bulk";
import { useAction } from "@/components/console/use-action";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Textarea } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableContainer, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useT } from "@/i18n/client";
import { BULK_ROW, parseIdentifiers, type BulkResult } from "@/lib/bulk";
import type { UserSummary } from "@/lib/types";
import { addGroupMembers, bulkUsers } from "./actions";

/**
 * The members of a group, with "Remove from group" on a selection (user:write,
 * like adding them). Your own account is skipped by the API in the master
 * realm, as in every bulk action.
 */
export function GroupMembers({ realm, groupId, members }: { realm: string; groupId: string; members: UserSummary[] }) {
  const { t, tn } = useT();
  return (
    <BulkProvider
      scope={`group-members:${realm}:${groupId}`}
      realm={realm}
      page={members.map((m) => m.id)}
      total={members.length}
      countLabel={(n) => tn("bulk.members.selected", n, "{count} member selected", "{count} members selected")}
      doneLabel={(n) => tn("bulk.members.done", n, "{count} member removed", "{count} members removed")}
      actions={[
        {
          id: "remove_member",
          label: t("bulk.members.remove", "Remove from group"),
          danger: true,
          title: (n) =>
            tn(
              "bulk.members.remove_title",
              n,
              "Remove {count} member from this group?",
              "Remove {count} members from this group?",
            ),
          description: t(
            "bulk.members.remove_text",
            "They lose what only this group grants them. Their accounts stay as they are.",
          ),
          run: (ids) => bulkUsers(realm, { action: "remove_group", ids, group_id: groupId }),
        },
      ]}
    >
      <TableContainer>
        <Table>
          <TableHeader>
            <TableRow>
              <BulkHead />
              <TableHead>{t("columns.name", "Name")}</TableHead>
              <TableHead>{t("columns.email", "Email")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {members.map((m) => (
              <TableRow key={m.id} className={BULK_ROW}>
                <BulkCell id={m.id} label={m.name || m.username} />
                <TableCell className="font-medium">{m.name || m.username}</TableCell>
                <TableCell className="text-text-muted">{m.email}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </BulkProvider>
  );
}

/** A pasted list of usernames or e-mails, added to the group. */
export function AddGroupMembers({ realm, groupId }: { realm: string; groupId: string }) {
  const { t, tn } = useT();
  const limit = useBulkLimit();
  const { run, pending } = useAction();
  const [text, setText] = useState("");
  const [result, setResult] = useState<BulkResult | null>(null);
  const names = parseIdentifiers(text);
  const tooMany = names.length > limit;
  return (
    <div className="mt-4 space-y-2">
      <Field
        label={t("access.add_members", "Add members")}
        htmlFor="group-members"
        hint={t("access.add_members_hint", "Usernames or e-mails, separated by spaces, commas or new lines.")}
      >
        <Textarea
          id="group-members"
          value={text}
          rows={3}
          className="font-mono text-[13px]"
          onChange={(e) => {
            setText(e.target.value);
            setResult(null);
          }}
        />
      </Field>
      {tooMany && (
        <p className="text-[12px] text-danger">
          {t("access.add_members_limit", "{limit} people at most at a time.", { limit })}
        </p>
      )}
      {result && (
        <BulkSummary
          realm={realm}
          result={result}
          doneLabel={(n) => tn("access.members_added", n, "{count} member added", "{count} members added")}
          onDismiss={() => setResult(null)}
        />
      )}
      <Button
        variant="secondary"
        size="sm"
        loading={pending}
        disabled={pending || names.length === 0 || tooMany}
        onClick={async () => {
          const r = await run(() => addGroupMembers(realm, groupId, names), { intent: `edit=${groupId}` });
          if (!r.ok) return;
          setResult(r.data);
          setText("");
        }}
      >
        {names.length > 0
          ? tn("access.add_count", names.length, "Add {count} person", "Add {count} people")
          : t("access.add_members", "Add members")}
      </Button>
    </div>
  );
}
