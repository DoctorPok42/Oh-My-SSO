"use client";

import type { ReactNode } from "react";
import { BulkProvider, type BulkAction, type BulkParams } from "@/components/console/bulk";
import { useT } from "@/i18n/client";
import type { BulkBody } from "@/lib/bulk";
import type { NameRef } from "@/lib/types";
import { bulkSessions } from "../sessions/actions";
import { bulkUsers, matchingUserIds } from "./actions";

/** The actions the bar offers on the users of this page: what the admin may do. */
export function UsersBulk({
  realm,
  scope,
  filter,
  page,
  total,
  ownId,
  write,
  revoke,
  mail,
  groups,
  roles,
  children,
}: {
  realm: string;
  scope: string;
  filter: { q?: string; status?: string };
  page: string[];
  total: number;
  /** Left out of every selection (master realm: your own account). */
  ownId?: string;
  /** user:write */
  write: boolean;
  /** session:revoke */
  revoke: boolean;
  /** E-mail is configured: invitations and forced resets can reach people. */
  mail: boolean;
  /** Empty without access:read. */
  groups: NameRef[];
  roles: NameRef[];
  children: ReactNode;
}) {
  const { t, tn } = useT();
  const users = (action: string, extra: (p: BulkParams) => Partial<BulkBody> = () => ({})) => {
    return (ids: string[], p: BulkParams) => bulkUsers(realm, { action, ids, ...extra(p) });
  };

  const actions: BulkAction[] = [];
  if (write) {
    actions.push(
      {
        id: "suspend",
        label: t("bulk.users.suspend", "Suspend"),
        title: (n) => tn("bulk.users.suspend_title", n, "Suspend {count} user?", "Suspend {count} users?"),
        description: t(
          "bulk.users.suspend_text",
          "Suspended users cannot sign in, and their active sessions end at once.",
        ),
        run: users("suspend"),
      },
      {
        id: "reactivate",
        label: t("bulk.users.reactivate", "Reactivate"),
        title: (n) => tn("bulk.users.reactivate_title", n, "Reactivate {count} user?", "Reactivate {count} users?"),
        description: t("bulk.users.reactivate_text", "These users can sign in again."),
        run: users("reactivate"),
      },
      {
        id: "unlock",
        label: t("bulk.users.unlock", "Unlock"),
        title: (n) => tn("bulk.users.unlock_title", n, "Unlock {count} account?", "Unlock {count} accounts?"),
        description: t("bulk.users.unlock_text", "Clears the failed sign-ins and the lock of these accounts."),
        run: users("unlock"),
      },
    );
  }
  if (revoke) {
    actions.push({
      id: "revoke_sessions",
      label: t("bulk.users.revoke_sessions", "Revoke sessions"),
      title: (n) =>
        tn(
          "bulk.users.revoke_sessions_title",
          n,
          "Sign {count} user out everywhere?",
          "Sign {count} users out everywhere?",
        ),
      description: t(
        "bulk.users.revoke_sessions_text",
        "Every active session of these users ends, and the applications lose their tokens. They have to sign in again.",
      ),
      run: (ids) => bulkSessions(realm, { action: "revoke_users", ids }),
    });
  }
  if (write) {
    if (groups.length > 0) {
      actions.push(
        {
          id: "add_group",
          label: t("bulk.users.add_group", "Add to group"),
          title: (n) =>
            tn("bulk.users.add_group_title", n, "Add {count} user to a group?", "Add {count} users to a group?"),
          description: t("bulk.users.add_group_text", "They get what the group grants, on top of their other groups."),
          picker: { label: t("bulk.users.group", "Group"), options: groups },
          run: users("add_group", (p) => ({ group_id: p.pick })),
        },
        {
          id: "remove_group",
          label: t("bulk.users.remove_group", "Remove from group"),
          overflow: true,
          title: (n) =>
            tn(
              "bulk.users.remove_group_title",
              n,
              "Remove {count} user from a group?",
              "Remove {count} users from a group?",
            ),
          description: t("bulk.users.remove_group_text", "They lose what only this group grants them."),
          picker: { label: t("bulk.users.group", "Group"), options: groups },
          run: users("remove_group", (p) => ({ group_id: p.pick })),
        },
      );
    }
    if (roles.length > 0) {
      actions.push(
        {
          id: "add_role",
          label: t("bulk.users.add_role", "Assign role"),
          overflow: true,
          title: (n) =>
            tn("bulk.users.add_role_title", n, "Assign a role to {count} user?", "Assign a role to {count} users?"),
          description: t("bulk.users.add_role_text", "The role is added to the roles they hold directly."),
          picker: { label: t("bulk.users.role", "Role"), options: roles },
          run: users("add_role", (p) => ({ role_id: p.pick })),
        },
        {
          id: "remove_role",
          label: t("bulk.users.remove_role", "Remove role"),
          overflow: true,
          title: (n) =>
            tn(
              "bulk.users.remove_role_title",
              n,
              "Remove a role from {count} user?",
              "Remove a role from {count} users?",
            ),
          description: t(
            "bulk.users.remove_role_text",
            "Only a role held directly can be removed: one that comes from a group stays.",
          ),
          picker: { label: t("bulk.users.role", "Role"), options: roles },
          run: users("remove_role", (p) => ({ role_id: p.pick })),
        },
      );
    }
    if (mail) {
      actions.push(
        {
          id: "resend_invite",
          label: t("bulk.users.resend_invite", "Resend invitation"),
          overflow: true,
          title: (n) =>
            tn("bulk.users.resend_invite_title", n, "Resend {count} invitation?", "Resend {count} invitations?"),
          description: t(
            "bulk.users.resend_invite_text",
            "Accounts that have not chosen a password get a new link by e-mail; the previous link stops working.",
          ),
          run: users("resend_invite"),
        },
        {
          id: "force_password_reset",
          label: t("bulk.users.force_reset", "Force password reset"),
          overflow: true,
          danger: true,
          title: (n) =>
            tn(
              "bulk.users.force_reset_title",
              n,
              "Force a new password for {count} user?",
              "Force a new password for {count} users?",
            ),
          description: t(
            "bulk.users.force_reset_text",
            "These users are signed out everywhere and get a link by e-mail. Signing in with their password is refused until they choose a new one. Suspended accounts are skipped.",
          ),
          run: users("force_password_reset"),
        },
      );
    }
    actions.push(
      {
        id: "reset_mfa",
        label: t("bulk.users.reset_mfa", "Reset MFA"),
        overflow: true,
        danger: true,
        reason: true,
        title: (n) => tn("bulk.users.reset_mfa_title", n, "Reset MFA of {count} user?", "Reset MFA of {count} users?"),
        description: t(
          "bulk.users.reset_mfa_text",
          "All enrolled factors (authenticator apps, passkeys, backup codes) are removed, and these users are signed out.",
        ),
        run: users("reset_mfa", (p) => ({ reason: p.reason })),
      },
      {
        id: "delete",
        label: t("bulk.users.delete", "Delete"),
        danger: true,
        confirmWord: t("bulk.word_delete", "delete"),
        title: (n) => tn("bulk.users.delete_title", n, "Delete {count} user?", "Delete {count} users?"),
        description: t(
          "bulk.users.delete_text",
          "These accounts, their sessions and their factors are permanently deleted. The audit log keeps their history.",
        ),
        run: users("delete"),
      },
    );
  }

  return (
    <BulkProvider
      scope={scope}
      realm={realm}
      page={page}
      total={total}
      actions={actions}
      countLabel={(n) => tn("bulk.users.selected", n, "{count} user selected", "{count} users selected")}
      doneLabel={(n) => tn("bulk.users.done", n, "{count} user updated", "{count} users updated")}
      matching={(exclude) => matchingUserIds(realm, filter, ownId ? [...exclude, ownId] : exclude)}
    >
      {children}
    </BulkProvider>
  );
}
