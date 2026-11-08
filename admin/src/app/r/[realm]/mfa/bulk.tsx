"use client";

import type { ReactNode } from "react";
import { BulkProvider, type BulkAction } from "@/components/console/bulk";
import { useT } from "@/i18n/client";
import { bulkRoleMfa } from "./actions";

/** One setting of the MFA policy of many roles (mfa_policy:write). */
export function RoleMfaBulk({ realm, page, children }: { realm: string; page: string[]; children: ReactNode }) {
  const { t, tn } = useT();
  const run = (action: string) => (ids: string[]) => bulkRoleMfa(realm, { action, ids });
  const ownRules = t(
    "bulk.mfa.own_rules",
    "A role on the realm default gets its own rules: any method, no grace period. The other settings of a role are kept.",
  );
  const actions: BulkAction[] = [
    {
      id: "require",
      label: t("bulk.mfa.require", "Require MFA"),
      title: (n) => tn("bulk.mfa.require_title", n, "Require MFA for {count} role?", "Require MFA for {count} roles?"),
      description: `${t(
        "bulk.mfa.require_text",
        "Members without a second factor must set one up at their next sign-in.",
      )} ${ownRules}`,
      run: run("require"),
    },
    {
      id: "optional",
      label: t("bulk.mfa.optional", "Stop requiring"),
      title: (n) =>
        tn(
          "bulk.mfa.optional_title",
          n,
          "Stop requiring MFA for {count} role?",
          "Stop requiring MFA for {count} roles?",
        ),
      description: t(
        "bulk.mfa.optional_text",
        "These roles no longer require a second factor. The realm policy and the clients may still ask for one.",
      ),
      run: run("optional"),
    },
    {
      id: "step_up_on",
      label: t("bulk.mfa.step_up_on", "Turn step-up on"),
      overflow: true,
      title: (n) =>
        tn("bulk.mfa.step_up_on_title", n, "Ask for step-up for {count} role?", "Ask for step-up for {count} roles?"),
      description: `${t(
        "bulk.mfa.step_up_on_text",
        "Members confirm their second factor again before a sensitive action.",
      )} ${ownRules}`,
      run: run("step_up_on"),
    },
    {
      id: "step_up_off",
      label: t("bulk.mfa.step_up_off", "Turn step-up off"),
      overflow: true,
      title: (n) =>
        tn(
          "bulk.mfa.step_up_off_title",
          n,
          "Turn step-up off for {count} role?",
          "Turn step-up off for {count} roles?",
        ),
      description: t("bulk.mfa.step_up_off_text", "These roles no longer ask for step-up before a sensitive action."),
      run: run("step_up_off"),
    },
    {
      id: "inherit",
      label: t("bulk.mfa.inherit", "Back to realm default"),
      overflow: true,
      danger: true,
      title: (n) =>
        tn(
          "bulk.mfa.inherit_title",
          n,
          "Put {count} role back on the realm default?",
          "Put {count} roles back on the realm default?",
        ),
      description: t(
        "bulk.mfa.inherit_text",
        "The own rules of these roles are deleted (methods, grace period, step-up): the realm policy applies to their members.",
      ),
      run: run("inherit"),
    },
  ];
  return (
    <BulkProvider
      scope={`mfa-roles:${realm}`}
      realm={realm}
      page={page}
      total={page.length}
      actions={actions}
      countLabel={(n) => tn("bulk.roles.selected", n, "{count} role selected", "{count} roles selected")}
      doneLabel={(n) => tn("bulk.roles.done", n, "{count} role updated", "{count} roles updated")}
    >
      {children}
    </BulkProvider>
  );
}
