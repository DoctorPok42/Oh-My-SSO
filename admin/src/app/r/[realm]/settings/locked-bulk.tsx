"use client";

import type { ReactNode } from "react";
import { BulkProvider } from "@/components/console/bulk";
import { ConfirmAction } from "@/components/console/confirm";
import { useT } from "@/i18n/client";
import { bulkUsers, matchingUserIds, unlockUser } from "../users/actions";

export function LockedBulk({
  realm,
  page,
  total,
  children,
}: {
  realm: string;
  page: string[];
  total: number;
  children: ReactNode;
}) {
  const { t, tn } = useT();
  return (
    <BulkProvider
      scope={`locked:${realm}`}
      realm={realm}
      page={page}
      total={total}
      countLabel={(n) => tn("bulk.locked.selected", n, "{count} account selected", "{count} accounts selected")}
      doneLabel={(n) => tn("bulk.locked.done", n, "{count} account unlocked", "{count} accounts unlocked")}
      matching={(exclude) => matchingUserIds(realm, { locked: true }, exclude)}
      actions={[
        {
          id: "unlock",
          label: t("bulk.users.unlock", "Unlock"),
          title: (n) => tn("bulk.users.unlock_title", n, "Unlock {count} account?", "Unlock {count} accounts?"),
          description: t("bulk.users.unlock_text", "Clears the failed sign-ins and the lock of these accounts."),
          run: (ids) => bulkUsers(realm, { action: "unlock", ids }),
        },
      ]}
    >
      {children}
    </BulkProvider>
  );
}

export function UnlockButton({ realm, id, name }: { realm: string; id: string; name: string }) {
  const { t } = useT();
  return (
    <ConfirmAction
      variant="secondary"
      confirmVariant="primary"
      trigger={t("users.unlock", "Unlock")}
      title={t("settings.locked.unlock_title", "Unlock {name}?", { name })}
      description={t("bulk.users.unlock_text", "Clears the failed sign-ins and the lock of these accounts.")}
      confirmLabel={t("users.unlock", "Unlock")}
      success={t("users.unlocked", "Account unlocked")}
      action={() => unlockUser(realm, id)}
    />
  );
}
