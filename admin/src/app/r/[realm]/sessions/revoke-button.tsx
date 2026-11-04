"use client";

import { ConfirmAction } from "@/components/console/confirm";
import { useT } from "@/i18n/client";
import { revokeSession } from "./actions";

export function RevokeSessionButton({ realm, id, user }: { realm: string; id: string; user: string }) {
  const { t } = useT();
  return (
    <ConfirmAction
      trigger={t("sessions.revoke", "Revoke")}
      title={t("sessions.revoke_title", "Sign {user} out of this session?", { user })}
      description={t(
        "sessions.revoke_text",
        "The session ends now: the applications it signed in to lose their tokens, and the user must sign in again.",
      )}
      confirmLabel={t("sessions.revoke_confirm", "Revoke session")}
      success={t("sessions.revoked", "Session revoked")}
      action={() => revokeSession(realm, id)}
    />
  );
}
