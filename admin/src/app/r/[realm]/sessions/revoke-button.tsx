"use client";

import { ConfirmAction } from "@/components/console/confirm";
import { revokeSession } from "./actions";

export function RevokeSessionButton({ realm, id, user }: { realm: string; id: string; user: string }) {
  return (
    <ConfirmAction
      trigger="Revoke"
      title={`Sign ${user} out of this session?`}
      description="The session ends now: the applications it signed in to lose their tokens, and the user must sign in again."
      confirmLabel="Revoke session"
      success="Session revoked"
      action={() => revokeSession(realm, id)}
    />
  );
}
