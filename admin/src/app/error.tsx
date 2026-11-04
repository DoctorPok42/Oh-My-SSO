"use client";

import { AuthCard } from "@/components/console/auth-card";
import { Button } from "@/components/ui/button";
import { useT } from "@/i18n/client";

// Unexpected errors (a bug, not an API refusal: those are shown in place).
// In production Next.js hides the message; the digest ties it to the
// server's log line.
export default function GlobalError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  const { t } = useT();
  return (
    <AuthCard title={t("error_state.other", "Something went wrong")}>
      <p>
        {t(
          "error.text",
          "The console hit an unexpected error. Try again; if it keeps happening, check the console server's logs.",
        )}
      </p>
      {error.digest && (
        <p className="font-mono text-[12px] text-text-muted">
          {t("error.reference", "Reference: {digest}", { digest: error.digest })}
        </p>
      )}
      <Button size="md" className="w-full" onClick={reset}>
        {t("error.try_again", "Try again")}
      </Button>
    </AuthCard>
  );
}
