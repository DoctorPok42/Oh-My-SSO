"use client";

import { AuthCard } from "@/components/console/auth-card";
import { Button } from "@/components/ui/button";

// Unexpected errors (a bug, not an API refusal: those are shown in place).
// In production Next.js hides the message; the digest ties it to the
// server's log line.
export default function GlobalError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <AuthCard title="Something went wrong">
      <p>
        The console hit an unexpected error. Try again; if it keeps happening, check the console server&apos;s logs.
      </p>
      {error.digest && <p className="font-mono text-[12px] text-text-muted">Reference: {error.digest}</p>}
      <Button size="md" className="w-full" onClick={reset}>
        Try again
      </Button>
    </AuthCard>
  );
}
