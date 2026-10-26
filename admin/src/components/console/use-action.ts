"use client";

import { useRouter } from "next/navigation";
import { useCallback, useState, useTransition } from "react";
import { toast } from "sonner";
import { usePendingReport } from "@/components/console/navigation-progress";
import { useStepUp } from "@/components/console/step-up";
import { needsSignIn, needsStepUp, type ApiResult } from "@/lib/api-error";

// Calls a Server Action and handles what every change has in common:
//  - step-up needed -> "Confirm it's you" dialog;
//  - session over -> the "session ended" page;
//  - other errors -> a toast with the API's message (unless the form shows it);
//  - success -> optional toast, then the page's data is reloaded
//    (router.refresh(): Server Components render again, client state stays).
// The progress bar shows while the action runs and while the page reloads.
// https://nextjs.org/docs/app/getting-started/updating-data

export function useAction() {
  const router = useRouter();
  const stepUp = useStepUp();
  const [pending, setPending] = useState(false);
  const [refreshing, startRefresh] = useTransition();
  usePendingReport(pending || refreshing);

  const run = useCallback(
    async <T>(
      fn: () => Promise<ApiResult<T>>,
      // quiet: the form shows the error itself (next to the field, or as a banner).
      opts: { success?: string; refresh?: boolean; quiet?: boolean; intent?: string } = {},
    ): Promise<ApiResult<T>> => {
      setPending(true);
      let r: ApiResult<T>;
      try {
        r = await fn();
      } catch {
        r = {
          ok: false,
          status: 0,
          error: "network",
          message: "The console did not answer, or your session ended. Reload the page.",
        };
      } finally {
        setPending(false);
      }
      if (!r.ok) {
        if (needsStepUp(r)) {
          stepUp.request(r.error === "mfa_enrollment_required" ? "enroll" : "expired", opts.intent);
        } else if (needsSignIn(r)) {
          router.push(
            `/auth/expired?returnTo=${encodeURIComponent(window.location.pathname + window.location.search)}`,
          );
        } else if (!opts.quiet) {
          toast.error(r.message);
        }
        return r;
      }
      if (opts.success) toast.success(opts.success);
      if (opts.refresh !== false) startRefresh(() => router.refresh());
      return r;
    },
    [router, stepUp],
  );

  return { run, pending, refreshing };
}
