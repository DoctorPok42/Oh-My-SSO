"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { useT } from "@/i18n/client";
import { needsSignIn } from "@/lib/api-error";
import { BULK_FIRST_POLL_MS, BULK_POLL_MS, type BulkJob } from "@/lib/bulk";
import { getBulkJob } from "@/lib/bulk-actions";

/** Failed polls in a row before the console gives up following a job. */
const MAX_POLL_FAILURES = 5;

/**
 * Follows a bulk action. The API answers a bulk request with the job it
 * started in the background (202): `follow` asks where it stands until it
 * ends, and `progress` is what a progress bar shows meanwhile. The job goes
 * on if the page is left: its report is in the audit log, under its
 * operation id.
 */
export function useBulkJob(realm: string) {
  const { t } = useT();
  const router = useRouter();
  const [progress, setProgress] = useState<BulkJob | null>(null);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  /** The ended job, or null when it could not be followed to its end. */
  const follow = useCallback(
    async (started: BulkJob): Promise<BulkJob | null> => {
      let job = started;
      let failures = 0;
      let looks = 0;
      setProgress(job);
      while (job.status === "running") {
        await new Promise((resolve) => setTimeout(resolve, looks++ === 0 ? BULK_FIRST_POLL_MS : BULK_POLL_MS));
        if (!alive.current) return null;
        const r = await getBulkJob(realm, started.id).catch(() => null);
        if (!alive.current) return null;
        if (r?.ok) {
          failures = 0;
          job = r.data;
          setProgress(job);
          continue;
        }
        if (r && needsSignIn(r)) {
          router.push(
            `/auth/expired?returnTo=${encodeURIComponent(window.location.pathname + window.location.search)}`,
          );
          return null;
        }
        // A hiccup (idp-admin restarting, a network blip): the job does not depend on us.
        if (++failures >= MAX_POLL_FAILURES) {
          setProgress(null);
          toast.error(
            t(
              "bulk.lost_track",
              "The console lost track of the bulk action, which goes on. Its result is in the audit log (operation {operation}).",
              { operation: started.operation_id },
            ),
          );
          return null;
        }
      }
      setProgress(null);
      router.refresh(); // what the action changed, in the table behind
      return job;
    },
    [realm, router, t],
  );

  return { progress, follow };
}
