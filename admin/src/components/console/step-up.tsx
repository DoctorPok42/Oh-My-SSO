"use client";

import { ShieldCheck } from "lucide-react";
import { usePathname, useSearchParams } from "next/navigation";
import { createContext, useCallback, useContext, useMemo, useState, useSyncExternalStore } from "react";
import { Button, buttonVariants } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { cn } from "@/lib/utils";

// Step-up: every change needs a second factor verified in the last minutes
// (10 by default, "MFA step-up max age" of the master realm). The console
// knows until when from GET /me (step_up_fresh_until) and offers the new
// sign-in BEFORE the admin starts editing, so no typing is lost.
//
// "Confirm it's you" = /auth/step-up: password + second factor again on the
// IdP (prompt=login), then back to the same page; `intent` (e.g. "new=1",
// "edit=<id>") reopens the drawer the admin was about to use.

type Reason = "edit" | "expired" | "enroll";

type StepUpContext = {
  /** Changes go through without a new sign-in right now. */
  fresh: boolean;
  freshUntil: Date | null;
  /** Opens the "Confirm it's you" dialog. */
  request: (reason?: Reason, intent?: string) => void;
  /** Runs `then` if fresh, otherwise asks for the step-up first. */
  ensure: (then: () => void, intent?: string) => void;
};

const Ctx = createContext<StepUpContext | null>(null);

export function useStepUp(): StepUpContext {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useStepUp outside <StepUpProvider>");
  return ctx;
}

// A clock that ticks every 15 s, read with useSyncExternalStore: during
// hydration React uses the server's answer (initialFresh), so the first
// client render matches the HTML; then the real clock takes over.
const TICK = 15_000;
function subscribe(onChange: () => void) {
  const t = setInterval(onChange, TICK);
  return () => clearInterval(t);
}
const clientTick = () => Math.floor(Date.now() / TICK);
const serverTick = () => null;

export function StepUpProvider({
  freshUntil,
  initialFresh,
  children,
}: {
  freshUntil: string | null;
  /** Freshness as computed by the server when it rendered the page. */
  initialFresh: boolean;
  children: React.ReactNode;
}) {
  const until = useMemo(() => (freshUntil ? new Date(freshUntil) : null), [freshUntil]);
  const tick = useSyncExternalStore(subscribe, clientTick, serverTick);
  const [dialog, setDialog] = useState<{ reason: Reason; intent?: string } | null>(null);
  const pathname = usePathname();
  const search = useSearchParams();

  const fresh = tick === null ? initialFresh : !!until && until.getTime() - tick * TICK > TICK;
  const request = useCallback((reason: Reason = "edit", intent?: string) => setDialog({ reason, intent }), []);
  const ensure = useCallback(
    (then: () => void, intent?: string) => (fresh ? then() : setDialog({ reason: "edit", intent })),
    [fresh],
  );

  // Back to this page after the new sign-in, with the intent added.
  const params = new URLSearchParams(search.toString());
  params.delete("new");
  params.delete("edit");
  if (dialog?.intent) {
    const [k, v] = dialog.intent.split("=");
    if (k && v) params.set(k, v);
  }
  const qs = params.toString();
  const returnTo = pathname + (qs ? `?${qs}` : "");
  const href = `/auth/step-up?returnTo=${encodeURIComponent(returnTo)}`;

  const text: Record<Reason, string> = {
    edit: "Changes in the admin console need a second factor verified in the last few minutes. You will sign in again with your password and your second factor, then come back here.",
    expired:
      "Your last confirmation is too old for this change. Sign in again with your password and your second factor, then do it again.",
    enroll:
      "Your account has no second factor yet. Set one up on the sign-in page, then come back here to make changes.",
  };

  return (
    <Ctx.Provider value={{ fresh, freshUntil: until, request, ensure }}>
      {children}
      <Dialog open={!!dialog} onOpenChange={(o) => !o && setDialog(null)}>
        <DialogContent>
          <div className="mb-4 grid size-10 place-items-center rounded-full bg-accent-soft text-accent">
            <ShieldCheck className="size-5" />
          </div>
          <DialogTitle>Confirm it&apos;s you</DialogTitle>
          <DialogDescription className="text-[14px] leading-6">{dialog && text[dialog.reason]}</DialogDescription>
          <div className="mt-6 flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setDialog(null)}>
              Not now
            </Button>
            {/* A full navigation (not a client-side Link): it leaves for the IdP. */}
            <a href={href} className={cn(buttonVariants())}>
              Continue
            </a>
          </div>
        </DialogContent>
      </Dialog>
    </Ctx.Provider>
  );
}
