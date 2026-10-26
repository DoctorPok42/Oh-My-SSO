"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { createContext, useCallback, useContext, useMemo, useState, useTransition } from "react";
import { Lock } from "lucide-react";
import { usePendingReport } from "@/components/console/navigation-progress";
import { useStepUp } from "@/components/console/step-up";
import { Banner } from "@/components/ui/banner";
import { Button } from "@/components/ui/button";
import { Dialog, DialogDescription, DialogTitle, SheetBody, SheetContent, SheetFooter } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";

// Drawers are opened through the URL: ?new=1 or ?edit=<id>. The server
// renders the page with the item already loaded, Back closes the drawer, a
// link can point at it, and after a step-up the admin lands back in it.
//
// Waiting for the server before showing anything felt broken (seconds with
// no reaction to a click), so the drawer moves at once: it opens at the
// click with a skeleton inside, and is filled when the item arrives; it
// closes at the click, and the URL catches up. The "intent" below is what
// the admin asked for, valid until the URL confirms the navigation; after
// that, the server's props decide again.

type Intent = "open" | "close";

const DrawerNav = createContext<{
  intent: Intent | null;
  go: (href: string, intent: Intent) => void;
} | null>(null);

/** Put once around the console (layout): shares the drawer's intent with the page's drawer. */
export function DrawerNavProvider({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const search = useSearchParams();
  const [intent, setIntent] = useState<Intent | null>(null);
  const [pending, startTransition] = useTransition();
  usePendingReport(pending);
  const go = useCallback(
    (href: string, next: Intent) => {
      setIntent(next);
      startTransition(() => router.push(href, { scroll: false }));
    },
    [router],
  );
  // Keep the optimistic state until the URL confirms the navigation. This
  // prevents stale server props from reopening a drawer during close.
  const drawerOpen = search.has("new") || search.has("edit");
  const confirmed = (intent === "open" && drawerOpen) || (intent === "close" && !drawerOpen);
  const value = useMemo(() => ({ intent: confirmed ? null : intent, go }), [confirmed, intent, go]);
  return <DrawerNav.Provider value={value}>{children}</DrawerNav.Provider>;
}

export function useDrawerUrl() {
  const router = useRouter();
  const nav = useContext(DrawerNav);
  const pathname = usePathname();
  const search = useSearchParams();
  const go = useCallback(
    (change: Record<string, string | null>) => {
      const p = new URLSearchParams(search.toString());
      for (const [k, v] of Object.entries(change)) {
        if (v === null) p.delete(k);
        else p.set(k, v);
      }
      const qs = p.toString();
      const href = pathname + (qs ? `?${qs}` : "");
      const intent: Intent = change.new || change.edit ? "open" : "close";
      if (nav) nav.go(href, intent);
      else router.push(href, { scroll: false });
    },
    [router, nav, pathname, search],
  );
  return {
    openNew: () => go({ new: "1", edit: null }),
    openEdit: (id: string) => go({ edit: id, new: null }),
    close: () => go({ new: null, edit: null }),
  };
}

/** Drawer frame: title, scrollable body, footer with Save / Cancel. */
export function Drawer({
  open,
  onClose,
  title,
  description,
  width,
  footer,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: React.ReactNode;
  width?: "md" | "lg";
  footer?: React.ReactNode;
  children: React.ReactNode;
}) {
  const intent = useContext(DrawerNav)?.intent ?? null;
  // Asked to open, the item is not here yet: skeleton.
  const waiting = intent === "open" && !open;
  const shown = intent === "close" ? false : open || intent === "open";
  return (
    <Dialog open={shown} onOpenChange={(o) => !o && onClose()}>
      <SheetContent width={width}>
        {waiting ? (
          <DrawerSkeleton />
        ) : (
          <>
            <SheetBody>
              <div>
                <DialogTitle>{title}</DialogTitle>
                <DialogDescription className={description ? undefined : "sr-only"}>
                  {description ?? title}
                </DialogDescription>
              </div>
              {children}
            </SheetBody>
            {footer && <SheetFooter>{footer}</SheetFooter>}
          </>
        )}
      </SheetContent>
    </Dialog>
  );
}

/** What a drawer looks like while its item loads: title, a few fields, the buttons. */
function DrawerSkeleton() {
  return (
    <>
      <SheetBody aria-busy="true">
        <div>
          <DialogTitle className="sr-only">Loading…</DialogTitle>
          <DialogDescription className="sr-only">The details are loading.</DialogDescription>
          <Skeleton className="h-6 w-56" />
          <Skeleton className="mt-2 h-4 w-72" />
        </div>
        {Array.from({ length: 5 }, (_, i) => (
          <div key={i} className="space-y-2">
            <Skeleton className="h-4 w-28" />
            <Skeleton className="h-9 w-full" />
          </div>
        ))}
      </SheetBody>
      <SheetFooter>
        <Skeleton className="h-9 w-24" />
        <Skeleton className="h-9 w-20" />
      </SheetFooter>
    </>
  );
}

/**
 * Why a form is read-only, if it is: no write permission, managed by a
 * configuration file, or no recent second factor (with the button to fix it).
 * Returns `locked` for the form's fields.
 */
export function useEditLock({
  canWrite,
  managedByConfig,
  intent,
}: {
  canWrite: boolean;
  managedByConfig?: boolean;
  intent?: string;
}) {
  const stepUp = useStepUp();
  let banner: React.ReactNode = null;
  if (!canWrite) {
    banner = <Banner tone="neutral">Read-only: your account may not change this.</Banner>;
  } else if (managedByConfig) {
    banner = (
      <Banner tone="neutral">
        Managed by a configuration file: change it there (configuration as code). Edits here are refused.
      </Banner>
    );
  } else if (!stepUp.fresh) {
    banner = (
      <Banner tone="info">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span>View only. To make changes, confirm it&apos;s you with your second factor.</span>
          <Button size="xs" variant="secondary" onClick={() => stepUp.request("edit", intent)}>
            <Lock className="size-3.5" />
            Confirm it&apos;s you
          </Button>
        </div>
      </Banner>
    );
  }
  return { locked: !canWrite || !!managedByConfig || !stepUp.fresh, banner };
}
