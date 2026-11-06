"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useTopLoader } from "nextjs-toploader";
import { useCallback, useEffect, useEffectEvent, useState, useSyncExternalStore, useTransition } from "react";
import { PageSkeleton } from "@/components/console/page-skeletons";
import { hrefView } from "@/lib/nav";
import { cn } from "@/lib/utils";

// The thin bar at the top of the window while something loads.
//
// The bar itself is nextjs-toploader (NextTopLoader, in app/layout.tsx): it
// starts by itself when a link is clicked and ends when Next.js shows the
// new page. https://github.com/TheSGJ/nextjs-toploader
//
// The console has other waits that are not link clicks: a search
// (router.push), a drawer loading, the page reloading after a change
// (router.refresh). They report here (usePendingReport), and
// NavigationProgress below starts the same bar while at least one runs.
//
// A navigation that replaces the page's content (a link, a search) also
// dims the content (PendingContent). Opening a drawer or reloading after a
// change does not dim anything.
//
// There are no loading.tsx files and no <Suspense> skeletons around the
// tables, on purpose. Once React has shown a Suspense fallback, it holds back
// what replaces it for 300 ms (FALLBACK_THROTTLE_MS, so that content does not
// flash): with a skeleton, a page the server answers in 30 ms appears after
// 330 ms. Without one, a navigation is a single transition: the current page
// stays until the next one is ready, then they swap. A page that really is
// slow gets its skeleton from here (PageSkeleton, after SKELETON_DELAY_MS),
// which React does not throttle: it is not a Suspense fallback.
//
// The counts live outside React (useSyncExternalStore): many components can
// report at once without re-rendering each other.
// https://react.dev/reference/react/useSyncExternalStore

/** How long the current page stays (dimmed) before the next page's skeleton replaces it. */
const SKELETON_DELAY_MS = 300;

let pendingCount = 0;
let contentCount = 0;
/** Where the running content navigations go, the latest last. */
const targets: string[] = [];
const listeners = new Set<() => void>();

function emit() {
  for (const l of listeners) l();
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Starts one wait; the returned function ends it (safe to call twice). */
export function beginPending(content = false, href?: string): () => void {
  pendingCount++;
  if (content) contentCount++;
  if (href) targets.push(href);
  emit();
  let ended = false;
  return () => {
    if (ended) return;
    ended = true;
    pendingCount--;
    if (content) contentCount--;
    if (href) targets.splice(targets.lastIndexOf(href), 1);
    emit();
  };
}

/** Something is loading (the bar shows) / the page's content is being replaced (it is dimmed). */
export const isPending = () => pendingCount > 0;
export const isContentPending = () => contentCount > 0;
/** Where the page is going, null when it stays. */
export const pendingTarget = () => targets.at(-1) ?? null;

/** pendingTarget(), for a component: the menus follow the click at once. */
export function usePendingTarget() {
  return useSyncExternalStore(subscribe, pendingTarget, () => null);
}

/**
 * Reports `pending` to the bar for as long as it is true. `content`: this
 * navigation replaces the page's content, dim it meanwhile; `href`: where it goes.
 */
export function usePendingReport(pending: boolean, content = false, href?: string) {
  useEffect(() => (pending ? beginPending(content, href) : undefined), [pending, content, href]);
}

/**
 * router.push / router.refresh in a React transition: `pending` stays true
 * until the new page is on screen, and the bar shows meanwhile.
 * https://react.dev/reference/react/useTransition
 */
export function useNavigate({ content = true }: { content?: boolean } = {}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [target, setTarget] = useState<string>();
  usePendingReport(pending, content, content ? target : undefined);
  const push = useCallback(
    (href: string, opts?: { scroll?: boolean }) => {
      setTarget(href);
      startTransition(() => router.push(href, opts));
    },
    [router],
  );
  const refresh = useCallback(() => {
    setTarget(undefined);
    startTransition(() => router.refresh());
  }, [router]);
  return { push, refresh, pending };
}

/**
 * The page's content, dimmed while a navigation replaces it. The dimming
 * waits 150 ms (CSS transition delay): a fast navigation shows nothing. Going
 * to another page, the next page's skeleton takes over after
 * SKELETON_DELAY_MS; a filter or a search stays on the page, dimmed. The
 * current page stays mounted: an interrupted navigation finds it intact.
 */
export function PendingContent({ children }: { children: React.ReactNode }) {
  const busy = useSyncExternalStore(subscribe, isContentPending, () => false);
  const target = usePendingTarget();
  const pathname = usePathname();
  const tab = useSearchParams().get("tab");
  const next = target ? hrefView(target) : null;
  const otherPage = next !== null && (next.path !== pathname || next.tab !== tab);
  const [lateFor, setLateFor] = useState<string | null>(null);
  useEffect(() => {
    if (!otherPage) return;
    const timer = setTimeout(() => setLateFor(target), SKELETON_DELAY_MS);
    return () => {
      clearTimeout(timer);
      setLateFor(null);
    };
  }, [otherPage, target]);
  const late = otherPage && lateFor === target;
  return (
    <div data-pending-content={busy} aria-busy={busy || undefined}>
      {late && <PageSkeleton href={target!} />}
      <div
        hidden={late}
        className={cn("transition-opacity duration-200 motion-reduce:transition-none", busy && "opacity-55 delay-150")}
      >
        {children}
      </div>
    </div>
  );
}

/**
 * Starts the top bar (nextjs-toploader) while one of the console's own waits
 * runs, and ends it after the last one. Renders nothing: the bar is
 * NextTopLoader's. Link clicks need nothing from here.
 */
export function NavigationProgress() {
  const loader = useTopLoader();
  const busy = useSyncExternalStore(subscribe, isPending, () => false);
  // useEffectEvent: the effect runs when `busy` changes, and still calls
  // the latest `loader`. https://react.dev/reference/react/useEffectEvent
  const sync = useEffectEvent((on: boolean) => {
    if (on) loader.start();
    else loader.done();
  });
  // Braces, not `() => sync(busy)`: an effect may only return a clean-up
  // function. start() and done() return an object, which React would call
  // as the clean-up ("destroy is not a function").
  // https://react.dev/reference/react/useEffect#parameters
  useEffect(() => {
    sync(busy);
  }, [busy]);
  return null;
}
