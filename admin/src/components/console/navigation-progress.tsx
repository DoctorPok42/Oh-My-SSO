"use client";

import { useRouter } from "next/navigation";
import { useTopLoader } from "nextjs-toploader";
import { useCallback, useEffect, useEffectEvent, useSyncExternalStore, useTransition } from "react";

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
// dims the content at once (PendingContent): the click visibly did
// something even before the new page's skeleton arrives. Opening a drawer
// or reloading after a change does not dim anything.
//
// The counts live outside React (useSyncExternalStore): many components can
// report at once without re-rendering each other.
// https://react.dev/reference/react/useSyncExternalStore

let pendingCount = 0;
let contentCount = 0;
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
export function beginPending(content = false): () => void {
  pendingCount++;
  if (content) contentCount++;
  emit();
  let ended = false;
  return () => {
    if (ended) return;
    ended = true;
    pendingCount--;
    if (content) contentCount--;
    emit();
  };
}

/** Something is loading (the bar shows) / the page's content is being replaced (it is dimmed). */
export const isPending = () => pendingCount > 0;
export const isContentPending = () => contentCount > 0;

/**
 * Reports `pending` to the bar for as long as it is true. `content`: this
 * navigation replaces the page's content, dim it meanwhile.
 */
export function usePendingReport(pending: boolean, content = false) {
  useEffect(() => (pending ? beginPending(content) : undefined), [pending, content]);
}

/**
 * router.push / router.refresh in a React transition: `pending` stays true
 * until the new page is on screen, and the bar shows meanwhile.
 * https://react.dev/reference/react/useTransition
 */
export function useNavigate({ content = true }: { content?: boolean } = {}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  usePendingReport(pending, content);
  const push = useCallback(
    (href: string, opts?: { scroll?: boolean }) => startTransition(() => router.push(href, opts)),
    [router],
  );
  const refresh = useCallback(() => startTransition(() => router.refresh()), [router]);
  return { push, refresh, pending };
}

/**
 * The page's content, dimmed while a navigation replaces it. The dimming
 * waits 150 ms (CSS transition delay): a fast navigation shows nothing.
 */
export function PendingContent({ children }: { children: React.ReactNode }) {
  const busy = useSyncExternalStore(subscribe, isContentPending, () => false);
  return (
    <div
      data-pending-content={busy}
      aria-busy={busy || undefined}
      className="transition-opacity duration-200 data-[pending-content=true]:opacity-55 data-[pending-content=true]:delay-150 motion-reduce:transition-none"
    >
      {children}
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
