"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useSyncExternalStore, useTransition } from "react";
import { progressDone, progressStart, workerBar } from "./progress-bar";

// The thin bar at the top of the window while something loads: a tab, a
// filter, a page of results, a drawer, a refresh after a change.
//
// Anything that waits reports it here (usePendingReport); the bar shows
// while at least one wait is running. It stays invisible for the first
// 150 ms (CSS animation delay, globals.css): a fast navigation shows nothing.
//
// A navigation that replaces the page's content (a link, a search) also
// dims the content at once (PendingContent): the click visibly did
// something even before the new page's skeleton arrives. Opening a drawer
// or reloading after a change does not dim anything.
//
// The counts live outside React (useSyncExternalStore): many components can
// report at once without re-rendering each other.
// https://react.dev/reference/react/useSyncExternalStore
//
// The bar itself is drawn by a Web Worker (progress-bar.ts): the first
// wait sends it "start", the last one "done", straight from here, without
// a React render. Its animation runs on the worker's thread, so a busy
// main thread does not freeze it. Browsers that cannot do this keep the
// CSS bar below.

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
  if (pendingCount === 1) progressStart();
  emit();
  let ended = false;
  return () => {
    if (ended) return;
    ended = true;
    pendingCount--;
    if (content) contentCount--;
    if (pendingCount === 0) progressDone();
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
 * waits 150 ms too (CSS transition delay): a fast navigation shows nothing.
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

export function NavigationProgress() {
  const busy = useSyncExternalStore(subscribe, isPending, () => false);
  useEffect(() => {
    // Once per page load (the worker and its canvas live as long as the page).
    if (workerBar() && pendingCount > 0) progressStart();
  }, []);
  // data-nav-progress stays on this element in both cases (tests, and the
  // CSS fallback); with the worker, CSS hides it.
  return (
    <div
      aria-hidden
      data-nav-progress={busy ? "on" : "off"}
      className="nav-progress pointer-events-none fixed inset-x-0 top-0 z-[100] h-[3px] origin-left bg-accent opacity-0"
    />
  );
}
