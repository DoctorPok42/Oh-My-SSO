"use client";

import { ChevronDown } from "lucide-react";
import * as React from "react";
import { cn } from "@/lib/utils";
import { fieldClass } from "@/components/ui/input";

// The CSS :open pseudo-class matches a <select> while its list is shown. Where
// the browser knows it, the chevron follows it exactly and no script runs.
function supportsOpenPseudo(): boolean {
  try {
    return typeof CSS !== "undefined" && CSS.supports("selector(:open)");
  } catch {
    return false;
  }
}

const noSubscribe = () => () => {};

const OPENER_KEYS = new Set([" ", "Enter", "F4"]);

// A real <select>, styled like the inputs: works in plain forms, with the
// keyboard and screen readers, on every device.
// wrapperClassName sizes the box (max-w-xs, w-36…): the chevron is anchored to
// the wrapper, so a width set only on the <select> leaves it at the far edge.
// The chevron turns while the list is open. Without :open there is no event
// for that, so the fallback relies on one fact: while the native list is
// shown it receives the pointer and the keyboard, the page gets nothing. The
// first pointer move, press, wheel or key the page sees after the opening
// therefore means the list is closed, even when the user picked the value that
// was already selected (no change event) or dismissed the list.
function NativeSelect({
  className,
  wrapperClassName,
  children,
  onMouseDown,
  onKeyDown,
  onChange,
  onBlur,
  ...props
}: React.ComponentProps<"select"> & { wrapperClassName?: string }) {
  // false on the server and during hydration, the real answer afterwards.
  const native = React.useSyncExternalStore(noSubscribe, supportsOpenPseudo, () => false);
  const [open, setOpen] = React.useState(false);

  React.useEffect(() => {
    if (!open || native) return;
    const close = () => setOpen(false);
    const events = ["pointermove", "pointerdown", "wheel", "keydown"] as const;
    // Wait a frame: events of the opening gesture itself are not a close.
    const frame = requestAnimationFrame(() => {
      for (const ev of events) document.addEventListener(ev, close, { capture: true, passive: true });
    });
    return () => {
      cancelAnimationFrame(frame);
      for (const ev of events) document.removeEventListener(ev, close, { capture: true });
    };
  }, [open, native]);

  return (
    <div className={cn("relative", wrapperClassName)}>
      <select
        data-slot="native-select"
        className={cn(fieldClass, "peer h-10 cursor-pointer appearance-none pr-9", className)}
        onMouseDown={(e) => {
          // The page only gets this press when the list is closed: it opens it.
          if (!native && e.button === 0 && !e.currentTarget.disabled) setOpen(true);
          onMouseDown?.(e);
        }}
        onKeyDown={(e) => {
          // Same: a key reaching the page means the list was closed.
          if (!native) setOpen(OPENER_KEYS.has(e.key) || (e.altKey && e.key.startsWith("Arrow")));
          onKeyDown?.(e);
        }}
        onChange={(e) => {
          setOpen(false);
          onChange?.(e);
        }}
        onBlur={(e) => {
          setOpen(false);
          onBlur?.(e);
        }}
        {...props}
      >
        {children}
      </select>
      <ChevronDown
        aria-hidden
        className={cn(
          "pointer-events-none absolute top-1/2 right-3 size-4 -translate-y-1/2 text-text-muted transition-transform",
          native ? "peer-[:open]:rotate-180" : open && "rotate-180",
        )}
      />
    </div>
  );
}

export { NativeSelect };
