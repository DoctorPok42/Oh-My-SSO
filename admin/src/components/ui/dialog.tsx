"use client";

import { Dialog as DialogPrimitive } from "radix-ui";
import { X } from "lucide-react";
import type * as React from "react";
import { cn } from "@/lib/utils";

// Modal dialog (Radix Dialog: focus trap, Escape, aria-modal), in two shapes:
// centred (DialogContent) and the DS "Drawer" sliding from the right
// (SheetContent, 760 px for clients, 640 px for the others).
// https://www.radix-ui.com/primitives/docs/components/dialog

const Dialog = DialogPrimitive.Root;
const DialogTrigger = DialogPrimitive.Trigger;
const DialogClose = DialogPrimitive.Close;

function Overlay({ className, ...props }: React.ComponentProps<typeof DialogPrimitive.Overlay>) {
  return (
    <DialogPrimitive.Overlay
      className={cn(
        "fixed inset-0 z-50 bg-black/40 data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:animate-in data-[state=open]:fade-in-0",
        className,
      )}
      {...props}
    />
  );
}

function CloseButton() {
  return (
    <DialogPrimitive.Close className="absolute top-4 right-4 rounded-sm p-1 text-text-muted transition-colors hover:bg-surface-alt hover:text-text-primary">
      <X className="size-4" />
      <span className="sr-only">Close</span>
    </DialogPrimitive.Close>
  );
}

function DialogContent({ className, children, ...props }: React.ComponentProps<typeof DialogPrimitive.Content>) {
  return (
    <DialogPrimitive.Portal>
      <Overlay />
      <DialogPrimitive.Content
        className={cn(
          "fixed top-1/2 left-1/2 z-50 max-h-[90vh] w-[calc(100%-2rem)] max-w-md -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-xl border border-border bg-surface p-6 shadow-elevation-md outline-none data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95 data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=open]:zoom-in-95",
          className,
        )}
        {...props}
      >
        {children}
        <CloseButton />
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  );
}

function SheetContent({
  className,
  children,
  width = "md",
  ...props
}: React.ComponentProps<typeof DialogPrimitive.Content> & { width?: "md" | "lg" }) {
  return (
    <DialogPrimitive.Portal>
      <Overlay />
      <DialogPrimitive.Content
        className={cn(
          "fixed inset-y-0 right-0 z-50 flex w-full flex-col border-l border-border bg-surface shadow-elevation-md outline-none data-[state=closed]:animate-out data-[state=closed]:slide-out-to-right data-[state=open]:animate-in data-[state=open]:slide-in-from-right",
          // Configuration space: room for two fields side by side.
          width === "lg" ? "sm:max-w-[760px]" : "sm:max-w-[640px]",
          className,
        )}
        {...props}
      >
        {children}
        <CloseButton />
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  );
}

/** Scrollable body of a drawer (padding 28 per the DS). */
function SheetBody({ className, ...props }: React.ComponentProps<"div">) {
  return <div className={cn("flex-1 space-y-5 overflow-y-auto px-7 pt-7 pb-6", className)} {...props} />;
}

/** Save / Cancel, always visible at the bottom of a drawer. */
function SheetFooter({ className, ...props }: React.ComponentProps<"div">) {
  return <div className={cn("flex gap-2 border-t border-border bg-surface px-7 py-4", className)} {...props} />;
}

function DialogTitle({ className, ...props }: React.ComponentProps<typeof DialogPrimitive.Title>) {
  return <DialogPrimitive.Title className={cn("pr-8 text-[18px] font-semibold", className)} {...props} />;
}

function DialogDescription({ className, ...props }: React.ComponentProps<typeof DialogPrimitive.Description>) {
  return <DialogPrimitive.Description className={cn("mt-1 text-[13px] text-text-secondary", className)} {...props} />;
}

export {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogTitle,
  DialogTrigger,
  SheetBody,
  SheetContent,
  SheetFooter,
};
