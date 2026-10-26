"use client";

import { useState } from "react";
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { useStepUp } from "@/components/console/step-up";
import { useAction } from "@/components/console/use-action";
import type { ApiResult } from "@/lib/api-error";

// A button that asks "Are you sure?" before a destructive change, offers the
// step-up first when needed, then runs the Server Action.
export function ConfirmAction<T>({
  trigger,
  title,
  description,
  confirmLabel,
  action,
  success,
  onDone,
  disabled,
  variant = "danger",
  size = "xs",
  confirmVariant = "destructive",
}: {
  trigger: React.ReactNode;
  title: string;
  description: React.ReactNode;
  confirmLabel: string;
  action: () => Promise<ApiResult<T>>;
  success?: string;
  onDone?: (data: T) => void;
  disabled?: boolean;
  variant?: "danger" | "secondary" | "primary";
  size?: "xs" | "sm";
  /** Red for destructive changes (default), blue otherwise. */
  confirmVariant?: "destructive" | "primary";
}) {
  const [open, setOpen] = useState(false);
  const stepUp = useStepUp();
  const { run, pending } = useAction();
  return (
    <>
      <Button variant={variant} size={size} disabled={disabled} onClick={() => stepUp.ensure(() => setOpen(true))}>
        {trigger}
      </Button>
      <AlertDialog open={open} onOpenChange={setOpen}>
        <AlertDialogContent>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div>{description}</div>
          </AlertDialogDescription>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <Button
              variant={confirmVariant}
              loading={pending}
              disabled={pending}
              onClick={async () => {
                const r = await run(action, { success });
                setOpen(false);
                if (r.ok) onDone?.(r.data);
              }}
            >
              {pending ? "Working…" : confirmLabel}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
