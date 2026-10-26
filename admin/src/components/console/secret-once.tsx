"use client";

import { KeyRound } from "lucide-react";
import { Banner } from "@/components/ui/banner";
import { Button } from "@/components/ui/button";
import { CopyField } from "@/components/ui/copy-button";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";

// DS "Code affiché une seule fois": a secret (client secret, activation link)
// the server does not keep in clear. Shown once; the dialog only closes with
// the button, not by a click outside, so it is not lost by accident.
export function SecretOnceDialog({
  open,
  title,
  description,
  items,
  onDone,
}: {
  open: boolean;
  title: string;
  description?: string;
  items: { label: string; value: string }[];
  onDone: () => void;
}) {
  return (
    <Dialog open={open}>
      <DialogContent
        className="max-w-lg"
        onInteractOutside={(e) => e.preventDefault()}
        onEscapeKeyDown={(e) => e.preventDefault()}
      >
        <div className="mb-4 grid size-10 place-items-center rounded-full bg-warning-soft text-warning">
          <KeyRound className="size-5" />
        </div>
        <DialogTitle>{title}</DialogTitle>
        {description && <DialogDescription>{description}</DialogDescription>}
        <Banner tone="warning" className="mt-4">
          Copy it now: it won&apos;t be shown again.
        </Banner>
        <dl className="mt-4 space-y-3">
          {items.map((i) => (
            <div key={i.label}>
              <dt className="mb-1.5 text-[13px] font-semibold text-text-secondary">{i.label}</dt>
              <dd>
                <CopyField value={i.value} />
              </dd>
            </div>
          ))}
        </dl>
        <div className="mt-6 flex justify-end">
          <Button onClick={onDone}>I&apos;ve copied it</Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
