"use client";

import { RotateCw } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { ConfirmAction } from "@/components/console/confirm";
import { useStepUp } from "@/components/console/step-up";
import { useAction } from "@/components/console/use-action";
import { Banner } from "@/components/ui/banner";
import { Button } from "@/components/ui/button";
import { CheckboxField } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Field } from "@/components/ui/field";
import { Input, Textarea } from "@/components/ui/input";
import { Segmented } from "@/components/ui/segmented";
import { activateKey, retireExpiredKeys, rotateKey } from "./actions";

export function KeyActions({ realm, hasPendingSaml }: { realm: string; hasPendingSaml: boolean }) {
  const [open, setOpen] = useState(false);
  const [purpose, setPurpose] = useState<"jwt_signing" | "saml_signing">("jwt_signing");
  const [keyType, setKeyType] = useState<"RSA" | "EC">("RSA");
  // Empty: the realm's default (Settings → default key rotation grace).
  const [grace, setGrace] = useState("");
  const [compromised, setCompromised] = useState(false);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const stepUp = useStepUp();
  const { run, pending } = useAction();

  async function rotate() {
    setError(null);
    const r = await run(
      () =>
        rotateKey(realm, {
          purpose,
          key_type: purpose === "saml_signing" ? "RSA" : keyType,
          grace_hours: Number(grace) || 0,
          compromised,
          reason: reason.trim(),
        }),
      { quiet: true },
    );
    if (!r.ok) return setError(r.message);
    setOpen(false);
    setCompromised(false);
    setReason("");
    toast.success(
      purpose === "saml_signing"
        ? "New SAML key published (pending). Activate it once service providers have the new metadata."
        : `New key ${r.data.new_key.kid.slice(0, 8)}… is signing. The old one stays published for ${r.data.grace_hours} h.`,
    );
    if (r.data.warning) toast.warning(r.data.warning);
  }

  return (
    <div className="flex flex-wrap gap-2">
      <ConfirmAction
        variant="secondary"
        size="sm"
        trigger="Retire expired keys"
        title="Retire the keys whose grace period ended?"
        description="They leave the JWKS and the SAML metadata. Rotation already does this automatically; use it to clean up at once."
        confirmLabel="Retire"
        confirmVariant="primary"
        action={() => retireExpiredKeys(realm)}
        onDone={(d) => toast.success(d.keys.length ? `${d.keys.length} key(s) retired` : "Nothing to retire")}
      />
      {hasPendingSaml && (
        <ConfirmAction
          variant="secondary"
          size="sm"
          trigger="Activate pending SAML key"
          title="Start signing with the new SAML key?"
          description={
            "Service providers that did not refresh the metadata will reject the responses. The previous key stays published for the realm's grace period."
          }
          confirmLabel="Activate"
          confirmVariant="primary"
          success="The new SAML key is signing"
          action={() => activateKey(realm, { purpose: "saml_signing", grace_hours: 0, reason: "" })}
        />
      )}
      <Button onClick={() => stepUp.ensure(() => setOpen(true))}>
        <RotateCw />
        Rotate key
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-lg">
          <DialogTitle>Rotate a signing key</DialogTitle>
          <DialogDescription>
            A new key pair is created in the key manager; the private key never leaves it.
          </DialogDescription>
          <div className="mt-5 space-y-4">
            <Field label="Key">
              <Segmented
                label="Purpose"
                value={purpose}
                onChange={setPurpose}
                options={[
                  { value: "jwt_signing", label: "OIDC tokens (JWT)" },
                  { value: "saml_signing", label: "SAML assertions" },
                ]}
              />
            </Field>
            {purpose === "jwt_signing" && (
              <Field label="Algorithm">
                <Segmented
                  label="Key type"
                  value={keyType}
                  onChange={setKeyType}
                  options={[
                    { value: "RSA", label: "RSA (RS256)" },
                    { value: "EC", label: "EC P-256 (ES256)" },
                  ]}
                />
              </Field>
            )}
            {!compromised && (
              <Field
                label="Grace period (hours)"
                htmlFor="k-grace"
                optional
                hint="How long the old public key stays published: longer than your longest token lifetime. Empty: the realm's default (Settings)."
              >
                <Input
                  id="k-grace"
                  type="number"
                  min={1}
                  placeholder="default"
                  value={grace}
                  onChange={(e) => setGrace(e.target.value)}
                  className="w-32"
                />
              </Field>
            )}
            <CheckboxField
              id="k-compromised"
              label="The current key is compromised"
              hint="It is removed at once, without grace period."
              checked={compromised}
              onCheckedChange={(v) => setCompromised(v === true)}
            />
            {compromised && (
              <>
                <Banner tone="danger">
                  Every token it signed stops being accepted now: users of every application must sign in again.
                </Banner>
                <Field label="Reason (kept in the audit log)" htmlFor="k-reason">
                  <Textarea id="k-reason" rows={2} value={reason} onChange={(e) => setReason(e.target.value)} />
                </Field>
              </>
            )}
            {error && <Banner tone="danger">{error}</Banner>}
          </div>
          <div className="mt-6 flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button
              variant={compromised ? "destructive" : "primary"}
              loading={pending}
              disabled={pending || (compromised && reason.trim().length < 3)}
              onClick={rotate}
            >
              {pending ? "Rotating…" : "Rotate now"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
