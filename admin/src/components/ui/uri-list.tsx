"use client";

import { Plus, X } from "lucide-react";
import { useT } from "@/i18n/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

/**
 * One input per URI, with add/remove. The value stays a "\n"-joined string
 * (what the form draft and `lines()` already use); empty rows are kept while
 * editing and dropped on submit.
 */
export function UriList({
  id,
  value,
  onChange,
  placeholder,
}: {
  id: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  const { t } = useT();
  const rows = value === "" ? [""] : value.split("\n");
  const set = (next: string[]) => onChange(next.join("\n"));
  return (
    <div className="space-y-2">
      {rows.map((row, i) => (
        <div key={i} className="flex gap-2">
          <Input
            id={i === 0 ? id : undefined}
            className="font-mono text-[13px]"
            value={row}
            placeholder={placeholder}
            onChange={(e) => set(rows.map((r, j) => (j === i ? e.target.value : r)))}
          />
          {rows.length > 1 && (
            <Button
              type="button"
              variant="ghost"
              aria-label={t("clients.field.remove_uri", "Remove")}
              onClick={() => set(rows.filter((_, j) => j !== i))}
            >
              <X className="size-4" />
            </Button>
          )}
        </div>
      ))}
      <Button type="button" variant="ghost" onClick={() => set([...rows, ""])}>
        <Plus className="size-4" />
        {t("clients.field.add_uri", "Add a URI")}
      </Button>
    </div>
  );
}
