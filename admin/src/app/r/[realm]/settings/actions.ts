"use server";

import { act, api, apiPath } from "@/lib/api";
import type { SettingsPatch } from "@/lib/settings-form";
import type { Settings } from "@/lib/types";

export async function updateSettings(realm: string, body: SettingsPatch) {
  return act(() => api<Settings>(apiPath(["realms", realm, "settings"]), { method: "PATCH", body }));
}

export async function sendTestEmail(realm: string, to: string) {
  return act(() =>
    api<{ status: string; to: string }>(apiPath(["realms", realm, "settings", "test-email"]), {
      method: "POST",
      body: { to },
    }),
  );
}
