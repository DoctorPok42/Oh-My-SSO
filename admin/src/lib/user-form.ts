// The user drawer's helpers (pure, unit-tested in tests/user-form.test.ts).

/**
 * Profile changes for PATCH /users/{id}: new and changed keys with their
 * value, removed keys as null (the API merges the profile).
 */
export function profilePatch(
  before: Record<string, unknown>,
  displayName: string,
  extra: { key: string; value: string }[],
): Record<string, string | null> {
  const next: Record<string, string> = {};
  if (displayName.trim()) next.name = displayName.trim();
  for (const { key, value } of extra) if (key.trim()) next[key.trim()] = value;
  const patch: Record<string, string | null> = {};
  for (const [k, v] of Object.entries(next)) if (before[k] !== v) patch[k] = v;
  for (const k of Object.keys(before)) if (!(k in next)) patch[k] = null;
  return patch;
}

/** Same members, any order. */
export function sameSet(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((x) => b.includes(x));
}
