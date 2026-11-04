// For the pages (Server Components) that show a <Pagination />. Not in
// components/console/pagination.tsx: that is a "use client" module, whose
// functions cannot be called on the server (only its components rendered).

/** offset from ?offset=, never negative. */
export function offsetParam(v: string | undefined): number {
  const n = Number(v);
  return Number.isInteger(n) && n > 0 ? n : 0;
}
