import { PageHeader } from "@/components/console/page-header";
import { ActionSkeleton, TableSkeleton } from "@/components/console/skeletons";
import { COLUMNS, PAGES } from "@/lib/pages";

// Shown at once while the page loads (React Suspense fallback).
export default function Loading() {
  return (
    <div aria-busy="true">
      <PageHeader {...PAGES.clientScopes} actions={<ActionSkeleton />} />
      <TableSkeleton columns={COLUMNS.clientScopes} />
    </div>
  );
}
