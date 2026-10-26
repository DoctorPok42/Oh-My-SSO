import { PageHeader } from "@/components/console/page-header";
import { ActionSkeleton, FilterSkeleton, TableSkeleton } from "@/components/console/skeletons";
import { COLUMNS, PAGES } from "@/lib/pages";

// Shown at once while the page loads (React Suspense fallback).
export default function Loading() {
  return (
    <div aria-busy="true">
      <PageHeader {...PAGES.clients} actions={<ActionSkeleton />} />
      <FilterSkeleton className="w-60" />
      <TableSkeleton columns={COLUMNS.clients} />
    </div>
  );
}
