import { PageHeader } from "@/components/console/page-header";
import { FilterSkeleton, TableSkeleton } from "@/components/console/skeletons";
import { Skeleton } from "@/components/ui/skeleton";
import { COLUMNS, PAGES } from "@/lib/pages";

// Shown at once while the page loads (React Suspense fallback).
export default function Loading() {
  return (
    <div aria-busy="true">
      <PageHeader {...PAGES.audit} />
      <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
        <FilterSkeleton className="mb-0 w-60" />
        <Skeleton className="h-9 w-full max-w-[640px]" />
      </div>
      <TableSkeleton columns={COLUMNS.audit} rows={10} />
    </div>
  );
}
