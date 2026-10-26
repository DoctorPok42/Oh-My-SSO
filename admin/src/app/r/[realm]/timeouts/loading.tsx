import { PageHeader } from "@/components/console/page-header";
import { TableSkeleton } from "@/components/console/skeletons";
import { COLUMNS, PAGES } from "@/lib/pages";

// Shown at once while the page loads (React Suspense fallback).
export default function Loading() {
  return (
    <div aria-busy="true">
      <PageHeader {...PAGES.timeouts} />
      <TableSkeleton columns={COLUMNS.timeouts} rows={4} />
    </div>
  );
}
