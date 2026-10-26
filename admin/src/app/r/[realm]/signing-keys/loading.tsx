import { PageHeader } from "@/components/console/page-header";
import { ActionSkeleton, TableSkeleton } from "@/components/console/skeletons";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { COLUMNS, PAGES } from "@/lib/pages";

// Shown at once while the page loads (React Suspense fallback).
export default function Loading() {
  return (
    <div aria-busy="true">
      <PageHeader {...PAGES.signingKeys} actions={<ActionSkeleton />} />
      <div className="mb-4 grid gap-4 md:grid-cols-2">
        {Array.from({ length: 2 }, (_, i) => (
          <Card key={i} className="p-4">
            <Skeleton className="h-4 w-56" />
            <Skeleton className="mt-3 h-9 w-full" />
          </Card>
        ))}
      </div>
      <TableSkeleton columns={COLUMNS.signingKeys} rows={4} />
    </div>
  );
}
