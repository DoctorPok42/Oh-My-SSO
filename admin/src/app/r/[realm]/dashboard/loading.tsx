import { CardSkeleton } from "@/components/console/skeletons";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { PAGES } from "@/lib/pages";

// Shown at once while the dashboard loads (loading.tsx = a React Suspense
// fallback for this page): same grid as the page, grey shapes for the numbers.
// https://nextjs.org/docs/app/api-reference/file-conventions/loading
export default function Loading() {
  return (
    <div aria-busy="true">
      <div className="mb-6">
        <h1 className="text-[22px] font-semibold">{PAGES.dashboard.title}</h1>
        <Skeleton className="mt-2 h-4 w-72" />
      </div>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }, (_, i) => (
          <div key={i} className="rounded-xl border border-border bg-surface p-5 shadow-elevation">
            <Skeleton className="h-4 w-28" />
            <Skeleton className="mt-3 h-7 w-16" />
          </div>
        ))}
      </div>
      <Card className="mt-4 py-4">
        <div className="flex flex-wrap items-center gap-6">
          <Skeleton className="h-4 w-24" />
          {Array.from({ length: 5 }, (_, i) => (
            <Skeleton key={i} className="h-5 w-32" />
          ))}
        </div>
      </Card>
      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <CardSkeleton lines={6} className="lg:col-span-2" />
        <div className="space-y-4">
          <CardSkeleton lines={2} />
          <CardSkeleton lines={2} />
        </div>
      </div>
      <CardSkeleton lines={2} className="mt-4" />
    </div>
  );
}
