import { PageHeader } from "@/components/console/page-header";
import { CardSkeleton, FormCardSkeleton } from "@/components/console/skeletons";
import { Skeleton } from "@/components/ui/skeleton";
import { PAGES } from "@/lib/pages";

// Shown at once while the page loads (React Suspense fallback): the four
// policy cards of the form, the save bar, then the realm and infrastructure.
export default function Loading() {
  return (
    <div aria-busy="true">
      <PageHeader {...PAGES.settings} />
      <div className="space-y-4">
        <div className="grid gap-4 lg:grid-cols-2">
          {Array.from({ length: 4 }, (_, i) => (
            <FormCardSkeleton key={i} fields={2} />
          ))}
        </div>
        <Skeleton className="h-9 w-36" />
      </div>
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <CardSkeleton lines={3} />
        <CardSkeleton lines={5} />
      </div>
    </div>
  );
}
