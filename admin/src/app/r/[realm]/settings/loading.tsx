import { PageHeader } from "@/components/console/page-header";
import { CardSkeleton, FormCardSkeleton } from "@/components/console/skeletons";
import { Skeleton } from "@/components/ui/skeleton";
import { PAGES } from "@/lib/pages";

// Shown at once while the page loads (React Suspense fallback). The sub-page
// is not known here: the first one's cards and the save bar stand for all.
export default function Loading() {
  return (
    <div aria-busy="true">
      <PageHeader {...PAGES.settingsGeneral} />
      <div className="space-y-4">
        <div className="grid gap-4 lg:grid-cols-2">
          <CardSkeleton lines={3} />
          <FormCardSkeleton fields={1} />
          <CardSkeleton lines={5} className="lg:col-span-2" />
        </div>
        <Skeleton className="h-9 w-36" />
      </div>
    </div>
  );
}
