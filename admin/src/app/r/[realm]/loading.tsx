import { Skeleton } from "@/components/ui/skeleton";
import { getI18n } from "@/i18n/server";

// Shown at once while a tab's data loads (React Suspense via loading.tsx).
export default async function Loading() {
  const { t } = await getI18n();
  return (
    <div aria-busy="true" aria-label={t("common.loading", "Loading")}>
      <Skeleton className="h-7 w-48" />
      <Skeleton className="mt-2 h-4 w-80" />
      <div className="mt-8 space-y-3 rounded-xl border border-border bg-surface p-4">
        {Array.from({ length: 6 }, (_, i) => (
          <Skeleton key={i} className="h-9 w-full" />
        ))}
      </div>
    </div>
  );
}
