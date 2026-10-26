import { PageHeader } from "@/components/console/page-header";
import { FormCardSkeleton, TableSkeleton } from "@/components/console/skeletons";
import { COLUMNS, PAGES } from "@/lib/pages";

// Shown at once while the page loads (React Suspense fallback).
export default function Loading() {
  return (
    <div aria-busy="true">
      <PageHeader {...PAGES.mfa} />
      <FormCardSkeleton fields={3} />
      <h2 className="mt-8 mb-3 text-[15px] font-semibold">Per role</h2>
      <TableSkeleton columns={COLUMNS.mfaRoles} rows={3} />
      <h2 className="mt-8 mb-3 text-[15px] font-semibold">Per client</h2>
      <TableSkeleton columns={COLUMNS.mfaClients} rows={3} />
    </div>
  );
}
