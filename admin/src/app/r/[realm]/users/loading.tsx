import { PageHeader } from "@/components/console/page-header";
import { ActionSkeleton, FilterSkeleton, TableSkeleton } from "@/components/console/skeletons";
import { COLUMNS, PAGES } from "@/lib/pages";

// Shown at once while the page loads (React Suspense fallback). The sub-page
// (users, roles, groups, permissions) is not known here: the users table's
// shape stands for all of them.
export default function Loading() {
  return (
    <div aria-busy="true">
      <PageHeader {...PAGES.users} actions={<ActionSkeleton />} />
      <FilterSkeleton className="w-[30rem] max-w-full" />
      <TableSkeleton columns={COLUMNS.users} rows={8} />
    </div>
  );
}
