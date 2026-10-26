import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableContainer, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { cn } from "@/lib/utils";

// Skeletons: grey shapes where the content will be, while it loads. They
// copy the real layout (same table headers, same card grid) so nothing
// jumps when the data arrives. `aria-busy` tells screen readers the area is
// loading; the shapes themselves are hidden from them (Skeleton is aria-hidden).

// Varied widths: identical bars look like a broken page, not like rows.
const WIDTHS = ["w-3/4", "w-1/2", "w-2/3", "w-5/12", "w-7/12", "w-1/3"];

/** A table with its real column headers and grey rows. */
export function TableSkeleton({
  columns,
  rows = 6,
  className,
}: {
  columns: readonly string[];
  rows?: number;
  className?: string;
}) {
  return (
    <TableContainer aria-busy="true" aria-label="Loading" className={className}>
      <Table>
        <TableHeader>
          <TableRow>
            {columns.map((c, i) => (
              <TableHead key={i}>{c || <span className="sr-only">Actions</span>}</TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {Array.from({ length: rows }, (_, r) => (
            <TableRow key={r}>
              {columns.map((c, i) => (
                <TableCell key={i}>
                  {c === "" ? (
                    <Skeleton className="ml-auto h-7 w-14" />
                  ) : (
                    <Skeleton className={cn("h-4", WIDTHS[(r + i) % WIDTHS.length])} />
                  )}
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

/** A row of filter buttons (segmented control) or a search bar. */
export function FilterSkeleton({ className }: { className?: string }) {
  return <Skeleton className={cn("mb-4 h-9 w-72", className)} />;
}

/** The button(s) on the right of a page title. */
export function ActionSkeleton() {
  return <Skeleton className="h-9 w-32" />;
}

/** A card with a title and a few lines. */
export function CardSkeleton({ lines = 3, className }: { lines?: number; className?: string }) {
  return (
    <Card aria-busy="true" className={className}>
      <Skeleton className="h-5 w-40" />
      <div className="mt-4 space-y-3">
        {Array.from({ length: lines }, (_, i) => (
          <Skeleton key={i} className={cn("h-4", WIDTHS[i % WIDTHS.length])} />
        ))}
      </div>
    </Card>
  );
}

/** A form card: title, description, labelled fields. */
export function FormCardSkeleton({ fields = 3, className }: { fields?: number; className?: string }) {
  return (
    <Card aria-busy="true" className={className}>
      <Skeleton className="h-5 w-40" />
      <Skeleton className="mt-2 h-4 w-64" />
      <div className="mt-5 space-y-4">
        {Array.from({ length: fields }, (_, i) => (
          <div key={i} className="space-y-2">
            <Skeleton className="h-4 w-32" />
            <Skeleton className="h-9 w-full max-w-sm" />
          </div>
        ))}
      </div>
    </Card>
  );
}
