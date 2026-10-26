import type * as React from "react";
import { cn } from "@/lib/utils";

// DS "Tableau": surface container, border, radius 12; cells 12×16; header
// 12px / 600 uppercase muted; 1px separators; row-hover on hover.
function TableContainer({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="table-container"
      className={cn("overflow-hidden rounded-xl border border-border bg-surface shadow-elevation", className)}
      {...props}
    />
  );
}

function Table({ className, ...props }: React.ComponentProps<"table">) {
  return (
    <div className="relative w-full overflow-x-auto">
      <table data-slot="table" className={cn("w-full border-collapse text-[14px]", className)} {...props} />
    </div>
  );
}

function TableHeader(props: React.ComponentProps<"thead">) {
  return <thead data-slot="table-header" {...props} />;
}

function TableBody(props: React.ComponentProps<"tbody">) {
  return <tbody data-slot="table-body" {...props} />;
}

function TableRow({ className, ...props }: React.ComponentProps<"tr">) {
  return (
    <tr
      data-slot="table-row"
      className={cn("border-b border-border transition-colors last:border-b-0 [tbody_&]:hover:bg-row-hover", className)}
      {...props}
    />
  );
}

function TableHead({ className, ...props }: React.ComponentProps<"th">) {
  return (
    <th
      data-slot="table-head"
      scope="col"
      className={cn(
        "border-b border-border px-4 py-3 text-left text-[12px] font-semibold tracking-wide whitespace-nowrap text-text-muted uppercase",
        className,
      )}
      {...props}
    />
  );
}

function TableCell({ className, ...props }: React.ComponentProps<"td">) {
  return <td data-slot="table-cell" className={cn("px-4 py-3 align-middle", className)} {...props} />;
}

/** Empty state: centred, muted. */
function TableEmpty({ colSpan, children }: { colSpan: number; children: React.ReactNode }) {
  return (
    <tr>
      <td colSpan={colSpan} className="px-4 py-12 text-center text-[13px] text-text-muted">
        {children}
      </td>
    </tr>
  );
}

export { Table, TableBody, TableCell, TableContainer, TableEmpty, TableHead, TableHeader, TableRow };
