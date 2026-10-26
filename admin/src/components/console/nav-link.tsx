"use client";

import Link, { useLinkStatus } from "next/link";
import type * as React from "react";
import { usePendingReport } from "@/components/console/navigation-progress";

// next/link that reports its navigation to the progress bar. Every internal
// link of the console uses it (tabs, filters, pages of results...).
//
// useLinkStatus() is `pending` from the click until the new page is shown;
// it only works in a component placed INSIDE the <Link>, hence the small
// <Report /> child. A link whose page was prefetched (production) navigates
// at once and never reports.
// https://nextjs.org/docs/app/api-reference/functions/use-link-status

export function NavLink({ children, ...props }: React.ComponentProps<typeof Link>) {
  return (
    <Link {...props}>
      {children}
      <Report />
    </Link>
  );
}

function Report() {
  const { pending } = useLinkStatus();
  usePendingReport(pending, true); // a link replaces the page's content: dim it meanwhile
  return null;
}
