"use client";

import type * as React from "react";
import { useNavigate } from "@/components/console/navigation-progress";

// A search / filter form (method GET: the filters end up in the URL, which
// can be bookmarked or shared).
//
// Without JavaScript it is a plain HTML form: the browser loads the URL.
// With JavaScript the console navigates itself: the header and the tabs
// stay, the progress bar shows, and only the results are reloaded. Empty
// fields are left out of the URL.
export function SearchForm({
  action,
  children,
  ...props
}: Omit<React.ComponentProps<"form">, "action" | "method" | "onSubmit"> & { action: string }) {
  const nav = useNavigate();
  return (
    <form
      {...props}
      action={action}
      method="get"
      onSubmit={(e) => {
        e.preventDefault();
        nav.push(searchHref(action, new FormData(e.currentTarget)));
      }}
    >
      {children}
    </form>
  );
}

/** The URL a GET form leads to: its action, plus the non-empty fields (trimmed). */
export function searchHref(action: string, fields: Iterable<[string, FormDataEntryValue]>): string {
  const q = new URLSearchParams();
  for (const [k, v] of fields) {
    if (typeof v === "string" && v.trim() !== "") q.set(k, v.trim());
  }
  const qs = q.toString();
  return qs ? `${action}?${qs}` : action;
}
