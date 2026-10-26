import { Search } from "lucide-react";
import { SearchForm } from "@/components/console/search-form";

// Header search: users of the current realm (name, username, e-mail). A GET
// form (SearchForm): it works before JavaScript loads, and the URL can be shared.
export function SearchBox({ realm }: { realm: string }) {
  return (
    <SearchForm
      action={`/r/${encodeURIComponent(realm)}/users`}
      role="search"
      className="relative hidden w-56 lg:block"
    >
      <label htmlFor="global-search" className="sr-only">
        Search users
      </label>
      <Search
        className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-text-muted"
        aria-hidden
      />
      <input
        id="global-search"
        name="q"
        type="search"
        placeholder="Search users…"
        className="h-9 w-full rounded-md border border-input-border bg-input-bg pr-3 pl-9 text-[13px] outline-none placeholder:text-text-muted focus:border-accent focus:ring-[3px] focus:ring-accent-soft"
      />
    </SearchForm>
  );
}
