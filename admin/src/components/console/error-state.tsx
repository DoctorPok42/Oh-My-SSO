import { Banner } from "@/components/ui/banner";
import type { ApiFailure } from "@/lib/api-error";

// An Admin API error, shown where the data would have been.
const TITLES: Record<string, string> = {
  forbidden: "You don't have access to this",
  not_found: "Not found",
  not_bootstrapped: "Oh-My-SSO is not set up yet",
  api_unreachable: "The Admin API is unreachable",
  ip_not_allowed: "This console may not call the Admin API",
};

export function ErrorState({ error }: { error: Pick<ApiFailure, "error" | "message"> }) {
  const title = TITLES[error.error] ?? "Something went wrong";
  return (
    <Banner tone={error.error === "forbidden" ? "warning" : "danger"}>
      <p className="font-semibold">{title}</p>
      <p className="mt-0.5">{error.message}</p>
      {error.error === "ip_not_allowed" && (
        <p className="mt-1">Add this server&apos;s address to ADMIN_API_ALLOWED_CIDRS of idp-admin.</p>
      )}
    </Banner>
  );
}
