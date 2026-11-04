import { Banner } from "@/components/ui/banner";
import { m, type Msg } from "@/i18n";
import { getI18n } from "@/i18n/server";
import type { ApiFailure } from "@/lib/api-error";

// An Admin API error, shown where the data would have been (Server
// Components only).
const TITLES: Record<string, Msg> = {
  forbidden: m("error_state.forbidden", "You don't have access to this"),
  not_found: m("error_state.not_found", "Not found"),
  not_bootstrapped: m("error_state.not_bootstrapped", "Oh-My-SSO is not set up yet"),
  api_unreachable: m("error_state.api_unreachable", "The Admin API is unreachable"),
  ip_not_allowed: m("error_state.ip_not_allowed", "This console may not call the Admin API"),
};

export async function ErrorState({ error }: { error: Pick<ApiFailure, "error" | "message"> }) {
  const { t, tm } = await getI18n();
  const known = TITLES[error.error];
  const title = known ? tm(known) : t("error_state.other", "Something went wrong");
  return (
    <Banner tone={error.error === "forbidden" ? "warning" : "danger"}>
      <p className="font-semibold">{title}</p>
      <p className="mt-0.5">{error.message}</p>
      {error.error === "ip_not_allowed" && (
        <p className="mt-1">
          {t("error_state.ip_hint", "Add this server's address to ADMIN_API_ALLOWED_CIDRS of idp-admin.")}
        </p>
      )}
    </Banner>
  );
}
