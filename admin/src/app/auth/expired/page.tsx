import { AuthCard } from "@/components/console/auth-card";
import { buttonVariants } from "@/components/ui/button";
import { getI18n } from "@/i18n/server";
import { safeReturnTo } from "@/lib/return-to";
import { cn } from "@/lib/utils";

export async function generateMetadata() {
  const { t } = await getI18n();
  return { title: t("expired.page_title", "Session ended") };
}

// The Admin API refused the token (session revoked by another admin, signed
// out elsewhere, account disabled...): ask before going to the IdP again.
export default async function Expired({ searchParams }: { searchParams: Promise<{ returnTo?: string }> }) {
  const returnTo = safeReturnTo((await searchParams).returnTo, "/");
  const { t } = await getI18n();
  return (
    <AuthCard title={t("expired.title", "Your session ended")}>
      <p>
        {t(
          "expired.text",
          "You were signed out: the session expired, was revoked, or your account changed. Sign in again to continue.",
        )}
      </p>
      <a
        href={`/auth/login?returnTo=${encodeURIComponent(returnTo)}`}
        className={cn(buttonVariants({ size: "md" }), "w-full")}
      >
        {t("expired.sign_in", "Sign in again")}
      </a>
    </AuthCard>
  );
}
