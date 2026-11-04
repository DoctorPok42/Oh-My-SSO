import { redirect } from "next/navigation";
import { AuthCard } from "@/components/console/auth-card";
import { Banner } from "@/components/ui/banner";
import { buttonVariants } from "@/components/ui/button";
import { m, type Msg } from "@/i18n";
import { getI18n } from "@/i18n/server";
import { getSession } from "@/lib/auth";
import { env } from "@/lib/env";
import { cn } from "@/lib/utils";

// "/": the console's front door. Signed in: straight to the default realm.
// Otherwise a sign-in button (and the reason of a failed sign-in).

const ERRORS: Record<string, Msg> = {
  access_denied: m(
    "home.error.access_denied",
    "Your account may not open the admin console: it must belong to the admins or auditors group of the master realm.",
  ),
  signin_expired: m(
    "home.error.signin_expired",
    "The sign-in took too long or was started in another tab. Please try again.",
  ),
  signin_failed: m(
    "home.error.signin_failed",
    "The sign-in could not be completed. Try again; if it keeps failing, check the console's logs.",
  ),
  idp_unreachable: m(
    "home.error.idp_unreachable",
    "The identity provider did not answer. Is idp running, and is OIDC_ISSUER right?",
  ),
};

export default async function Home({ searchParams }: { searchParams: Promise<{ error?: string }> }) {
  if (await getSession()) redirect(`/r/${env().DEFAULT_REALM}/dashboard`);
  const { error } = await searchParams;
  const { t, tm } = await getI18n();
  const message = error ? tm(ERRORS[error] ?? ERRORS.signin_failed!) : undefined;
  return (
    <AuthCard title={t("home.title", "Admin console")}>
      <p>{t("home.description", "Manage realms, applications, users and security policies of Oh-My-SSO.")}</p>
      {message && <Banner tone="danger">{message}</Banner>}
      {/* A plain link, not next/link: /auth/login leaves the console for the IdP. */}
      <a href="/auth/login" className={cn(buttonVariants({ size: "md" }), "w-full")}>
        {t("home.sign_in", "Sign in")}
      </a>
      <p className="text-[12px] text-text-muted">
        {t("home.sign_in_hint", "You will sign in on the identity provider with your password and your second factor.")}
      </p>
    </AuthCard>
  );
}
