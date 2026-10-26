import { redirect } from "next/navigation";
import { AuthCard } from "@/components/console/auth-card";
import { Banner } from "@/components/ui/banner";
import { buttonVariants } from "@/components/ui/button";
import { getSession } from "@/lib/auth";
import { env } from "@/lib/env";
import { cn } from "@/lib/utils";

// "/": the console's front door. Signed in: straight to the default realm.
// Otherwise a sign-in button (and the reason of a failed sign-in).

const ERRORS: Record<string, string> = {
  access_denied:
    "Your account may not open the admin console: it must belong to the admins or auditors group of the master realm.",
  signin_expired: "The sign-in took too long or was started in another tab. Please try again.",
  signin_failed: "The sign-in could not be completed. Try again; if it keeps failing, check the console's logs.",
  idp_unreachable: "The identity provider did not answer. Is idp running, and is OIDC_ISSUER right?",
};

export default async function Home({ searchParams }: { searchParams: Promise<{ error?: string }> }) {
  if (await getSession()) redirect(`/r/${env().DEFAULT_REALM}/dashboard`);
  const { error } = await searchParams;
  const message = error ? (ERRORS[error] ?? ERRORS.signin_failed) : undefined;
  return (
    <AuthCard title="Admin console">
      <p>Manage realms, applications, users and security policies of Oh-My-SSO.</p>
      {message && <Banner tone="danger">{message}</Banner>}
      {/* A plain link, not next/link: /auth/login leaves the console for the IdP. */}
      <a href="/auth/login" className={cn(buttonVariants({ size: "md" }), "w-full")}>
        Sign in
      </a>
      <p className="text-[12px] text-text-muted">
        You will sign in on the identity provider with your password and your second factor.
      </p>
    </AuthCard>
  );
}
