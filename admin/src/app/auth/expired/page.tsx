import { AuthCard } from "@/components/console/auth-card";
import { buttonVariants } from "@/components/ui/button";
import { safeReturnTo } from "@/lib/return-to";
import { cn } from "@/lib/utils";

export const metadata = { title: "Session ended" };

// The Admin API refused the token (session revoked by another admin, signed
// out elsewhere, account disabled...): ask before going to the IdP again.
export default async function Expired({ searchParams }: { searchParams: Promise<{ returnTo?: string }> }) {
  const returnTo = safeReturnTo((await searchParams).returnTo, "/");
  return (
    <AuthCard title="Your session ended">
      <p>You were signed out: the session expired, was revoked, or your account changed. Sign in again to continue.</p>
      <a
        href={`/auth/login?returnTo=${encodeURIComponent(returnTo)}`}
        className={cn(buttonVariants({ size: "md" }), "w-full")}
      >
        Sign in again
      </a>
    </AuthCard>
  );
}
