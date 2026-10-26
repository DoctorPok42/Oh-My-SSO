import { Logo } from "@/components/console/logo";

// The centred card of the pages seen before signing in (DS login view).
export function AuthCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <main className="grid min-h-dvh place-items-center bg-page px-4 py-10">
      <div className="w-full max-w-[400px]">
        <div className="rounded-xl border border-border bg-surface p-8 shadow-elevation-md">
          <Logo className="mb-7" />
          <h1 className="text-[20px] font-semibold">{title}</h1>
          <div className="mt-2 space-y-5 text-[14px] text-text-secondary">{children}</div>
        </div>
        <p className="mt-5 text-center text-[12px] text-text-muted">Protected by OMSSO · SAML 2.0 / OIDC / MFA</p>
      </div>
    </main>
  );
}
