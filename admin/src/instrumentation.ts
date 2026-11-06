// Runs once when the console's server starts (Next.js instrumentation):
// https://nextjs.org/docs/app/guides/instrumentation
export async function register() {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  // The translations (ADMIN_LOCALES_DIR): a wrong file stops the server now.
  const { checkAtStartup } = await import("@/i18n/catalog");
  checkAtStartup();
  // The IdP's metadata, so that the first sign-in does not wait for it. The IdP
  // may not be up yet: the first sign-in then asks, as it would have.
  const { oidcConfig } = await import("@/lib/oidc");
  await Promise.resolve()
    .then(oidcConfig)
    .catch((err: unknown) => {
      console.warn("IdP metadata not read at start-up:", err instanceof Error ? err.message : err);
    });
}
