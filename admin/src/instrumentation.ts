// Runs once when the console's server starts (Next.js instrumentation):
// https://nextjs.org/docs/app/guides/instrumentation
export async function register() {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  // The translations (ADMIN_LOCALES_DIR): a wrong file stops the server now.
  const { checkAtStartup } = await import("@/i18n/catalog");
  checkAtStartup();
}
