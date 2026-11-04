import Link from "next/link";
import { AuthCard } from "@/components/console/auth-card";
import { buttonVariants } from "@/components/ui/button";
import { getI18n } from "@/i18n/server";
import { cn } from "@/lib/utils";

export async function generateMetadata() {
  const { t } = await getI18n();
  return { title: t("not_found.title", "Not found") };
}

export default async function NotFound() {
  const { t } = await getI18n();
  return (
    <AuthCard title={t("not_found.title", "Not found")}>
      <p>{t("not_found.text", "This page or realm does not exist, or it was renamed.")}</p>
      <Link href="/" className={cn(buttonVariants({ size: "md" }), "w-full")}>
        {t("not_found.back", "Back to the console")}
      </Link>
    </AuthCard>
  );
}
