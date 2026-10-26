import Link from "next/link";
import { AuthCard } from "@/components/console/auth-card";
import { buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export const metadata = { title: "Not found" };

export default function NotFound() {
  return (
    <AuthCard title="Not found">
      <p>This page or realm does not exist, or it was renamed.</p>
      <Link href="/" className={cn(buttonVariants({ size: "md" }), "w-full")}>
        Back to the console
      </Link>
    </AuthCard>
  );
}
