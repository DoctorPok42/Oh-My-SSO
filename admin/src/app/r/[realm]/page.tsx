import { redirect } from "next/navigation";

// /r/demo -> /r/demo/dashboard
export default async function RealmIndex({ params }: { params: Promise<{ realm: string }> }) {
  redirect(`/r/${encodeURIComponent((await params).realm)}/dashboard`);
}
