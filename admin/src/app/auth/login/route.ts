import type { NextRequest } from "next/server";
import { redirectToIdP } from "@/lib/login";

// GET /auth/login?returnTo=/r/demo/clients -> the IdP's sign-in page.
export async function GET(req: NextRequest) {
  return redirectToIdP(req.nextUrl.searchParams.get("returnTo"), false);
}
