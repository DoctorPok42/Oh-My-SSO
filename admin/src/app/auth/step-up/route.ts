import type { NextRequest } from "next/server";
import { redirectToIdP } from "@/lib/login";

// GET /auth/step-up?returnTo=... -> sign in again, password and second factor,
// even though the IdP session is alive (prompt=login, max_age=0). Every change
// in the console requires a second factor verified in the last minutes
// (step-up, RFC 9470); the Admin API answers 403 step_up_required otherwise.
export async function GET(req: NextRequest) {
  return redirectToIdP(req.nextUrl.searchParams.get("returnTo"), true);
}
