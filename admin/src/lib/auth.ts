import "server-only";
import { cookies } from "next/headers";
import { env, isHttps } from "@/lib/env";
import { cookieNames, isSession, readChunked, unseal, type Session } from "@/lib/session";

/** The signed-in admin's session, from the encrypted cookie; null if absent or invalid. */
export async function getSession(): Promise<Session | null> {
  const jar = await cookies();
  const raw = readChunked(jar.getAll(), cookieNames(isHttps()).session);
  const session = await unseal<Session>(raw, env().SESSION_SECRET, "session");
  return isSession(session) ? session : null;
}
