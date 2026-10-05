"use server";

import { getAllSessionCookieIds } from "@/lib/cookies";
import { clearSession } from "@/lib/server/session";

/**
 * "Sign in with another account" on /denied: ends every session this browser holds on the login host (not only the
 * cookie), so going back to the relying party cannot silently reuse the refused session and land on /denied again.
 */
export async function signOutEverywhereOnThisBrowser(): Promise<{ redirect: string }> {
  const ids = (await getAllSessionCookieIds().catch(() => [])) as string[];
  for (const sessionId of ids.filter(Boolean)) {
    await clearSession({ sessionId }).catch((error) => console.warn("[azdigi] could not end a session on /denied", String(error)));
  }
  return { redirect: "/loginname" };
}
