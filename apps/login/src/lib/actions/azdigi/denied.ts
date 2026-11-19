"use server";

import { clearSession } from "@/lib/actions/session";
import { getAllSessionCookieIds } from "@/lib/server/cookies";
import { createLogger } from "@/lib/server/logger";

const logger = createLogger("azdigi-denied");

/**
 * "Sign in with another account" on /denied: ends every session this browser holds on the login host (not only the
 * cookie), so going back to the relying party cannot silently reuse the refused session and land on /denied again.
 */
export async function signOutEverywhereOnThisBrowser(): Promise<{ redirect: string }> {
  const ids = (await getAllSessionCookieIds().catch(() => [])) as string[];
  for (const sessionId of ids.filter(Boolean)) {
    await clearSession({ sessionId }).catch((error) =>
      logger.warn("could not end a session on /denied", { error: String(error) }),
    );
  }
  return { redirect: "/loginname" };
}
