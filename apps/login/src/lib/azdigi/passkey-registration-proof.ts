// AZDIGI: a passkey registration that was started with the emailed registration code (no session) may only be
// finished by the browser that started it that way. Without this, a registration started from a session could be
// finished later through the session-less path, after the checks on the session path would refuse it, and anyone who
// learned a passkey id could finish a registration for that user from another browser.
//
// The proof is a short-lived cookie only the server can produce (upstream's signed proof, own HKDF purpose), bound to
// the user and to the one registration. Its expiry is enforced on the server.
import { setBrowserCookie } from "@/lib/server/fingerprint";
import { createSignedProof, isSignedProofValid } from "@/lib/server/signed-proof";
import { cookies } from "next/headers";

export const PASSKEY_REGISTRATION_COOKIE = "azdigi.passkeyRegistration";
export const PASSKEY_REGISTRATION_TTL_SECONDS = 600;

export function passkeyRegistrationProof(userId: string, passkeyId: string, now: number = Date.now()): string {
  return createSignedProof("azdigi-passkey-registration", [userId, passkeyId], PASSKEY_REGISTRATION_TTL_SECONDS, now);
}

export function isPasskeyRegistrationProofValid(
  value: string | undefined,
  userId: string | undefined,
  passkeyId: string | undefined,
  now: number = Date.now(),
): boolean {
  return isSignedProofValid("azdigi-passkey-registration", value, [userId, passkeyId], now);
}

export async function rememberCodeStartedRegistration(userId: string, passkeyId: string) {
  await setBrowserCookie(
    PASSKEY_REGISTRATION_COOKIE,
    passkeyRegistrationProof(userId, passkeyId),
    PASSKEY_REGISTRATION_TTL_SECONDS,
  );
}

export async function wasStartedWithCode(userId: string, passkeyId: string): Promise<boolean> {
  const store = await cookies();
  return isPasskeyRegistrationProofValid(store.get(PASSKEY_REGISTRATION_COOKIE)?.value, userId, passkeyId);
}
