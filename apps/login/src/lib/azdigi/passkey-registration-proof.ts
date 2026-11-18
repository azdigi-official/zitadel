// AZDIGI: a passkey registration that was started with the emailed registration code (no session) may only be
// finished by the browser that started it that way. Without this, a registration started from a session could be
// finished later through the session-less path, after the checks on the session path would refuse it.
//
// The proof is a short-lived cookie only the server can produce (the same keyed value as the verified-browser cookie,
// lib/azdigi/verification-check.ts), bound to the user and to the one registration.
import { cookies } from "next/headers";
import { verificationCheckMatches, verificationCheckValue } from "./verification-check";

const COOKIE = "azdigi.passkeyRegistration";
const scope = (passkeyId: string) => `passkey-registration:${passkeyId}`;

export async function rememberCodeStartedRegistration(userId: string, passkeyId: string) {
  const store = await cookies();
  store.set(COOKIE, verificationCheckValue(userId, scope(passkeyId)), { httpOnly: true, sameSite: "lax", path: "/", maxAge: 600 });
}

export async function wasStartedWithCode(userId: string, passkeyId: string): Promise<boolean> {
  const store = await cookies();
  return verificationCheckMatches(store.get(COOKIE)?.value, userId, scope(passkeyId));
}
