// AZDIGI: the "this browser verified this user a moment ago" cookie must be something only the server can produce.
//
// After a user proves control of their account (email code, invitation, registration) the login sets a five-minute
// `verificationCheck` cookie; while it matches, that browser may set the account's FIRST password or passkey without
// another code. Upstream computes it as sha256(userId:fingerprintId): no secret, and the fingerprint is a cookie the
// browser's owner writes. Anyone who knew a user id could compute it and set the first credential of any account that
// has none yet (measured on the local stack, 15/11/2026: tools/e2e 33).
//
// Here the value is an HMAC keyed with a secret only the server holds: the login's service token, which is already the
// one secret this process has (no new configuration). Renewing that token only voids cookies that live five minutes.
import crypto from "node:crypto";

function key(env: NodeJS.ProcessEnv): Buffer {
  const secret = env.ZITADEL_SERVICE_USER_TOKEN;
  if (!secret) {
    // fail closed: without a server secret no browser is ever "verified"
    throw new Error("verification check unavailable: no server secret");
  }
  return crypto.createHmac("sha256", "azdigi.verification-check.v1").update(secret).digest();
}

export function verificationCheckValue(userId: string, fingerprintId: string, env: NodeJS.ProcessEnv = process.env): string {
  return crypto.createHmac("sha256", key(env)).update(`${userId}:${fingerprintId}`).digest("hex");
}

export function verificationCheckMatches(cookieValue: string | undefined, userId: string, fingerprintId: string | undefined, env: NodeJS.ProcessEnv = process.env): boolean {
  if (!cookieValue || !userId || !fingerprintId) return false;
  let expected: string;
  try {
    expected = verificationCheckValue(userId, fingerprintId, env);
  } catch {
    return false;
  }
  const a = Buffer.from(cookieValue);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
