// AZDIGI: who may add a way to sign in (passkey, TOTP, security key) to an account from a session.
//
// A new strong factor can afterwards satisfy the login policy on its own, so adding one is only allowed from a session
// the policy already accepts. Otherwise somebody who knows a staff member's password could enrol their own passkey or
// authenticator and walk past the forced second factor.
//
// One exception, the first set-up: a session that proved a first factor for an account with no strong factor at all
// (staff setting up the forced second factor, a new account). There is nothing to walk past yet.
import { getEnrollmentAuthorizationError } from "@/lib/server/enrollment-guard";
import { checkSessionPolicy } from "@/lib/server/session";
import { checkUserVerification } from "@/lib/server/verify-helper";
import { ServiceConfig } from "@/lib/server/zitadel";
import { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { registeredMethodsOf } from "./issue";
import { hasVerifiedFirstFactor } from "./policy";

const STRONG = [AuthenticationMethodType.TOTP, AuthenticationMethodType.U2F, AuthenticationMethodType.PASSKEY];

export async function mayEnrolSignInMethod({
  serviceConfig,
  session,
}: {
  serviceConfig: ServiceConfig;
  session: Session | undefined;
}): Promise<boolean> {
  const user = session?.factors?.user;
  if (!session || !user?.id) return false;

  const verdict = await checkSessionPolicy({ serviceConfig, session });
  if (verdict.ok) return true;

  // only a live session that lacks nothing but the second factor; an expired or otherwise refused one gets nothing
  if (verdict.reason === "second-factor-missing" && hasVerifiedFirstFactor(session)) {
    // unreadable methods fail closed
    const registered = await registeredMethodsOf(serviceConfig, user.id);
    if (registered && !STRONG.some((method) => registered.includes(method))) return true;
  }

  console.warn("[azdigi] sign-in method enrolment refused: the session does not satisfy the login policy", {
    userId: user.id,
    organizationId: user.organizationId,
    reason: verdict.reason,
  });
  return false;
}

/** Shown by the server actions that refuse; the pages redirect to the sign-in instead. */
export const ENROLMENT_REFUSED = "Sign in completely before adding a sign-in method.";

/**
 * What a sign-in method being added can do afterwards:
 * - "strong": a passkey, an authenticator app, a security key or a linked IdP, each of which can satisfy the login
 *   policy (or its second factor) on its own;
 * - "code": an email or SMS code sent to the account's own verified address or phone.
 */
export type EnrolmentKind = "strong" | "code";

/**
 * The one gate every enrolment entry point calls, in place of upstream's getEnrollmentAuthorizationError. Returns null
 * when allowed, otherwise the message to show.
 *
 * Upstream allows any session with a verified primary factor (password, passkey, IdP) to add any factor, so a known
 * staff password would be enough to enrol a passkey or authenticator and walk past the forced second factor. For
 * strong methods this requires mayEnrolSignInMethod instead. Upstream's onboarding path is kept: an account with no
 * sign-in method at all, verified in this browser (signed verification check), may set up its first one. Codes keep
 * upstream's rule.
 */
export async function enrolmentAuthorizationError({
  serviceConfig,
  session,
  userId,
  kind,
}: {
  serviceConfig: ServiceConfig;
  session: Session | undefined;
  userId: string;
  kind: EnrolmentKind;
}): Promise<string | null> {
  if (!session || session.factors?.user?.id !== userId) {
    return ENROLMENT_REFUSED;
  }

  if (kind === "code") {
    return getEnrollmentAuthorizationError({ serviceConfig, session, userId });
  }

  if (await mayEnrolSignInMethod({ serviceConfig, session })) {
    return null;
  }

  // unreadable methods fail closed
  const registered = await registeredMethodsOf(serviceConfig, userId);
  if (registered && registered.length === 0 && (await checkUserVerification(userId))) {
    return null;
  }

  return ENROLMENT_REFUSED;
}
