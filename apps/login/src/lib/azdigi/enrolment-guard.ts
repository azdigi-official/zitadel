// AZDIGI: who may add a way to sign in (passkey, TOTP, security key, IdP link, email / SMS code) to an account from a
// session.
//
// A new strong factor can afterwards satisfy the login policy on its own, so adding one is only allowed from a session
// the policy already accepts. Otherwise somebody who knows a staff member's password could enrol their own passkey or
// authenticator and walk past the forced second factor.
//
// One exception, the first set-up: a session that proved a first factor for an account with no strong factor at all
// (staff setting up the forced second factor, a new account). There is nothing to walk past yet.
//
// Upstream (v4.20.5, GHSA-qqv8-37gw-ww2q) adds two rules of its own, both applied here as well: a second factor the
// user configured must be verified in the session (unless it was a user-verified passkey sign-in), and the
// organisation's login settings must allow the kind of authenticator being added.
import {
  getSetupAuthorizationError,
  PASSKEYS_NOT_ALLOWED_ERROR,
  SECOND_FACTOR_NOT_ALLOWED_ERROR,
  SECOND_FACTOR_REQUIRED_ERROR,
  SetupMethod,
} from "@/lib/server/enrollment-guard";
import { checkSessionPolicy, hasVerifiedSecondFactor, SECOND_FACTOR_METHODS } from "@/lib/server/session";
import { checkUserVerification } from "@/lib/server/verify-helper";
import { getLoginSettings, ServiceConfig } from "@/lib/server/zitadel";
import { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { PasskeysType, SecondFactorType } from "@zitadel/proto/zitadel/settings/v2/login_settings_pb";
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
 * What is being added: upstream's setup methods plus "idp" (linking an external identity).
 * - passkey, totp, u2f, idp: strong, each can satisfy the login policy (or its second factor) on its own;
 * - otp_email, otp_sms: a code sent to the account's own verified address or phone.
 */
export type EnrolmentMethod = SetupMethod | "idp";

const SECOND_FACTOR_SETTING: Record<"totp" | "u2f", SecondFactorType> = {
  totp: SecondFactorType.TOTP,
  u2f: SecondFactorType.U2F,
};

/** Upstream's rule: a configured second factor must be verified, unless the session signed in with a user-verified passkey. */
function secondFactorRequirementError(session: Session, registered: AuthenticationMethodType[]): string | null {
  if (session.factors?.webAuthN?.verifiedAt && session.factors.webAuthN.userVerified) {
    return null;
  }
  const hasSecondFactor = registered.some((method) => SECOND_FACTOR_METHODS.includes(method));
  return hasSecondFactor && !hasVerifiedSecondFactor(session, registered) ? SECOND_FACTOR_REQUIRED_ERROR : null;
}

/** Upstream's rule: the organisation's login settings (read fresh) must allow the authenticator type. */
async function settingsError(serviceConfig: ServiceConfig, session: Session, method: "passkey" | "totp" | "u2f") {
  const loginSettings = await getLoginSettings({
    serviceConfig,
    organization: session.factors?.user?.organizationId,
    fresh: true,
  });
  if (!loginSettings) {
    return ENROLMENT_REFUSED;
  }
  if (method === "passkey") {
    return loginSettings.passkeysType === PasskeysType.ALLOWED ? null : PASSKEYS_NOT_ALLOWED_ERROR;
  }
  return loginSettings.secondFactors.includes(SECOND_FACTOR_SETTING[method]) ? null : SECOND_FACTOR_NOT_ALLOWED_ERROR;
}

/**
 * The one gate every enrolment entry point calls, in place of upstream's getEnrollmentAuthorizationError /
 * getSetupAuthorizationError. Returns null when allowed, otherwise the message to show. Every rule must hold:
 *
 * Strong methods (passkey, TOTP, security key, IdP link)
 *  1. the session satisfies the organisation's login policy, or it is the first set-up (first factor proven, no strong
 *     factor on the account), or upstream's onboarding path (no sign-in method at all, verified in this browser);
 *  2. outside onboarding: upstream's rule, a second factor the user configured is verified in this session (an
 *     OTP-first customer who signed in with the emailed code has verified the configured OTP_EMAIL);
 *  3. passkey, TOTP, security key: the organisation's settings allow that authenticator (IdPs: checked by the IdP flow).
 *
 * Codes (email, SMS): upstream's rule unchanged (getSetupAuthorizationError).
 */
export async function enrolmentAuthorizationError({
  serviceConfig,
  session,
  userId,
  method,
}: {
  serviceConfig: ServiceConfig;
  session: Session | undefined;
  userId: string;
  method: EnrolmentMethod;
}): Promise<string | null> {
  if (!session || session.factors?.user?.id !== userId) {
    return ENROLMENT_REFUSED;
  }

  if (method === "otp_email" || method === "otp_sms") {
    return getSetupAuthorizationError({ serviceConfig, session, userId, method });
  }

  // unreadable methods fail closed
  const registered = await registeredMethodsOf(serviceConfig, userId);
  if (!registered) {
    return ENROLMENT_REFUSED;
  }

  if (await mayEnrolSignInMethod({ serviceConfig, session })) {
    const secondFactorError = secondFactorRequirementError(session, registered);
    if (secondFactorError) {
      return secondFactorError;
    }
  } else if (!(registered.length === 0 && (await checkUserVerification(userId)))) {
    return ENROLMENT_REFUSED;
  }

  return method === "idp" ? null : settingsError(serviceConfig, session, method);
}
