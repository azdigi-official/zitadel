import "server-only";

import { emailVerificationVerdict, registeredMethodsOf } from "@/lib/azdigi/issue";
import { isOtpFirstOrg } from "@/lib/azdigi/org-lookup";
import { sessionInScopedOrg } from "@/lib/azdigi/org-scope";
import { assertSessionSatisfiesPolicy, PolicyVerdict } from "@/lib/azdigi/policy";
import { getMostRecentCookieWithLoginname, getSessionCookieById } from "@/lib/server/cookies";
import { getLoginSettings, getSession, ServiceConfig } from "@/lib/server/zitadel";
import { Timestamp, timestampDate } from "@zitadel/client";
import { AuthRequest } from "@zitadel/proto/zitadel/oidc/v2/authorization_pb";
import { SAMLRequest } from "@zitadel/proto/zitadel/saml/v2/authorization_pb";
import { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { GetSessionResponse } from "@zitadel/proto/zitadel/session/v2/session_service_pb";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";

type LoadMostRecentSessionParams = {
  serviceConfig: ServiceConfig;
  sessionParams: {
    loginName?: string;
    organization?: string;
  };
};

export async function loadMostRecentSession({
  serviceConfig,
  sessionParams,
}: LoadMostRecentSessionParams): Promise<Session | undefined> {
  const recent = await getMostRecentCookieWithLoginname({
    loginName: sessionParams.loginName,
    organization: sessionParams.organization,
  });

  if (!recent) {
    return undefined;
  }

  return loadSession(serviceConfig, recent);
}

export async function loadSessionById(
  serviceConfig: ServiceConfig,
  sessionId: string,
  organization?: string,
): Promise<Session | undefined> {
  const recent = await getSessionCookieById({ sessionId, organization });

  if (!recent) {
    return undefined;
  }

  return loadSession(serviceConfig, recent);
}

export async function loadSession(
  serviceConfig: ServiceConfig,
  cookie: { id: string; token: string },
): Promise<Session | undefined> {
  return getSession({ serviceConfig, sessionId: cookie.id, sessionToken: cookie.token })
    .then((resp: GetSessionResponse) => resp.session)
    .catch(async (error) => {
      const { Code, ConnectError } = await import("@connectrpc/connect");
      const isSessionRejected =
        error instanceof ConnectError && (error.code === Code.NotFound || error.code === Code.PermissionDenied);

      // The `sessions` cookie has no maxAge, so it can outlive the server-side session
      // and reference one the session projection no longer holds, e.g. the user logged out, an
      // admin/API terminated the session, or the user/org/instance was removed. In that
      // case getSession throws `not_found`. If the session still exists but the cookie's token
      // no longer matches it (e.g. the token was rotated by a later session update), getSession
      // throws `permission_denied` (QUERY-dsfr3). Treat both like the no-cookie case and
      // return undefined instead of letting the error crash the caller's render.
      // Every call site already handles an undefined session, either with a graceful fallback
      // or by throwing its own explicit "no session" error.
      if (isSessionRejected) {
        console.warn("[Session] Could not load session", error);
        return undefined;
      }

      throw error;
    });
}

/**
 * A session proves genuine (primary) authentication when a primary factor — password,
 * passkey/WebAuthn or IDP intent — has been verified and the session has not expired.
 *
 * A WebAuthn factor only counts as a *primary* factor when it was user-verified
 * (`userVerified` true, i.e. passwordless login). A presence-only WebAuthn assertion is a
 * second-factor (U2F) check and must NOT be treated as primary authentication — mirroring
 * how `mfa-helper` distinguishes "authenticated with passkey" from a 2FA WebAuthn check.
 *
 * This is the shared gate behind both the credential-enrollment guard
 * (`getEnrollmentAuthorizationError`) and the MFA-setup page, so an "identify-only"
 * session (only `factors.user` set, produced by submitting a login name) is never enough
 * to attach a new authenticator (GHSA-45f2-5q3r-xgg6).
 */
export function hasVerifiedPrimaryFactor(session: Partial<Session>): {
  valid: boolean;
  verifiedAt?: Timestamp;
} {
  const validPassword = session?.factors?.password?.verifiedAt;
  const validPasskey =
    session?.factors?.webAuthN?.verifiedAt && !!session?.factors?.webAuthN?.userVerified
      ? session?.factors?.webAuthN?.verifiedAt
      : undefined;
  const validIDP = session?.factors?.intent?.verifiedAt;

  const stillValid = session.expirationDate ? timestampDate(session.expirationDate) > new Date() : true;

  const verifiedAt = validPassword || validPasskey || validIDP;
  const valid = !!(verifiedAt && stillValid);

  return { valid, verifiedAt };
}

/** The authentication methods that are second factors (a passkey is multi-factor on its own). */
export const SECOND_FACTOR_METHODS = [
  AuthenticationMethodType.TOTP,
  AuthenticationMethodType.OTP_EMAIL,
  AuthenticationMethodType.OTP_SMS,
  AuthenticationMethodType.U2F,
];

/**
 * Reports whether the session has verified one of the second factors in `authMethods`, the
 * user's configured authentication methods. A user-verified passkey is not considered here;
 * callers that treat it as multi-factor check it separately.
 */
export function hasVerifiedSecondFactor(session: Partial<Session>, authMethods: AuthenticationMethodType[]): boolean {
  const factors = session.factors;
  return (
    (authMethods.includes(AuthenticationMethodType.TOTP) && !!factors?.totp?.verifiedAt) ||
    (authMethods.includes(AuthenticationMethodType.OTP_EMAIL) && !!factors?.otpEmail?.verifiedAt) ||
    (authMethods.includes(AuthenticationMethodType.OTP_SMS) && !!factors?.otpSms?.verifiedAt) ||
    (authMethods.includes(AuthenticationMethodType.U2F) && !!factors?.webAuthN?.verifiedAt)
  );
}

/**
 * AZDIGI: a session is valid when the organisation's fresh login policy accepts its verified factors
 * (lib/azdigi/policy.ts), the same rule the token wrapper (lib/azdigi/issue.ts) enforces, so there is no gap
 * between "shown as signed in" and "receives tokens". Unlike upstream's rule, an email or SMS code is a valid sole
 * factor in an OTP-first organisation, and a password never gets past a TOTP, security key or passkey the user set up.
 */
export async function checkSessionPolicy({
  serviceConfig,
  session,
}: {
  serviceConfig: ServiceConfig;
  session: Session;
}): Promise<PolicyVerdict> {
  const organizationId = session.factors?.user?.organizationId;
  const userId = session.factors?.user?.id;
  const [loginSettings, otpFirstOrg, registeredMethods] = await Promise.all([
    getLoginSettings({ serviceConfig, organization: organizationId, fresh: true }),
    isOtpFirstOrg(serviceConfig, organizationId),
    userId ? registeredMethodsOf(serviceConfig, userId) : Promise.resolve(undefined),
  ]);
  return assertSessionSatisfiesPolicy({ session, loginSettings, otpFirstOrg, registeredMethods });
}

/**
 * Whether a session counts, and if not, the step that is missing: the organisation's policy, then EMAIL_VERIFICATION.
 * Callers that send the user on use redirectForVerdict (lib/azdigi/issue.ts) with this verdict.
 */
export async function sessionVerdict({
  serviceConfig,
  session,
}: {
  serviceConfig: ServiceConfig;
  session: Session;
}): Promise<PolicyVerdict> {
  // session can't be checked without user
  if (!session.factors?.user) {
    return { ok: false, reason: "no-user", next: "loginname" };
  }

  const verdict = await checkSessionPolicy({ serviceConfig, session });
  if (!verdict.ok) {
    console.warn("[azdigi] session does not satisfy the login policy", {
      userId: session.factors.user.id,
      organizationId: session.factors.user.organizationId,
      reason: verdict.reason,
    });
    return verdict;
  }

  // EMAIL_VERIFICATION: the same rule the token guard applies (lib/azdigi/issue.ts)
  const email = await emailVerificationVerdict(serviceConfig, session.factors.user.id);
  if (!email.ok) {
    console.warn("[Session] Email is not verified", { userId: session.factors.user.id, reason: email.reason });
  }
  return email;
}

export async function isSessionValid({
  serviceConfig,
  session,
}: {
  serviceConfig: ServiceConfig;
  session: Session;
}): Promise<boolean> {
  return (await sessionVerdict({ serviceConfig, session })).ok;
}

export async function findValidSession({
  serviceConfig,
  sessions,
  authRequest,
  samlRequest,
  organization,
}: {
  serviceConfig: ServiceConfig;
  sessions: Session[];
  authRequest?: AuthRequest;
  samlRequest?: SAMLRequest;
  organization?: string;
}): Promise<Session | undefined> {
  let sessionsWithHint = sessions.filter((s) => {
    // AZDIGI: an application that names its organisation never gets another organisation's session (#46)
    if (authRequest && !sessionInScopedOrg(s, authRequest.scope)) {
      return false;
    }
    if (authRequest && authRequest.hintUserId) {
      return s.factors?.user?.id === authRequest.hintUserId;
    }
    if (authRequest && authRequest.loginHint) {
      return s.factors?.user?.loginName === authRequest.loginHint;
    }
    if (samlRequest) {
      // SAML requests don't contain user hints like OIDC (hintUserId/loginHint)
      // so we return all sessions for further processing
      return true;
    }
    return true;
  });

  if (organization) {
    sessionsWithHint = sessionsWithHint.filter((s) => s.factors?.user?.organizationId === organization);
  }

  if (sessionsWithHint.length === 0) {
    return undefined;
  }

  // sort by change date descending
  sessionsWithHint.sort((a, b) => {
    const dateA = a.changeDate ? timestampDate(a.changeDate).getTime() : 0;
    const dateB = b.changeDate ? timestampDate(b.changeDate).getTime() : 0;
    return dateB - dateA;
  });

  // return the first valid session according to settings
  for (const session of sessionsWithHint) {
    if (await isSessionValid({ serviceConfig, session })) {
      return session;
    }
  }

  return undefined;
}
