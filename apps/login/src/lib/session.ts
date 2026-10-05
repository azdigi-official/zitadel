import { timestampDate } from "@zitadel/client";
import { AuthRequest } from "@zitadel/proto/zitadel/oidc/v2/authorization_pb";
import { SAMLRequest } from "@zitadel/proto/zitadel/saml/v2/authorization_pb";
import { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { GetSessionResponse } from "@zitadel/proto/zitadel/session/v2/session_service_pb";
import { registeredMethodsOf } from "./azdigi/issue";
import { isOtpFirstOrg } from "./azdigi/org-lookup";
import { assertSessionSatisfiesPolicy, PolicyVerdict } from "./azdigi/policy";
import { getMostRecentCookieWithLoginname } from "./cookies";
import { getLoginSettings, getSession, getUserByID, ServiceConfig } from "./zitadel";

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

  return getSession({ serviceConfig, sessionId: recent.id, sessionToken: recent.token }).then(
    (resp: GetSessionResponse) => resp.session,
  );
}

/**
 * AZDIGI: a session is valid when the organisation's fresh login policy accepts its verified factors
 * (lib/azdigi/policy.ts) — the same rule the token wrapper (lib/azdigi/issue.ts) enforces, so there is no gap
 * between "shown as signed in" and "receives tokens".
 **/
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

export async function isSessionValid({
  serviceConfig,
  session,
}: {
  serviceConfig: ServiceConfig;
  session: Session;
}): Promise<boolean> {
  // session can't be checked without user
  if (!session.factors?.user) {
    return false;
  }

  const verdict = await checkSessionPolicy({ serviceConfig, session });

  if (!verdict.ok) {
    console.warn("[azdigi] session does not satisfy the login policy", {
      userId: session.factors.user.id,
      organizationId: session.factors.user.organizationId,
      reason: verdict.reason,
    });
    return false;
  }

  // Check email verification if EMAIL_VERIFICATION environment variable is enabled
  if (process.env.EMAIL_VERIFICATION === "true") {
    const userResponse = await getUserByID({ serviceConfig, userId: session.factors.user.id });

    const humanUser = userResponse?.user?.type.case === "human" ? userResponse?.user.type.value : undefined;

    if (humanUser && !humanUser.email?.isVerified) {
      console.warn("[Session] Email is not verified");
      return false;
    }
  }

  return true;
}

export async function findValidSession({
  serviceConfig,
  sessions,
  authRequest,
  samlRequest,
}: {
  serviceConfig: ServiceConfig;
  sessions: Session[];
  authRequest?: AuthRequest;
  samlRequest?: SAMLRequest;
}): Promise<Session | undefined> {
  const sessionsWithHint = sessions.filter((s) => {
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
