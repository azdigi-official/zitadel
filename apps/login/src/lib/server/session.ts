"use server";

import { buildServerChallenges } from "@/lib/azdigi/challenges";
import { clientIpFromHeaders } from "@/lib/azdigi/client-ip";
import { estimateUnlockAt, isLockedMessage, orgKindFromSettings } from "@/lib/azdigi/lockout";
import { decideOtpFirstForUser } from "@/lib/azdigi/otp-first";
import { hasVerifiedFirstFactor } from "@/lib/azdigi/policy";
import { limiters } from "@/lib/azdigi/rate-limit";
import { createSessionAndUpdateCookie, setSessionAndUpdateCookie } from "@/lib/server/cookie";
import {
  deleteSession,
  getLoginSettings,
  getSecuritySettings,
  getSession,
  getUserByID,
  humanMFAInitSkipped,
  listAuthenticationMethodTypes,
  listUsers,
} from "@/lib/zitadel";
import { create, Duration, timestampDate } from "@zitadel/client";
import { Challenges, RequestChallenges } from "@zitadel/proto/zitadel/session/v2/challenge_pb";
import { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { Checks, ChecksSchema } from "@zitadel/proto/zitadel/session/v2/session_service_pb";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { getTranslations } from "next-intl/server";
import { headers } from "next/headers";
import { completeFlowOrGetUrl } from "../client";
import {
  getMostRecentSessionCookie,
  getSessionCookieById,
  getSessionCookieByLoginName,
  removeSessionFromCookie,
} from "../cookies";
import { getServiceConfig } from "../service-url";
import { getPublicHost } from "./host";

export async function skipMFAAndContinueWithNextUrl({
  userId,
  requestId,
  loginName,
  sessionId,
  organization,
}: {
  userId: string;
  loginName?: string;
  sessionId?: string;
  requestId?: string;
  organization?: string;
}): Promise<{ redirect: string } | { error: string } | { samlData: { url: string; fields: Record<string, string> } }> {
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  const loginSettings = await getLoginSettings({ serviceConfig, organization: organization });

  await humanMFAInitSkipped({ serviceConfig, userId });

  if (requestId && sessionId) {
    return completeFlowOrGetUrl(
      {
        sessionId: sessionId,
        requestId: requestId,
        organization: organization,
      },
      loginSettings?.defaultRedirectUri,
    );
  } else if (loginName) {
    return completeFlowOrGetUrl(
      {
        loginName: loginName,
        organization: organization,
      },
      loginSettings?.defaultRedirectUri,
    );
  }

  return { error: "Could not skip MFA and continue" };
}

export type ContinueWithSessionCommand = Session & { requestId?: string };

export async function continueWithSession({ requestId, ...session }: ContinueWithSessionCommand) {
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  const t = await getTranslations("error");

  const loginSettings = await getLoginSettings({ serviceConfig, organization: session.factors?.user?.organizationId });

  if (requestId && session.id && session.factors?.user) {
    return completeFlowOrGetUrl(
      {
        sessionId: session.id,
        requestId: requestId,
        organization: session.factors.user.organizationId,
      },
      loginSettings?.defaultRedirectUri,
    );
  } else if (session.factors?.user) {
    return completeFlowOrGetUrl(
      {
        loginName: session.factors.user.loginName,
        organization: session.factors.user.organizationId,
      },
      loginSettings?.defaultRedirectUri,
    );
  }

  // Fallback error if we couldn't determine where to redirect
  return { error: t("couldNotContinueSession") };
}

export type UpdateSessionCommand = {
  loginName?: string;
  sessionId?: string;
  organization?: string;
  checks?: Checks;
  requestId?: string;
  /**
   * AZDIGI: the client only names which challenge it wants (otpEmail / otpSms / webAuthN with its
   * userVerificationRequirement). Delivery details are built on the server and OTP codes are never returned.
   */
  challenges?: RequestChallenges;
  /** AZDIGI: ignored — the lifetime always comes from the organisation's login settings */
  lifetime?: Duration;
};

/** Loose shape (all optional) so upstream callers keep reading `error`, `factors`, `challenges` as before. */
export type UpdateSessionResult = {
  error?: string;
  redirect?: string;
  failedAttempts?: number;
  locked?: boolean;
  sessionId?: string;
  factors?: Session["factors"];
  /** only the WebAuthn challenge is ever returned; OTP codes never leave the server */
  challenges?: Pick<Challenges, "webAuthN">;
  authMethods?: AuthenticationMethodType[];
};

function otpErrorToResult(
  error: unknown,
  t: Awaited<ReturnType<typeof getTranslations>>,
  remaining: number,
  unlockAt?: Date,
) {
  const raw: string =
    (error as any)?.rawMessage ?? (error as any)?.message ?? (typeof error === "string" ? error : "") ?? "";
  // observed on v4.11 (04/10/2026): "User is locked (COMMAND-S6h4R)" from the 4th wrong code, "Code is invalid (CODE-woT0xc)"
  // before that; the session create for a locked user says "Errors.User.NotActive (SESSION-Gj4ko)"
  if (isLockedMessage(raw)) {
    return { error: unlockAt ? t("userLockedUntil", { time: unlockAt }) : t("userLocked"), locked: true };
  }
  const failedAttempts: number | undefined =
    typeof (error as any)?.failedAttempts === "number" ? (error as any).failedAttempts : undefined;
  if (failedAttempts !== undefined || /Code is invalid|CODE-|Errors\.User\.Code|Errors\.User\.MFA\.OTP/i.test(raw)) {
    return { error: t("codeInvalid", { remaining }), failedAttempts };
  }
  return undefined;
}

/** The expected unlock time for a (just) locked user, or undefined while the unlock worker is off. */
async function unlockEtaForUser(serviceConfig: ReturnType<typeof getServiceConfig>["serviceConfig"], userId: string) {
  const user = await getUserByID({ serviceConfig, userId })
    .then((r) => r.user)
    .catch(() => undefined);
  if (!user) {
    return undefined;
  }
  const settings = await getLoginSettings({ serviceConfig, organization: user.details?.resourceOwner, fresh: true }).catch(() => undefined);
  return estimateUnlockAt(user.details?.changeDate ? timestampDate(user.details.changeDate) : undefined, orgKindFromSettings(settings));
}

function passwordParams(loginName?: string, organization?: string, requestId?: string) {
  const params = new URLSearchParams();
  if (loginName) params.append("loginName", loginName);
  if (organization) params.append("organization", organization);
  if (requestId) params.append("requestId", requestId);
  return params;
}

export async function updateOrCreateSession(options: UpdateSessionCommand): Promise<UpdateSessionResult> {
  const { loginName, sessionId, organization, checks, requestId } = options;

  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);
  const host = getPublicHost(_headers);

  const t = await getTranslations("verify.errors");

  if (!host) {
    return { error: "Could not get host" }; // Technical error, maybe leave or translate if key exists
  }

  const challenges = buildServerChallenges(options.challenges, host, requestId);
  const wantsOtpSend = !!(challenges?.otpEmail || challenges?.otpSms);
  const triesOtpCode = !!(checks?.otpEmail || checks?.otpSms || checks?.totp);

  let recentSession = sessionId
    ? await getSessionCookieById({ sessionId })
    : loginName
      ? await getSessionCookieByLoginName({ loginName, organization })
      : await getMostRecentSessionCookie();

  if (!recentSession) {
    if (!loginName) {
      return { error: t("couldNotFindSession") };
    }

    // user check only; challenges are requested below once the session is known to be allowed to receive them
    const userChecks = create(ChecksSchema, {
      user: { search: { case: "loginName", value: loginName } },
    });

    const result = await createSessionAndUpdateCookie({
      checks: userChecks,
      requestId,
    }).catch((error) => {
      console.error("Could not create session", error);
      return undefined;
    });

    if (result && "sessionCookie" in result) {
      recentSession = result.sessionCookie;
    }

    if (!recentSession) {
      return {
        error: t("couldNotFindSession"),
      };
    }
  }

  let userId: string | undefined;

  if (wantsOtpSend || triesOtpCode) {
    const current = await getSession({ serviceConfig, sessionId: recentSession.id, sessionToken: recentSession.token })
      .then((resp) => resp?.session)
      .catch(() => undefined);

    if (!current?.factors?.user?.id) {
      return { error: t("couldNotFindSession") };
    }
    userId = current.factors.user.id;
    const organizationId = current.factors.user.organizationId;

    // the soft attempt limit comes first: a 3rd wrong code would lock the user in Zitadel
    if (triesOtpCode) {
      const attempts = limiters.otpVerifyPerUser.hit(`user:${userId}`);
      if (!attempts.allowed) {
        console.warn("[azdigi] OTP verify rate limited", { userId, organizationId });
        return { error: t("tooManyCodeAttempts", { minutes: Math.max(1, Math.ceil(attempts.retryAfterMs / 60000)) }) };
      }
    }

    if (!hasVerifiedFirstFactor(current)) {
      // an OTP as the first factor: only for eligible users of allow-listed organisations
      const userResponse = await getUserByID({ serviceConfig, userId }).catch(() => undefined);
      const user = userResponse?.user;
      const decision = await decideOtpFirstForUser({
        serviceConfig,
        userId,
        organizationId,
        humanUser: user?.type.case === "human" ? user.type.value : undefined,
        userState: user?.state,
      });
      if (!decision.eligible && decision.reason === "user-state") {
        console.warn("[azdigi] OTP-first refused", { userId, organizationId, reason: decision.reason });
        const unlockAt = await unlockEtaForUser(serviceConfig, userId);
        return { error: unlockAt ? t("userLockedUntil", { time: unlockAt }) : t("userLocked"), locked: true };
      }
      if (!decision.eligible) {
        console.warn("[azdigi] OTP-first refused", { userId, organizationId, reason: decision.reason });
        return {
          error: t("otpFirstNotAllowed"),
          redirect: "/password?" + passwordParams(current.factors.user.loginName, organizationId, requestId),
        };
      }
    }

    if (wantsOtpSend) {
      const ip = clientIpFromHeaders(_headers);
      const perLogin = limiters.otpSendPerLogin.hit(`login:${organizationId}:${current.factors.user.loginName}`);
      const perIp = ip ? limiters.otpSendPerIp.hit(`ip:${ip}`) : { allowed: true, retryAfterMs: 0 };
      if (!perLogin.allowed || !perIp.allowed) {
        console.warn("[azdigi] OTP send rate limited", {
          userId,
          organizationId,
          scope: perLogin.allowed ? "ip" : "login",
        });
        const retryAfterMs = Math.max(perLogin.retryAfterMs, perIp.retryAfterMs);
        return { error: t("tooManyCodeRequests", { minutes: Math.max(1, Math.ceil(retryAfterMs / 60000)) }) };
      }
    }

  }

  const loginSettings = await getLoginSettings({ serviceConfig, organization });

  let lifetime = checks?.webAuthN
    ? loginSettings?.multiFactorCheckLifetime // TODO different lifetime for webauthn u2f/passkey
    : checks?.otpEmail || checks?.otpSms || checks?.totp
      ? loginSettings?.secondFactorCheckLifetime
      : undefined;

  if (!lifetime || !lifetime.seconds) {
    console.warn("No lifetime provided for session, defaulting to 24 hours");
    lifetime = {
      seconds: BigInt(60 * 60 * 24), // default to 24 hours
      nanos: 0,
    } as Duration;
  }

  let session;
  try {
    session = await setSessionAndUpdateCookie({
      recentCookie: recentSession,
      checks,
      challenges,
      requestId,
      lifetime,
    });
  } catch (error) {
    if (triesOtpCode) {
      const remaining = userId ? limiters.otpVerifyPerUser.peek(`user:${userId}`).remaining : 0;
      const mapped = otpErrorToResult(error, t, remaining, userId ? await unlockEtaForUser(serviceConfig, userId) : undefined);
      if (mapped) {
        return mapped;
      }
    }

    // any other failure: the session behind the cookie may be gone — re-create it for the same user (upstream behaviour)
    const loginNameForCreation = options.loginName || recentSession?.loginName;
    const orgForCreation = options.organization || recentSession?.organization;

    if (!loginNameForCreation) {
      throw error;
    }

    const users = await listUsers({
      serviceConfig,
      loginName: loginNameForCreation,
      organizationId: orgForCreation,
    });

    if (users.details?.totalResult === BigInt(1) && users.result[0].userId) {
      const user = users.result[0];
      const newChecks = create(ChecksSchema, {
        ...(checks || {}),
        user: { search: { case: "userId", value: user.userId } } as any,
      });

      const result = await createSessionAndUpdateCookie({
        checks: newChecks,
        requestId,
        lifetime,
        challenges,
      });
      // @ts-ignore
      session = { ...result.session, challenges: result.challenges };
    } else {
      throw error;
    }
  }

  if (!session || ("error" in session && session.error)) {
    return { error: t("couldNotUpdateSession") };
  }

  if (triesOtpCode && userId) {
    // a verified code ends the attempt window
    limiters.otpVerifyPerUser.clear(`user:${userId}`);
  }

  // if password, check if user has MFA methods
  let authMethods;
  if (checks && checks.password && session.factors?.user?.id) {
    const response = await listAuthenticationMethodTypes({ serviceConfig, userId: session.factors.user.id });
    if (response.authMethodTypes && response.authMethodTypes.length) {
      authMethods = response.authMethodTypes;
    }
  }

  // @ts-ignore
  const issued: Challenges | undefined = session.challenges;

  return {
    sessionId: session.id,
    factors: session.factors,
    // OTP codes (returnCode) never leave the server; only the WebAuthn challenge is needed by the browser
    challenges: issued?.webAuthN ? { webAuthN: issued.webAuthN } : undefined,
    authMethods,
  };
}

type ClearSessionOptions = {
  sessionId: string;
};

export async function clearSession(options: ClearSessionOptions) {
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  const { sessionId } = options;

  const sessionCookie = await getSessionCookieById({ sessionId });

  if (!sessionCookie) {
    return;
  }

  const deleteResponse = await deleteSession({
    serviceConfig,
    sessionId: sessionCookie.id,
    sessionToken: sessionCookie.token,
  });

  const securitySettings = await getSecuritySettings({ serviceConfig });
  const iFrameEnabled = !!securitySettings?.embeddedIframe?.enabled;

  if (!deleteResponse) {
    throw new Error("Could not delete session");
  }

  return removeSessionFromCookie({ session: sessionCookie, iFrameEnabled });
}
