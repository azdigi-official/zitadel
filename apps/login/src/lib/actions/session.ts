"use server";

import { completeFlowOrGetUrl } from "@/lib/actions/flow";
import { clientIpFromHeaders } from "@/lib/azdigi/client-ip";
import { decoyLoginName, decoyOrganization, withMinimumDuration } from "@/lib/azdigi/decoy";
import { redirectForVerdict } from "@/lib/azdigi/issue";
import { estimateUnlockAt, isLockedMessage, orgKindFromSettings } from "@/lib/azdigi/lockout";
import { isOtpFirstOrg } from "@/lib/azdigi/org-lookup";
import { decideOtpFirstForUser } from "@/lib/azdigi/otp-first";
import { hasVerifiedFirstFactor } from "@/lib/azdigi/policy";
import { limiters } from "@/lib/azdigi/rate-limit";
import { sendVerificationOnce } from "@/lib/azdigi/verification-mail";
import { getOTPSMSResendCooldownSeconds, getOTPSMSRetryAfterSeconds, SessionUpdatedError } from "@/lib/server/challenges";
import {
  getMostRecentSessionCookie,
  getSessionCookieById,
  getSessionCookieByLoginName,
  removeSessionFromCookie,
} from "@/lib/server/cookies";
import { isClassifiedError } from "@/lib/server/grpc/interceptors/error-classification";
import { getPublicHost, getPublicHostWithProtocol } from "@/lib/server/host";
import { createLogger } from "@/lib/server/logger";
import { shouldEnforceMFA } from "@/lib/server/mfa-helper";
import { getServiceConfig } from "@/lib/server/service-url";
import { hasVerifiedPrimaryFactor, loadSession, sessionVerdict } from "@/lib/server/session";
import { createSessionAndUpdateCookie, setSessionAndUpdateCookie } from "@/lib/server/session-cookie";
import {
  deleteSession,
  getLoginSettings,
  getSecuritySettings,
  getUserByID,
  humanMFAInitSkipped,
  listUsers,
  ServiceConfig,
} from "@/lib/server/zitadel";
import { Code, create, Duration, timestampDate } from "@zitadel/client";
import {
  Challenges,
  RequestChallenges,
  RequestChallenges_OTPEmail_SendCodeSchema,
} from "@zitadel/proto/zitadel/session/v2/challenge_pb";
import { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { Checks, ChecksSchema } from "@zitadel/proto/zitadel/session/v2/session_service_pb";
import { getTranslations } from "next-intl/server";
import { headers } from "next/headers";

const logger = createLogger("session");

/**
 * Server actions are public endpoints, so every argument is caller-controlled. The session an
 * action acts on is therefore always resolved from the caller's own signed `sessions` cookie and
 * loaded from ZITADEL with that cookie's token, never taken from the request body.
 */
async function loadCallerSession({
  serviceConfig,
  sessionId,
  loginName,
  organization,
}: {
  serviceConfig: ServiceConfig;
  sessionId?: string;
  loginName?: string;
  organization?: string;
}): Promise<Session | undefined> {
  const sessionCookie = sessionId
    ? await getSessionCookieById({ sessionId })
    : loginName
      ? await getSessionCookieByLoginName({ loginName, organization })
      : undefined;

  if (!sessionCookie) {
    return undefined;
  }

  return loadSession(serviceConfig, sessionCookie);
}

export async function skipMFAAndContinueWithNextUrl({
  requestId,
  loginName,
  sessionId,
  organization,
}: {
  loginName?: string;
  sessionId?: string;
  requestId?: string;
  organization?: string;
}): Promise<{ redirect: string } | { error: string } | { samlData: { url: string; fields: Record<string, string> } }> {
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  const session = await loadCallerSession({ serviceConfig, sessionId, loginName, organization });
  const userId = session?.factors?.user?.id;

  // only a user who just authenticated may skip the MFA setup prompt, and only for themselves
  if (!session || !userId || !hasVerifiedPrimaryFactor(session).valid) {
    return { error: "Could not skip MFA and continue" };
  }

  const userLoginSettings = await getLoginSettings({ serviceConfig, organization: session.factors?.user?.organizationId });

  if (shouldEnforceMFA(session, userLoginSettings)) {
    return { error: "Could not skip MFA and continue" };
  }

  const loginSettings = await getLoginSettings({ serviceConfig, organization: organization });

  await humanMFAInitSkipped({ serviceConfig, userId });

  if (requestId && session.id) {
    return completeFlowOrGetUrl(
      {
        sessionId: session.id,
        requestId: requestId,
        organization: organization,
      },
      loginSettings?.defaultRedirectUri,
    );
  } else if (session.factors?.user?.loginName) {
    return completeFlowOrGetUrl(
      {
        loginName: session.factors.user.loginName,
        organization: organization,
      },
      loginSettings?.defaultRedirectUri,
    );
  }

  return { error: "Could not skip MFA and continue" };
}

export type ContinueWithSessionCommand = { sessionId: string; requestId?: string };

export async function continueWithSession({ sessionId, requestId }: ContinueWithSessionCommand) {
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  const t = await getTranslations("error");

  const session = await loadCallerSession({ serviceConfig, sessionId });

  if (!session?.factors?.user) {
    return { error: t("couldNotContinueSession") };
  }

  const loginSettings = await getLoginSettings({ serviceConfig, organization: session.factors.user.organizationId });

  // Validate session (including MFA) before completing the flow. AZDIGI: a refused session continues at the step the
  // policy names (e.g. /mfa while the password is still valid), never through a blind sendLoginname
  const verdict = await sessionVerdict({ serviceConfig, session });

  if (!verdict.ok) {
    logger.warn("continueWithSession: session is not valid, redirecting to the missing step", {
      sessionId: session.id,
      reason: verdict.reason,
    });
    return { redirect: redirectForVerdict(verdict, session, requestId) };
  }

  if (requestId && session.id) {
    return completeFlowOrGetUrl(
      {
        sessionId: session.id,
        requestId: requestId,
        organization: session.factors.user.organizationId,
      },
      loginSettings?.defaultRedirectUri,
    );
  }

  return completeFlowOrGetUrl(
    {
      loginName: session.factors.user.loginName,
      organization: session.factors.user.organizationId,
    },
    loginSettings?.defaultRedirectUri,
  );
}

export type UpdateSessionCommand = {
  loginName?: string;
  sessionId?: string;
  organization?: string;
  checks?: Checks;
  requestId?: string;
  challenges?: RequestChallenges;
};

/**
 * This action only completes second factors and passkeys. The primary checks (user, password,
 * IDP intent) run through their own actions, which enforce the login policy first, so they are
 * dropped here instead of being forwarded to the session API.
 */
function pickSecondFactorChecks(checks?: Checks): Checks | undefined {
  if (!checks) {
    return undefined;
  }

  return create(ChecksSchema, {
    webAuthN: checks.webAuthN,
    totp: checks.totp,
    otpSms: checks.otpSms,
    otpEmail: checks.otpEmail,
  });
}

/**
 * The WebAuthN relying party and the link in the OTP email are always derived from the host this
 * request was served on (the same host that is forwarded to and validated by ZITADEL), never taken
 * from the caller. Otherwise anyone could make ZITADEL send a genuine OTP email whose link points
 * to a host of their choice.
 */
function bindChallengesToHost(
  challenges: RequestChallenges | undefined,
  hostWithProtocol: string,
  requestId?: string,
): RequestChallenges | undefined {
  if (!challenges) {
    return undefined;
  }

  const bound = { ...challenges };

  if (bound.webAuthN) {
    bound.webAuthN = { ...bound.webAuthN, domain: new URL(hostWithProtocol).hostname };
  }

  if (bound.otpEmail) {
    const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? "";
    let urlTemplate = `${hostWithProtocol}${basePath}/otp/email?code={{.Code}}&userId={{.UserID}}&sessionId={{.SessionID}}`;

    if (requestId) {
      urlTemplate += `&requestId=${encodeURIComponent(requestId)}`;
    }

    bound.otpEmail = {
      ...bound.otpEmail,
      deliveryType: { case: "sendCode", value: create(RequestChallenges_OTPEmail_SendCodeSchema, { urlTemplate }) },
    };
  }

  return bound;
}

/**
 * AZDIGI: one loose shape (all optional) for every answer, so the callers keep reading `error`, `factors`,
 * `challenges` and `retryAfterSeconds`, and the AZDIGI answers can add `redirect`, `locked` and `failedAttempts`.
 */
export type UpdateSessionResult = {
  error?: string;
  redirect?: string;
  locked?: boolean;
  failedAttempts?: number;
  sessionId?: string;
  factors?: Session["factors"];
  /** only the WebAuthn challenge is ever returned; OTP codes never leave the server */
  challenges?: Pick<Challenges, "webAuthN">;
  retryAfterSeconds?: number;
};

type Translate = Awaited<ReturnType<typeof getTranslations>>;

const minutesUntil = (retryAfterMs: number) => Math.max(1, Math.ceil(retryAfterMs / 60000));

/** AZDIGI: Zitadel's answers to a wrong, unavailable or locked code, as the messages the code screens show. */
function otpErrorToResult(
  error: unknown,
  t: Translate,
  remaining: number,
  unlockAt?: Date,
): UpdateSessionResult | undefined {
  const fields =
    typeof error === "object" && error !== null
      ? (error as { rawMessage?: unknown; message?: unknown; failedAttempts?: unknown })
      : {};
  const raw =
    typeof fields.rawMessage === "string"
      ? fields.rawMessage
      : typeof fields.message === "string"
        ? fields.message
        : typeof error === "string"
          ? error
          : "";
  // observed on v4.11 (04/10/2026): "User is locked (COMMAND-S6h4R)" from the 4th wrong code, "Code is invalid (CODE-woT0xc)"
  // before that; the session create for a locked user says "Errors.User.NotActive (SESSION-Gj4ko)"
  if (isLockedMessage(raw)) {
    return { error: unlockAt ? t("userLockedUntil", { time: unlockAt }) : t("userLocked"), locked: true };
  }
  if (/COMMAND-S34gh|Code not found|Errors\.User\.Code\.NotFound/i.test(raw)) {
    return { error: t("codeUnavailable") };
  }
  const failedAttempts = typeof fields.failedAttempts === "number" ? fields.failedAttempts : undefined;
  if (failedAttempts !== undefined || /Code is invalid|CODE-|Errors\.User\.Code|Errors\.User\.MFA\.OTP/i.test(raw)) {
    return { error: t("codeInvalid", { remaining }), failedAttempts };
  }
  return undefined;
}

/** AZDIGI: the expected unlock time for a (just) locked user, or undefined while the unlock worker is off. */
async function unlockEtaForUser(serviceConfig: ServiceConfig, userId: string) {
  const user = await getUserByID({ serviceConfig, userId })
    .then((r) => r.user)
    .catch(() => undefined);
  if (!user) {
    return undefined;
  }
  const settings = await getLoginSettings({ serviceConfig, organization: user.details?.resourceOwner, fresh: true }).catch(
    () => undefined,
  );
  return estimateUnlockAt(
    user.details?.changeDate ? timestampDate(user.details.changeDate) : undefined,
    orgKindFromSettings(settings),
  );
}

function flowParams(loginName?: string, organization?: string, requestId?: string) {
  const params = new URLSearchParams();
  if (loginName) params.append("loginName", loginName);
  if (organization) params.append("organization", organization);
  if (requestId) params.append("requestId", requestId);
  return params;
}

/** AZDIGI: the answers a real customer gets on the email-code page, for an unknown name (same limits, same messages). */
function decoyOtpAnswer({
  loginName,
  organization,
  tries,
  ip,
  t,
}: {
  loginName: string;
  organization: string;
  tries: boolean;
  ip?: string;
  t: Translate;
}): UpdateSessionResult {
  const name = decoyLoginName(loginName);
  if (tries) {
    const key = `decoy:${organization}:${name}`;
    const attempts = limiters.otpVerifyPerUser.hit(key);
    if (!attempts.allowed) {
      return { error: t("tooManyCodeAttempts", { minutes: minutesUntil(attempts.retryAfterMs) }) };
    }
    return { error: t("codeInvalid", { remaining: limiters.otpVerifyPerUser.peek(key).remaining }) };
  }
  const perLogin = limiters.otpSendPerLogin.hit(`login:${organization}:${name}`);
  const perIp = ip ? limiters.otpSendPerIp.hit(`ip:${ip}`) : { allowed: true, retryAfterMs: 0 };
  if (!perLogin.allowed || !perIp.allowed) {
    return {
      error: t("tooManyCodeRequests", { minutes: minutesUntil(Math.max(perLogin.retryAfterMs, perIp.retryAfterMs)) }),
    };
  }
  return {};
}

export async function updateOrCreateSession(options: UpdateSessionCommand): Promise<UpdateSessionResult> {
  // AZDIGI: code requests and code checks take a minimum time (decoy.ts), real or decoy
  const otp = !!(
    options.challenges?.otpEmail ||
    options.challenges?.otpSms ||
    options.checks?.otpEmail ||
    options.checks?.otpSms
  );
  return otp ? withMinimumDuration(() => updateOrCreateSessionNow(options)) : updateOrCreateSessionNow(options);
}

async function updateOrCreateSessionNow(options: UpdateSessionCommand): Promise<UpdateSessionResult> {
  const { loginName, sessionId, organization, requestId } = options;
  const checks = pickSecondFactorChecks(options.checks);

  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);
  const host = getPublicHost(_headers);

  const t = await getTranslations("verify.errors");

  if (!host) {
    return { error: "Could not get host" }; // Technical error, maybe leave or translate if key exists
  }

  const challenges = bindChallengesToHost(options.challenges, getPublicHostWithProtocol(_headers), requestId);
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

    // AZDIGI: an email code as the first factor without a session cookie: only an account of the OTP-first organisation
    // continues; any other name (unknown, staff, another organisation) gets the decoy answers (decoy.ts). Discovery is
    // scoped to the requested organisation and the account's owner is verified before any challenge is issued.
    if (!sessionId && (challenges?.otpEmail || checks?.otpEmail)) {
      const ip = clientIpFromHeaders(_headers);
      const otpOrg = await decoyOrganization(serviceConfig, organization);
      if (checks?.otpEmail) {
        return decoyOtpAnswer({ loginName, organization: otpOrg ?? organization ?? "", tries: true, ip, t });
      }
      // outside a customer context (no OTP-first or requested organisation) there is nothing to pretend
      if (otpOrg || organization) {
        const found = await listUsers({
          serviceConfig,
          loginName: decoyLoginName(loginName),
          organizationId: organization,
        }).catch(() => undefined);
        const account = found?.details?.totalResult === BigInt(1) ? found.result[0] : undefined;
        const owner = account?.details?.resourceOwner;
        const realCustomer =
          !!account && (!organization || owner === organization) && (await isOtpFirstOrg(serviceConfig, owner));
        if (!realCustomer) {
          return decoyOtpAnswer({ loginName, organization: otpOrg ?? organization ?? "", tries: false, ip, t });
        }
      }
    }

    const userChecks = create(ChecksSchema, {
      user: { search: { case: "loginName", value: loginName } },
    });

    // the challenges are requested by the setSession call below, requesting them here as well would send every code twice
    const result = await createSessionAndUpdateCookie({
      checks: userChecks,
      requestId,
    }).catch((error) => {
      if (isClassifiedError(error) && error.isUserError) {
        logger.warn("Could not create session (client error)", { grpcCode: error.code, httpStatus: error.httpStatus });
      } else {
        logger.error("Could not create session (server error)", { error });
      }
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

  // AZDIGI: who may receive or try a code, and how often
  if (wantsOtpSend || triesOtpCode) {
    const current = await loadSession(serviceConfig, recentSession).catch(() => undefined);

    if (!current?.factors?.user?.id) {
      return { error: t("couldNotFindSession") };
    }
    const currentUserId = current.factors.user.id;
    userId = currentUserId;
    const organizationId = current.factors.user.organizationId;
    if (organization && organization !== organizationId) {
      return { error: t("couldNotFindSession") };
    }

    // the soft attempt limit comes first: a further wrong code would lock the user in Zitadel
    if (triesOtpCode) {
      const attempts = limiters.otpVerifyPerUser.hit(`user:${currentUserId}`);
      if (!attempts.allowed) {
        logger.warn("OTP verify rate limited", { userId: currentUserId, organizationId });
        return { error: t("tooManyCodeAttempts", { minutes: minutesUntil(attempts.retryAfterMs) }) };
      }
    }

    if (!hasVerifiedFirstFactor(current)) {
      // an OTP as the first factor: only for eligible users of allow-listed organisations
      const user = await getUserByID({ serviceConfig, userId: currentUserId })
        .then((r) => r.user)
        .catch(() => undefined);
      const decision = await decideOtpFirstForUser({
        serviceConfig,
        userId: currentUserId,
        organizationId,
        humanUser: user?.type.case === "human" ? user.type.value : undefined,
        userState: user?.state,
      });
      if (!decision.eligible && decision.reason === "setup-required") {
        const params = flowParams(current.factors.user.loginName, organizationId, requestId);
        params.set("invite", String(decision.invite));
        if (await sendVerificationOnce({ userId: currentUserId, isInvite: decision.invite, requestId })) {
          params.set("codeSent", "true");
        }
        return { error: t("otpFirstNotAllowed"), redirect: "/verify?" + params };
      }
      if (!decision.eligible && decision.reason === "user-state") {
        logger.warn("OTP-first refused", { userId: currentUserId, organizationId, reason: decision.reason });
        const unlockAt = await unlockEtaForUser(serviceConfig, currentUserId);
        return { error: unlockAt ? t("userLockedUntil", { time: unlockAt }) : t("userLocked"), locked: true };
      }
      if (!decision.eligible) {
        logger.warn("OTP-first refused", { userId: currentUserId, organizationId, reason: decision.reason });
        return {
          error: t("otpFirstNotAllowed"),
          redirect: "/password?" + flowParams(current.factors.user.loginName, organizationId, requestId),
        };
      }
    }

    if (wantsOtpSend) {
      const ip = clientIpFromHeaders(_headers);
      const perLogin = limiters.otpSendPerLogin.hit(`login:${organizationId}:${current.factors.user.loginName}`);
      const perIp = ip ? limiters.otpSendPerIp.hit(`ip:${ip}`) : { allowed: true, retryAfterMs: 0 };
      if (!perLogin.allowed || !perIp.allowed) {
        logger.warn("OTP send rate limited", {
          userId: currentUserId,
          organizationId,
          scope: perLogin.allowed ? "ip" : "login",
        });
        return {
          error: t("tooManyCodeRequests", { minutes: minutesUntil(Math.max(perLogin.retryAfterMs, perIp.retryAfterMs)) }),
        };
      }
    }
  }

  if (challenges?.otpSms) {
    const retryAfterSeconds = getOTPSMSRetryAfterSeconds(recentSession.otpSmsSentTs);
    if (retryAfterSeconds > 0) {
      // no error message: the UI shows the countdown on the resend button instead
      return { retryAfterSeconds };
    }
  }

  // The lifetime always comes from the login policy of the session's user (the cookie entry is
  // signed and its organization set from the session), never from the caller.
  const loginSettings = await getLoginSettings({ serviceConfig, organization: recentSession.organization ?? organization });

  let lifetime = checks?.webAuthN
    ? loginSettings?.multiFactorCheckLifetime // TODO different lifetime for webauthn u2f/passkey
    : checks?.totp || checks?.otpEmail || checks?.otpSms
      ? loginSettings?.secondFactorCheckLifetime
      : undefined;

  if (!lifetime || !lifetime.seconds) {
    logger.warn("No lifetime provided for session, defaulting to 24 hours");
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
    // AZDIGI: a wrong, unavailable or locked code is answered on the code screen, never by re-creating the session
    if (triesOtpCode) {
      const remaining = userId ? limiters.otpVerifyPerUser.peek(`user:${userId}`).remaining : 0;
      const mapped = otpErrorToResult(
        error,
        t,
        remaining,
        userId ? await unlockEtaForUser(serviceConfig, userId) : undefined,
      );
      if (mapped) {
        return mapped;
      }
    }

    // the code was already sent for this session: creating a new session with the same challenge would send
    // a second code, and the first one could not be verified against the new session
    if (error instanceof SessionUpdatedError && (challenges?.otpSms || challenges?.otpEmail)) {
      throw error;
    }

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
    // AZDIGI: a verified code ends the attempt window
    limiters.otpVerifyPerUser.clear(`user:${userId}`);
  }

  // @ts-ignore
  const challengeResponse: Challenges | undefined = session.challenges;

  // AZDIGI: asking for a code proves nothing yet: return no user id, organisation or display name to the browser
  // (the decoy answer could not return them either)
  if (wantsOtpSend && !checks) {
    return { retryAfterSeconds: challenges?.otpSms ? getOTPSMSResendCooldownSeconds() : undefined };
  }

  return {
    sessionId: session.id,
    factors: session.factors,
    // Only the WebAuthN challenge may reach the browser. `sanitizeChallenges` already stops
    // `returnCode` from being requested, so `otpSms`/`otpEmail` should always be unset here —
    // keeping the projection explicit means no OTP code can leak through this boundary even
    // if that ever regresses (GHSA-3gwm-5wx8-4gm6).
    challenges: challengeResponse?.webAuthN ? { webAuthN: challengeResponse.webAuthN } : undefined,
    // lets the UI count down until the next OTP SMS may be requested
    retryAfterSeconds: challenges?.otpSms ? getOTPSMSResendCooldownSeconds() : undefined,
  };
}

type ClearSessionOptions = {
  sessionId: string;
};

export async function clearSession(options: ClearSessionOptions): Promise<{ error?: string } | void> {
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  const { sessionId } = options;

  const sessionCookie = await getSessionCookieById({ sessionId });

  if (!sessionCookie) {
    return;
  }

  try {
    const deleteResponse = await deleteSession({
      serviceConfig,
      sessionId: sessionCookie.id,
      sessionToken: sessionCookie.token,
    });
    if (!deleteResponse) {
      throw new Error("Could not delete session");
    }
  } catch (error) {
    // The backend verifies the cookie's token before it looks at the session
    // state, so PermissionDenied is what a session that no longer exists answers
    // (nothing to verify against). It is also what a live session with a stale
    // cookie token would answer; we deliberately prune the cookie entry in that
    // case too: the user explicitly asked to remove the account from this
    // browser, and without its token the server-side session cannot be used by
    // anyone and simply expires. Every other failure keeps the entry and is
    // reported so the caller can show it.
    // (A session terminated by an RP-initiated logout keeps its token id, so
    // deleting it again succeeds and never reaches this branch.)
    if (!isClassifiedError(error) || error.code !== Code.PermissionDenied) {
      logger.error("clearSession: could not delete session", { sessionId: sessionCookie.id, error });
      const t = await getTranslations("error");
      return { error: t("couldNotClearSession") };
    }

    logger.warn("clearSession: session rejected the cookie token (gone or stale), pruning cookie entry", {
      sessionId: sessionCookie.id,
    });
  }

  // Only needed for the cookie rewrite, so it must not gate the delete above.
  const securitySettings = await getSecuritySettings({ serviceConfig });
  const iFrameEnabled = !!securitySettings?.embeddedIframe?.enabled;

  await removeSessionFromCookie({ session: sessionCookie, iFrameEnabled });
}
