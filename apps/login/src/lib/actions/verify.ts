"use server";

import { createLogger } from "@/lib/server/logger";
import {
  addOTPEmail,
  createInviteCode,
  getLoginSettings,
  getSession,
  getUserByID,
  listAuthenticationMethodTypes,
  verifyEmail,
  verifyInviteCode,
  verifyTOTPRegistration,
  sendEmailCode as zitadelSendEmailCode,
} from "@/lib/server/zitadel";

import { completeFlowOrGetUrl } from "@/lib/actions/flow";
import { clientIpFromHeaders } from "@/lib/azdigi/client-ip";
import { enrolmentAuthorizationError } from "@/lib/azdigi/enrolment-guard";
import { isOtpFirstOrg } from "@/lib/azdigi/org-lookup";
import { claimVerifyPageSend, limiters } from "@/lib/azdigi/rate-limit";
import { getSessionCookieByLoginName } from "@/lib/server/cookies";
import { getPublicHostWithProtocol } from "@/lib/server/host";
import { checkMFAFactors } from "@/lib/server/mfa-helper";
import { getServiceConfig } from "@/lib/server/service-url";
import { loadMostRecentSession } from "@/lib/server/session";
import { createSessionAndUpdateCookie } from "@/lib/server/session-cookie";
import { setUserVerificationCheckCookie } from "@/lib/server/verification-check";
import { buildVerificationUrlTemplate } from "@/lib/server/verification-email";
import { create } from "@zitadel/client";
import { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { ChecksSchema } from "@zitadel/proto/zitadel/session/v2/session_service_pb";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { getTranslations } from "next-intl/server";
import { headers } from "next/headers";

const logger = createLogger("verify");

export async function verifyTOTP(code: string, loginName?: string, organization?: string) {
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  return loadMostRecentSession({
    serviceConfig,
    sessionParams: {
      loginName,
      organization,
    },
  }).then(async (session) => {
    if (session?.factors?.user?.id) {
      // Enrollment must be authorized: a bare identify-only session must not be able to
      // activate a TOTP factor on the account (GHSA-45f2-5q3r-xgg6).
      // AZDIGI: an authenticator can satisfy the second factor on its own (lib/azdigi/enrolment-guard.ts)
      const enrollmentError = await enrolmentAuthorizationError({
        serviceConfig,
        session,
        userId: session.factors.user.id,
        kind: "strong",
      });
      if (enrollmentError) {
        return { error: enrollmentError };
      }

      return verifyTOTPRegistration({ serviceConfig, code, userId: session.factors.user.id });
    } else {
      throw Error("No user id found in session.");
    }
  });
}

type VerifyUserByEmailCommand = {
  userId: string;
  loginName?: string; // to determine already existing session
  organization?: string;
  code: string;
  isInvite: boolean;
  requestId?: string;
};

export async function sendVerification(command: VerifyUserByEmailCommand) {
  const t = await getTranslations("verify");
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  const verifyResponse = command.isInvite
    ? await verifyInviteCode({ serviceConfig, userId: command.userId, verificationCode: command.code }).catch((error) => {
        logger.warn("Could not verify invite:", { error });
        return { error: t("errors.couldNotVerifyInvite") };
      })
    : await verifyEmail({ serviceConfig, userId: command.userId, verificationCode: command.code }).catch((error) => {
        logger.warn("Could not verify email:", { error });
        return { error: t("errors.couldNotVerifyEmail") };
      });

  if ("error" in verifyResponse) {
    return verifyResponse;
  }

  if (!verifyResponse) {
    return { error: t("errors.couldNotVerify") };
  }

  let session: Session | undefined;
  const userResponse = await getUserByID({ serviceConfig, userId: command.userId });

  if (!userResponse || !userResponse.user) {
    return { error: t("errors.couldNotLoadUser") };
  }

  const user = userResponse.user;

  const sessionCookie = await getSessionCookieByLoginName({
    loginName: command.loginName ?? user.preferredLoginName,
    organization: command.organization,
  });

  if (sessionCookie) {
    session = await getSession({ serviceConfig, sessionId: sessionCookie.id, sessionToken: sessionCookie.token })
      .then((response) => {
        if (response?.session) {
          return response.session;
        }
      })
      .catch((error) => {
        // user session is not found, so we create a new one
        logger.warn("[verify] user session is not found, so we create a new one", { error });
        return undefined;
      });
  }

  // load auth methods for user
  const authMethodResponse = await listAuthenticationMethodTypes({ serviceConfig, userId: user.userId });

  if (!authMethodResponse || !authMethodResponse.authMethodTypes) {
    return { error: t("errors.couldNotLoadAuthenticators") };
  }

  const hasPrimaryMethod =
    authMethodResponse?.authMethodTypes?.some(
      (m: AuthenticationMethodType) =>
        m === AuthenticationMethodType.PASSWORD ||
        m === AuthenticationMethodType.PASSKEY ||
        m === AuthenticationMethodType.IDP,
    ) ?? false;

  // AZDIGI: in the OTP-first organisation the email code is the first factor of a freshly verified customer: grant
  // OTP_EMAIL (the address was just verified) and continue to /otp/email instead of the authenticator set-up
  const otpFirstOrg = user.type?.case === "human" && (await isOtpFirstOrg(serviceConfig, user.details?.resourceOwner));
  if (otpFirstOrg && !hasPrimaryMethod && !authMethodResponse.authMethodTypes.includes(AuthenticationMethodType.OTP_EMAIL)) {
    const granted = await addOTPEmail({ serviceConfig, userId: user.userId })
      .then(() => true)
      .catch((error: unknown) => {
        logger.warn("could not add the OTP_EMAIL method after verification", { userId: user.userId, error: String(error) });
        return false;
      });
    if (granted) {
      authMethodResponse.authMethodTypes = [...authMethodResponse.authMethodTypes, AuthenticationMethodType.OTP_EMAIL];
    }
  }
  const otpFirstReady = otpFirstOrg && authMethodResponse.authMethodTypes.includes(AuthenticationMethodType.OTP_EMAIL);

  // if no primary auth methods are found on the user, redirect to set one up
  if (!hasPrimaryMethod && !otpFirstReady) {
    if (!session) {
      const checks = create(ChecksSchema, {
        user: {
          search: {
            case: "loginName",
            value: userResponse.user.preferredLoginName,
          },
        },
      });

      const result = await createSessionAndUpdateCookie({
        checks,
        requestId: command.requestId,
      });
      session = result.session;
    }

    if (!session) {
      return { error: t("errors.couldNotCreateSession") };
    }

    const params = new URLSearchParams({
      sessionId: session.id,
    });

    if (session.factors?.user?.loginName) {
      params.set("loginName", session.factors?.user?.loginName);
    }

    if (command.requestId) {
      params.set("requestId", command.requestId);
    }

    // remember the successful verification for this browser (signed with a server-only secret),
    // checks are done for users with invalid sessions and invalid userAgentId
    await setUserVerificationCheckCookie(user.userId);

    return { redirect: `/authenticator/set?${params}` };
  }

  // if no session found only show success page,
  // if user is invited, recreate invite flow to not depend on session
  if (!session?.factors?.user?.id) {
    const verifySuccessParams = new URLSearchParams({});

    if (command.userId) {
      verifySuccessParams.set("userId", command.userId);
    }

    if (("loginName" in command && command.loginName) || user.preferredLoginName) {
      verifySuccessParams.set(
        "loginName",
        "loginName" in command && command.loginName ? command.loginName : user.preferredLoginName,
      );
    }
    if (command.requestId) {
      verifySuccessParams.set("requestId", command.requestId);
    }
    if (command.organization) {
      verifySuccessParams.set("organization", command.organization);
    }

    return { redirect: `/verify/success?${verifySuccessParams}` };
  }

  // AZDIGI: fresh, these settings decide the next factor
  const loginSettings = await getLoginSettings({ serviceConfig, organization: user.details?.resourceOwner, fresh: true });

  // redirect to mfa factor if user has one, or redirect to set one up
  const mfaFactorCheck = await checkMFAFactors(
    serviceConfig,
    session,
    loginSettings,
    authMethodResponse.authMethodTypes,
    command.organization,
    command.requestId,
    { otpFirstOrg },
  );

  if (mfaFactorCheck?.redirect) {
    // AZDIGI: presentation context only, the OTP page checks the live verified email before showing success
    if (mfaFactorCheck.redirect.startsWith("/otp/email?")) {
      const params = new URLSearchParams(mfaFactorCheck.redirect.split("?")[1]);
      params.set("emailVerified", "true");
      return { redirect: "/otp/email?" + params };
    }
    return mfaFactorCheck;
  }

  // login user if no additional steps are required
  if (command.requestId && session.id) {
    return completeFlowOrGetUrl(
      {
        sessionId: session.id,
        requestId: command.requestId,
        organization: command.organization ?? session.factors?.user?.organizationId,
      },
      loginSettings?.defaultRedirectUri,
    );
  }

  // Regular flow - return URL for client-side navigation
  return completeFlowOrGetUrl(
    {
      loginName: session.factors.user.loginName,
      organization: session.factors?.user?.organizationId,
    },
    loginSettings?.defaultRedirectUri,
  );
}

type resendVerifyEmailCommand = {
  userId: string;
  isInvite: boolean;
  requestId?: string;
};

export async function resendVerification(command: resendVerifyEmailCommand) {
  const t = await getTranslations("verify");
  const _headers = await headers();

  // AZDIGI: a published action that mails any user id it is given, before sign-in. Every new code voids the previous
  // one, so it is held to the client IP's code budget (the same limiter as code requests; the IP comes only from the
  // proxy's trusted header) and to one mail per user and kind per minute, shared with the automatic send.
  const ip = clientIpFromHeaders(_headers);
  const perIp = ip ? limiters.otpSendPerIp.hit(`ip:${ip}`) : { allowed: true, retryAfterMs: 0 };
  if (!perIp.allowed) {
    return { error: t("errors.tooManyCodeRequests", { minutes: Math.max(1, Math.ceil(perIp.retryAfterMs / 60000)) }) };
  }
  if (!claimVerifyPageSend(command.userId, command.isInvite ? "invite" : "email")) {
    return { error: t("errors.tooManyCodeRequests", { minutes: 1 }) };
  }

  const { serviceConfig } = getServiceConfig(_headers);
  const hostWithProtocol = await getPublicHostWithProtocol(_headers);

  const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? "";
  const urlTemplate = buildVerificationUrlTemplate(hostWithProtocol, basePath, command.isInvite, command.requestId);

  return command.isInvite
    ? createInviteCode({
        serviceConfig,
        userId: command.userId,
        urlTemplate,
      }).catch((error) => {
        if (error.code === 9) {
          return { error: t("errors.userAlreadyVerified") };
        }
        return { error: t("errors.couldNotResendInvite") };
      })
    : zitadelSendEmailCode({
        serviceConfig,
        userId: command.userId,
        urlTemplate,
      });
}
