"use server";

import { createSessionAndUpdateCookie, createSessionForIdpAndUpdateCookie } from "@/lib/server/cookie";
import { addHumanUser, addIDPLink, getLoginSettings, getUserByID, listAuthenticationMethodTypes } from "@/lib/zitadel";
import { create } from "@zitadel/client";
import { Factors } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { ChecksJson, ChecksSchema } from "@zitadel/proto/zitadel/session/v2/session_service_pb";
import { cookies, headers } from "next/headers";
import { getTranslations } from "next-intl/server";
import { getServiceConfig } from "../service-url";
import { checkEmailVerification, checkMFAFactors } from "../verify-helper";
import { getOrSetFingerprintId } from "../fingerprint";
import crypto from "crypto";
import { completeFlowOrGetUrl } from "../client";
import { resolveOrgIdByName } from "../azdigi/org-lookup";

type RegisterUserCommand = {
  email: string;
  firstName: string;
  lastName: string;
  password?: string;
  /** AZDIGI: ignored — self-registration always lands in the organisation named by AZDIGI_REGISTER_ORG_NAME */
  organization: string;
  requestId?: string;
  /** AZDIGI: "otp" registers without password or passkey; the email code becomes the first factor after verification */
  method?: "otp" | "passkey" | "password";
};

/** The organisation self-registration lands in (compose AZDIGI_REGISTER_ORG_NAME, default "AZDIGI Customers"). */
export async function registrationOrgId(serviceConfig: Parameters<typeof getLoginSettings>[0]["serviceConfig"]) {
  return resolveOrgIdByName(serviceConfig, process.env.AZDIGI_REGISTER_ORG_NAME || "AZDIGI Customers");
}

export type RegisterUserResponse = {
  userId: string;
  sessionId: string;
  factors: Factors | undefined;
};
export async function registerUser(
  command: RegisterUserCommand,
): Promise<{ error: string } | { redirect: string } | { samlData: { url: string; fields: Record<string, string> } }> {
  const t = await getTranslations("register");
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  // AZDIGI: the client never chooses the organisation, and the policy is read fresh before creating anything
  const organization = await registrationOrgId(serviceConfig);
  if (!organization) {
    return { error: t("disabled.description") };
  }
  const loginSettings = await getLoginSettings({ serviceConfig, organization, fresh: true });
  if (!loginSettings?.allowRegister) {
    return { error: t("disabled.description") };
  }
  if (command.method === "otp") {
    command.password = undefined;
  }

  const addResponse = await addHumanUser({
    serviceConfig,
    email: command.email,
    firstName: command.firstName,
    lastName: command.lastName,
    password: command.password ? command.password : undefined,
    organization,
  });

  if (!addResponse) {
    return { error: t("errors.couldNotCreateUser") };
  }

  let checkPayload: any = {
    user: { search: { case: "userId", value: addResponse.userId } },
  };

  if (command.password) {
    checkPayload = {
      ...checkPayload,
      password: { password: command.password },
    } as ChecksJson;
  }

  const checks = create(ChecksSchema, checkPayload);

  // AZDIGI: the user projection may lag a moment behind AddHumanUser ("User could not be found (QUERY-Dfbg2)"
  // seen on v4.11); retry the session creation briefly instead of failing the registration
  let result: Awaited<ReturnType<typeof createSessionAndUpdateCookie>> | undefined;
  for (let attempt = 0; attempt < 6; attempt++) {
    try {
      result = await createSessionAndUpdateCookie({
        checks,
        requestId: command.requestId,
        lifetime: command.password ? loginSettings?.passwordCheckLifetime : undefined,
      });
      break;
    } catch (error) {
      const notFound = (error as { code?: unknown })?.code === 5;
      if (!notFound || attempt === 5) {
        throw error;
      }
      await new Promise((resolve) => setTimeout(resolve, 250 * (attempt + 1)));
    }
  }
  const session = result?.session;

  if (!session || !session.factors?.user) {
    return { error: t("errors.couldNotCreateSession") };
  }

  if (!command.password) {
    const params = new URLSearchParams({
      loginName: session.factors.user.loginName,
      organization: session.factors.user.organizationId,
    });

    if (command.requestId) {
      params.append("requestId", command.requestId);
    }

    // AZDIGI: email-code registration — verify the address first; verify.ts then grants otp_email and the policy
    // sends the user to /otp/email (no passkey, no password)
    if (command.method === "otp") {
      params.set("userId", session.factors.user.id);
      params.set("send", "true");
      return { redirect: "/verify?" + params };
    }

    // Set verification cookie for users registering with passkey (no password)
    // This allows them to proceed with passkey registration without additional verification
    const cookiesList = await cookies();
    const userAgentId = await getOrSetFingerprintId();

    const verificationCheck = crypto.createHash("sha256").update(`${session.factors.user.id}:${userAgentId}`).digest("hex");

    await cookiesList.set({
      name: "verificationCheck",
      value: verificationCheck,
      httpOnly: true,
      path: "/",
      maxAge: 300, // 5 minutes
    });

    return { redirect: "/passkey/set?" + params };
  } else {
    const userResponse = await getUserByID({ serviceConfig, userId: session?.factors?.user?.id });

    if (!userResponse.user) {
      return { error: t("errors.userNotFound") };
    }

    const humanUser = userResponse.user.type.case === "human" ? userResponse.user.type.value : undefined;

    const emailVerificationCheck = checkEmailVerification(
      session,
      humanUser,
      session.factors.user.organizationId,
      command.requestId,
    );

    if (emailVerificationCheck?.redirect) {
      return emailVerificationCheck;
    }

    return completeFlowOrGetUrl(
      command.requestId && session.id
        ? {
            sessionId: session.id,
            requestId: command.requestId,
            organization: session.factors.user.organizationId,
          }
        : {
            loginName: session.factors.user.loginName,
            organization: session.factors.user.organizationId,
          },
      loginSettings?.defaultRedirectUri,
    );
  }
}

type RegisterUserAndLinkToIDPommand = {
  email: string;
  firstName: string;
  lastName: string;
  organization: string;
  requestId?: string;
  idpIntent: {
    idpIntentId: string;
    idpIntentToken: string;
  };
  idpUserId: string;
  idpId: string;
  idpUserName: string;
};

export type registerUserAndLinkToIDPResponse = {
  userId: string;
  sessionId: string;
  factors: Factors | undefined;
};
export async function registerUserAndLinkToIDP(
  command: RegisterUserAndLinkToIDPommand,
): Promise<{ error: string } | { redirect: string } | { samlData: { url: string; fields: Record<string, string> } }> {
  const t = await getTranslations("register");

  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  const addUserResponse = await addHumanUser({
    serviceConfig,
    email: command.email,
    firstName: command.firstName,
    lastName: command.lastName,
    organization: command.organization,
  });

  if (!addUserResponse) {
    return { error: t("errors.couldNotCreateUser") };
  }

  const loginSettings = await getLoginSettings({ serviceConfig, organization: command.organization });

  const idpLink = await addIDPLink({
    serviceConfig,
    idp: {
      id: command.idpId,
      userId: command.idpUserId,
      userName: command.idpUserName,
    },
    userId: addUserResponse.userId,
  });

  if (!idpLink) {
    return { error: t("errors.couldNotLinkIDP") };
  }

  const session = await createSessionForIdpAndUpdateCookie({
    requestId: command.requestId,
    userId: addUserResponse.userId, // the user we just created
    idpIntent: command.idpIntent,
    lifetime: loginSettings?.externalLoginCheckLifetime,
  });

  if (!session || !session.factors?.user) {
    return { error: t("errors.couldNotCreateSession") };
  }

  // const userResponse = await getUserByID({
  //   serviceConfig.baseUrl,
  //   userId: session?.factors?.user?.id,
  // });

  // if (!userResponse.user) {
  //   return { error: "User not found in the system" };
  // }

  // const humanUser = userResponse.user.type.case === "human" ? userResponse.user.type.value : undefined;

  // check to see if user was verified
  // const emailVerificationCheck = checkEmailVerification(session, humanUser, command.organization, command.requestId);

  // if (emailVerificationCheck?.redirect) {
  //   return emailVerificationCheck;
  // }

  // check if user has MFA methods
  let authMethods;
  if (session.factors?.user?.id) {
    const response = await listAuthenticationMethodTypes({ serviceConfig, userId: session.factors.user.id });
    if (response.authMethodTypes && response.authMethodTypes.length) {
      authMethods = response.authMethodTypes;
    }
  }

  // Always check MFA factors, even if no auth methods are configured
  // This ensures that force MFA settings are respected
  const mfaFactorCheck = await checkMFAFactors(
    serviceConfig,
    session,
    loginSettings,
    authMethods || [], // Pass empty array if no auth methods
    command.organization,
    command.requestId,
  );

  if (mfaFactorCheck?.redirect) {
    return mfaFactorCheck;
  }

  return completeFlowOrGetUrl(
    command.requestId && session.id
      ? {
          sessionId: session.id,
          requestId: command.requestId,
          organization: session.factors.user.organizationId,
        }
      : {
          loginName: session.factors.user.loginName,
          organization: session.factors.user.organizationId,
        },
    loginSettings?.defaultRedirectUri,
  );
}
