import { LoginSettings, PasskeysType } from "@zitadel/proto/zitadel/settings/v2/login_settings_pb";
import { HumanUser, UserState } from "@zitadel/proto/zitadel/user/v2/user_pb";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { getLoginSettings, listAuthenticationMethodTypes, ServiceConfig } from "../zitadel";
import { isOtpFirstOrg } from "./org-lookup";

/**
 * Who may sign in with an email code and nothing else: a user of an allow-listed organisation whose fresh login
 * policy does not force MFA, who has the OTP_EMAIL method and a verified email, and who is active.
 */
export type OtpFirstDecision =
  | { eligible: true; altPassword: boolean; altPasskey: boolean }
  | { eligible: false; reason: "org" | "forceMfa" | "no-otp-email-method" | "email-unverified" | "user-state" };

export type OtpFirstInput = {
  otpFirstOrg: boolean;
  loginSettings: LoginSettings | undefined;
  authMethods: AuthenticationMethodType[] | undefined;
  emailVerified: boolean;
  userState?: UserState;
};

export function decideOtpFirst({ otpFirstOrg, loginSettings, authMethods, emailVerified, userState }: OtpFirstInput): OtpFirstDecision {
  if (!otpFirstOrg) {
    return { eligible: false, reason: "org" };
  }
  if (!loginSettings || loginSettings.forceMfa) {
    return { eligible: false, reason: "forceMfa" };
  }
  if (!authMethods?.includes(AuthenticationMethodType.OTP_EMAIL)) {
    return { eligible: false, reason: "no-otp-email-method" };
  }
  if (!emailVerified) {
    return { eligible: false, reason: "email-unverified" };
  }
  if (userState !== undefined && userState !== UserState.ACTIVE) {
    return { eligible: false, reason: "user-state" };
  }
  return {
    eligible: true,
    altPassword: authMethods.includes(AuthenticationMethodType.PASSWORD),
    altPasskey: authMethods.includes(AuthenticationMethodType.PASSKEY) && loginSettings.passkeysType === PasskeysType.ALLOWED,
  };
}

/**
 * The "use your password / passkey instead" links on the email-code page come from the organisation's policy, not from
 * the account's methods: an account with a password must look like one without (and like an unknown name, decoy.ts).
 * Owner decision 06/10/2026.
 */
export function otpFirstAlternatives(loginSettings: LoginSettings | undefined): { altPassword: boolean; altPasskey: boolean } {
  const local = !!loginSettings?.allowLocalAuthentication;
  return {
    altPassword: local && !!loginSettings?.allowUsernamePassword,
    altPasskey: local && loginSettings?.passkeysType === PasskeysType.ALLOWED,
  };
}

/** Same decision from live data (fresh settings, allow-list lookup, auth methods). */
export async function decideOtpFirstForUser({
  serviceConfig,
  userId,
  organizationId,
  humanUser,
  userState,
  authMethods,
}: {
  serviceConfig: ServiceConfig;
  userId: string;
  organizationId: string | undefined;
  humanUser: HumanUser | undefined;
  userState?: UserState;
  authMethods?: AuthenticationMethodType[];
}): Promise<OtpFirstDecision> {
  const otpFirstOrg = await isOtpFirstOrg(serviceConfig, organizationId);
  if (!otpFirstOrg) {
    return { eligible: false, reason: "org" };
  }
  const [loginSettings, methods] = await Promise.all([
    getLoginSettings({ serviceConfig, organization: organizationId, fresh: true }),
    authMethods ? Promise.resolve(authMethods) : listAuthenticationMethodTypes({ serviceConfig, userId }).then((r) => r.authMethodTypes),
  ]);
  return decideOtpFirst({
    otpFirstOrg,
    loginSettings,
    authMethods: methods,
    emailVerified: !!humanUser?.email?.isVerified,
    userState,
  });
}

/** Query string for /otp/email when OTP-first applies. */
export function otpFirstParams({
  loginName,
  organization,
  requestId,
  altPassword,
  altPasskey = false,
}: {
  loginName: string;
  organization?: string;
  requestId?: string;
  altPassword: boolean;
  altPasskey?: boolean;
}): URLSearchParams {
  const params = new URLSearchParams({ loginName, altPassword: `${altPassword}` });
  if (altPasskey) params.append("altPasskey", "true");
  if (organization) params.append("organization", organization);
  if (requestId) params.append("requestId", requestId);
  return params;
}
