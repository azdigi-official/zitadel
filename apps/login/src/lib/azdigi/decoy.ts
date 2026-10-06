import { LoginSettings } from "@zitadel/proto/zitadel/settings/v2/login_settings_pb";
import { getLoginSettings, ServiceConfig } from "../zitadel";
import { isOtpFirstOrg, resolveOtpFirstOrgIds } from "./org-lookup";
import { otpFirstAlternatives, otpFirstParams } from "./otp-first";

/**
 * Account enumeration (M4 security test, owner decision 06/10/2026): in a customer (OTP-first) context an unknown login
 * name gets the same screens as a real customer — the email-code page with the same parameters, a code request that
 * "succeeds" without sending anything, and the same wrong-code / too-many-attempts answers. Nothing is sent and no session
 * exists. Staff organisations use Zitadel's ignoreUnknownUsernames (fake password page) instead.
 */

/** Real redirects carry the user's preferred login name (lower-case email); a decoy must not echo the typed casing. */
export function decoyLoginName(loginName: string): string {
  return loginName.trim().toLowerCase();
}

/** The OTP-first organisation a decoy pretends the account lives in, or undefined when the context is not a customer one. */
export async function decoyOrganization(serviceConfig: ServiceConfig, contextOrg: string | undefined): Promise<string | undefined> {
  if (contextOrg) {
    return (await isOtpFirstOrg(serviceConfig, contextOrg)) ? contextOrg : undefined;
  }
  const ids = Array.from(await resolveOtpFirstOrgIds(serviceConfig));
  return ids.length === 1 ? ids[0] : undefined;
}

/**
 * Real and decoy answers of the first-factor steps both take at least this long (with jitter), so response time does not
 * tell them apart: the real path (user search, session, send) stays below it in normal operation.
 */
export async function withMinimumDuration<T>(run: () => Promise<T>, minMs = 900, jitterMs = 300): Promise<T> {
  const until = Date.now() + minMs + Math.random() * jitterMs;
  try {
    return await run();
  } finally {
    const left = until - Date.now();
    if (left > 0) await new Promise((resolve) => setTimeout(resolve, left));
  }
}

/** `/otp/email?…` exactly as a real customer without a password gets it, or undefined outside a customer context. */
export async function decoyOtpRedirect(
  serviceConfig: ServiceConfig,
  { loginName, contextOrg, requestId }: { loginName: string; contextOrg: string | undefined; requestId?: string },
): Promise<{ redirect: string } | undefined> {
  const organization = await decoyOrganization(serviceConfig, contextOrg);
  if (!organization || !loginName.trim()) {
    return undefined;
  }
  const loginSettings = await getLoginSettings({ serviceConfig, organization, fresh: true });
  const params = otpFirstParams({ loginName: decoyLoginName(loginName), organization, requestId, ...otpFirstAlternatives(loginSettings) });
  return { redirect: "/otp/email?" + params };
}

/**
 * Password and password-reset answers in the OTP-first organisation follow Zitadel's ignoreUnknownUsernames behaviour
 * (generic "could not authenticate", silent reset), as the email-code page offers the password link to everyone.
 */
export async function hidingUnknownAccounts(
  serviceConfig: ServiceConfig,
  settings: LoginSettings | undefined,
  organization: string | undefined,
): Promise<LoginSettings | undefined> {
  if (!settings || settings.ignoreUnknownUsernames || !(await isOtpFirstOrg(serviceConfig, organization))) {
    return settings;
  }
  return { ...settings, ignoreUnknownUsernames: true } as LoginSettings;
}
