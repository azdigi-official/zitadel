// AZDIGI: the way forward when an enrolment page is refused because a configured second factor must be verified first
// (upstream v4.20.5, `SECOND_FACTOR_REQUIRED_ERROR`). Instead of a dead end the page offers one button to the screen
// that verifies a factor the user has, and that screen comes back to the enrolment page afterwards (enrolment-return.ts).
// This only shows the path; the enrolment gate on the server is unchanged and decides again when the user comes back.
import "server-only";

import { getUserMetadata, ServiceConfig } from "@/lib/server/zitadel";
import { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { enrolmentReturnTarget } from "./enrolment-return";
import { registeredMethodsOf } from "./issue";
import { OTP_CHANNEL_METADATA_KEY, phoneChannels } from "./otp-channel";

/** Which text and button label the page shows (`azdigiEnrol.<kind>` in the locales). */
export type SecondFactorStepKind = "emailCode" | "phoneCode" | "totp" | "u2f" | "choose";

export type SecondFactorStep = { kind: SecondFactorStepKind; href: string };

const M = AuthenticationMethodType;
const SECOND_FACTORS = [M.TOTP, M.U2F, M.OTP_EMAIL, M.OTP_SMS];

/**
 * Picks the screen from the user's configured second factors:
 * - codes only (email and/or SMS/Zalo): the code screen of the channel the user chose (user metadata, as on the code
 *   screen itself), email otherwise; the code is sent there like at every sign-in, under the same limits;
 * - a single authenticator app or security key: its screen;
 * - several kinds: the chooser (`/mfa`).
 * Returns undefined when the methods cannot be read or the user has no second factor (then the gate's reason was
 * something else and the page shows its message only).
 */
export function pickSecondFactorStep(
  methods: AuthenticationMethodType[],
  storedChannel: string | undefined,
  phoneChannelsOffered: boolean,
): { kind: SecondFactorStepKind; path: string } | undefined {
  const factors = SECOND_FACTORS.filter((method) => methods.includes(method));
  if (factors.length === 0) {
    return undefined;
  }
  const codesOnly = factors.every((method) => method === M.OTP_EMAIL || method === M.OTP_SMS);
  if (codesOnly) {
    const phoneChosen = (storedChannel === "zalo" || storedChannel === "sms") && phoneChannelsOffered;
    const useSms = factors.includes(M.OTP_SMS) && (!factors.includes(M.OTP_EMAIL) || phoneChosen);
    return useSms ? { kind: "phoneCode", path: "/otp/sms" } : { kind: "emailCode", path: "/otp/email" };
  }
  if (factors.length === 1 && factors[0] === M.TOTP) {
    return { kind: "totp", path: "/otp/time-based" };
  }
  if (factors.length === 1 && factors[0] === M.U2F) {
    return { kind: "u2f", path: "/u2f" };
  }
  return { kind: "choose", path: "/mfa" };
}

export async function secondFactorStep({
  serviceConfig,
  session,
  returnTo,
  requestId,
}: {
  serviceConfig: ServiceConfig;
  session: Session;
  /** the enrolment page to come back to (validated again here) */
  returnTo: string;
  requestId?: string;
}): Promise<SecondFactorStep | undefined> {
  const user = session.factors?.user;
  if (!user?.id) {
    return undefined;
  }
  const methods = await registeredMethodsOf(serviceConfig, user.id);
  if (!methods) {
    return undefined;
  }
  const storedChannel = methods.includes(M.OTP_SMS)
    ? await getUserMetadata({ serviceConfig, userId: user.id, key: OTP_CHANNEL_METADATA_KEY }).catch(() => undefined)
    : undefined;
  const picked = pickSecondFactorStep(methods, storedChannel, phoneChannels().length > 0);
  if (!picked) {
    return undefined;
  }

  const params = new URLSearchParams();
  if (user.loginName) params.set("loginName", user.loginName);
  if (user.organizationId) params.set("organization", user.organizationId);
  if (session.id) params.set("sessionId", session.id);
  if (requestId) params.set("requestId", requestId);
  // the security-key screen has no way back; after it the flow ends at /account, where the button now succeeds
  const target = enrolmentReturnTarget(returnTo);
  if (target && picked.kind !== "u2f") params.set("returnTo", target);
  return { kind: picked.kind, href: `${picked.path}?${params}` };
}
