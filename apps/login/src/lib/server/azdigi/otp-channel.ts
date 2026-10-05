"use server";

import { availableChannels, isOtpChannel, OTP_CHANNEL_METADATA_KEY, otpMethodForChannel, OtpChannel } from "@/lib/azdigi/otp-channel";
import { getServiceConfig } from "@/lib/service-url";
import { loadMostRecentSession } from "@/lib/session";
import { addOTPSMS, getUserByID, listAuthenticationMethodTypes, setUserMetadata } from "@/lib/zitadel";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { getTranslations } from "next-intl/server";
import { headers } from "next/headers";

export type SetOtpChannelCommand = {
  channel: OtpChannel;
  loginName?: string;
  organization?: string;
  requestId?: string;
  altPassword?: boolean;
};

/**
 * Stores the customer's channel choice (user metadata `azdigi.otp_channel`) and returns the OTP screen that requests
 * the code. Phone channels need a verified phone and the otp_sms factor, which is granted here like otp_email is
 * after a password (phase 4). Sending itself stays in updateOrCreateSession (rate limited, server-built challenge).
 */
export async function setOtpChannel(command: SetOtpChannelCommand): Promise<{ redirect: string } | { error: string }> {
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);
  const t = await getTranslations("otp.channel");

  // server-side too: a channel the picker does not offer (e.g. SMS while production is Zalo-only) is refused
  if (!isOtpChannel(command.channel) || !availableChannels().includes(command.channel)) {
    return { error: t("errors.unknownChannel") };
  }

  const session = await loadMostRecentSession({
    serviceConfig,
    sessionParams: { loginName: command.loginName, organization: command.organization },
  });
  const userId = session?.factors?.user?.id;
  if (!userId) {
    return { error: t("errors.noSession") };
  }

  if (command.channel !== "email") {
    const user = await getUserByID({ serviceConfig, userId }).then((r) => r.user).catch(() => undefined);
    const human = user?.type.case === "human" ? user.type.value : undefined;
    if (!human?.phone?.isVerified) {
      return { error: t("errors.phoneNotVerified") };
    }
    const methods = await listAuthenticationMethodTypes({ serviceConfig, userId });
    if (!methods.authMethodTypes?.includes(AuthenticationMethodType.OTP_SMS)) {
      await addOTPSMS({ serviceConfig, userId });
    }
  }

  try {
    await setUserMetadata({ serviceConfig, userId, key: OTP_CHANNEL_METADATA_KEY, value: command.channel });
  } catch (error) {
    console.warn("[azdigi] could not store the OTP channel", { userId, error: String(error) });
    return { error: t("errors.couldNotStore") };
  }

  const params = new URLSearchParams();
  if (command.loginName) params.append("loginName", command.loginName);
  if (command.organization) params.append("organization", command.organization);
  if (command.requestId) params.append("requestId", command.requestId);
  if (command.altPassword) params.append("altPassword", "true");
  return { redirect: `/otp/${otpMethodForChannel(command.channel)}?${params}` };
}
