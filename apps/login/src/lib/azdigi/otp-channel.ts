/**
 * Which channel carries the one-time code for a customer: email (Zitadel SMTP), or the phone via Zitadel's SMS
 * challenge, where the Identity Notifier (M2) delivers Zalo first with SMS as fallback. The choice is stored as user
 * metadata so the Notifier can read it by userId.
 */
export const OTP_CHANNEL_METADATA_KEY = "azdigi.otp_channel";

export const OTP_CHANNELS = ["email", "zalo", "sms"] as const;
export type OtpChannel = (typeof OTP_CHANNELS)[number];

export function isOtpChannel(value: unknown): value is OtpChannel {
  return typeof value === "string" && (OTP_CHANNELS as readonly string[]).includes(value);
}

/** The login route that requests the code for a channel (zalo and sms both ride Zitadel's otpSms challenge). */
export function otpMethodForChannel(channel: OtpChannel): "email" | "sms" {
  return channel === "email" ? "email" : "sms";
}

/** `+84901234567` → `*** *** 567`: never show the full number on the login screens. */
export function maskPhone(phone: string | undefined): string {
  const digits = (phone ?? "").replace(/\D/g, "");
  if (digits.length < 3) {
    return "***";
  }
  return `*** *** ${digits.slice(-3)}`;
}

/** Runtime switch (compose `AZDIGI_SMS_ENABLED`): the phone channels only make sense once a provider delivers them. */
export function smsChannelsEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.AZDIGI_SMS_ENABLED === "true";
}

/**
 * Phone channels offered once SMS delivery is enabled (compose `AZDIGI_SMS_CHANNELS`, default `zalo,sms`). Production
 * starts Zalo-only (no SMS provider yet): offering "SMS" there would promise a text message that never comes.
 */
export function phoneChannels(env: NodeJS.ProcessEnv = process.env): OtpChannel[] {
  if (!smsChannelsEnabled(env)) {
    return [];
  }
  const listed = (env.AZDIGI_SMS_CHANNELS ?? "zalo,sms").split(",").map((s) => s.trim());
  return (["zalo", "sms"] as const).filter((channel) => listed.includes(channel));
}

/** Every channel the customer may pick right now: email always, plus the enabled phone channels. */
export function availableChannels(env: NodeJS.ProcessEnv = process.env): OtpChannel[] {
  return ["email", ...phoneChannels(env)];
}
