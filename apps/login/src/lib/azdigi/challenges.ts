import { create } from "@zitadel/client";
import { RequestChallenges, RequestChallengesSchema } from "@zitadel/proto/zitadel/session/v2/challenge_pb";

/**
 * Challenges as they may reach Zitadel: a code is always SENT to the user, never returned to the caller. Whoever gets
 * the code back holds the factor; nothing in the login needs it.
 */
export function withoutReturnedCodes(challenges: RequestChallenges | undefined): RequestChallenges | undefined {
  if (!challenges) {
    return undefined;
  }
  const safe: Record<string, unknown> = {};
  if (challenges.webAuthN) safe.webAuthN = challenges.webAuthN;
  if (challenges.otpSms) safe.otpSms = { returnCode: false };
  if (challenges.otpEmail && challenges.otpEmail.deliveryType.case === "sendCode") safe.otpEmail = challenges.otpEmail;
  return Object.keys(safe).length ? create(RequestChallengesSchema, safe) : undefined;
}

/** Server-built challenges: sendCode with our own link template, never returnCode, WebAuthn domain = login host. */
export function buildServerChallenges(
  requested: RequestChallenges | undefined,
  host: string,
  requestId?: string,
): RequestChallenges | undefined {
  if (!requested) {
    return undefined;
  }
  const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? "";
  const origin = `${host.includes("localhost") ? "http://" : "https://"}${host}`;
  const built: Record<string, unknown> = {};
  if (requested.otpEmail) {
    built.otpEmail = {
      deliveryType: {
        case: "sendCode",
        value: {
          urlTemplate:
            `${origin}${basePath}/otp/email?code={{.Code}}&userId={{.UserID}}&sessionId={{.SessionID}}` +
            (requestId ? `&requestId=${encodeURIComponent(requestId)}` : ""),
        },
      },
    };
  }
  if (requested.otpSms) {
    built.otpSms = { returnCode: false };
  }
  if (requested.webAuthN) {
    const [hostname] = host.split(":");
    built.webAuthN = { domain: hostname, userVerificationRequirement: requested.webAuthN.userVerificationRequirement };
  }
  return Object.keys(built).length ? create(RequestChallengesSchema, built) : undefined;
}
