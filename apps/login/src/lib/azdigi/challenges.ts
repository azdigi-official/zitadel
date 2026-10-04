import { create } from "@zitadel/client";
import { RequestChallenges, RequestChallengesSchema } from "@zitadel/proto/zitadel/session/v2/challenge_pb";

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
