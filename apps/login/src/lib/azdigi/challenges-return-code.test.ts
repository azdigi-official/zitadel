import { create } from "@zitadel/client";
import { RequestChallengesSchema } from "@zitadel/proto/zitadel/session/v2/challenge_pb";
import { describe, expect, test } from "vitest";
import { withoutReturnedCodes } from "./challenges";

describe("challenges as they may reach Zitadel", () => {
  test("a code is never asked back: returnCode for email is dropped, for SMS switched off", () => {
    const asked = create(RequestChallengesSchema, {
      otpEmail: { deliveryType: { case: "returnCode", value: {} } },
      otpSms: { returnCode: true },
    });
    const safe = withoutReturnedCodes(asked);
    expect(safe?.otpEmail).toBeUndefined();
    expect(safe?.otpSms?.returnCode).toBe(false);
  });

  test("a code that is sent to the user, and a passkey challenge, pass through", () => {
    const asked = create(RequestChallengesSchema, {
      otpEmail: { deliveryType: { case: "sendCode", value: { urlTemplate: "https://login.test/otp/email?code={{.Code}}" } } },
      webAuthN: { domain: "login.test", userVerificationRequirement: 1 },
    });
    const safe = withoutReturnedCodes(asked);
    expect(safe?.otpEmail?.deliveryType.case).toBe("sendCode");
    expect(safe?.webAuthN?.domain).toBe("login.test");
  });

  test("nothing asked, nothing sent", () => {
    expect(withoutReturnedCodes(undefined)).toBeUndefined();
    expect(withoutReturnedCodes(create(RequestChallengesSchema, { otpEmail: { deliveryType: { case: "returnCode", value: {} } } }))).toBeUndefined();
  });
});
