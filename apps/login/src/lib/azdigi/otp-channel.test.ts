import { describe, expect, test } from "vitest";
import { isOtpChannel, maskPhone, otpMethodForChannel, smsChannelsEnabled } from "./otp-channel";

describe("otp channel helpers", () => {
  test("channels and their OTP route", () => {
    expect(isOtpChannel("zalo")).toBe(true);
    expect(isOtpChannel("pigeon")).toBe(false);
    expect(otpMethodForChannel("email")).toBe("email");
    expect(otpMethodForChannel("zalo")).toBe("sms");
    expect(otpMethodForChannel("sms")).toBe("sms");
  });
  test("phone is masked to its last three digits", () => {
    expect(maskPhone("+84901234567")).toBe("*** *** 567");
    expect(maskPhone("12")).toBe("***");
    expect(maskPhone(undefined)).toBe("***");
  });
  test("phone channels are off unless AZDIGI_SMS_ENABLED=true", () => {
    expect(smsChannelsEnabled({} as any)).toBe(false);
    expect(smsChannelsEnabled({ AZDIGI_SMS_ENABLED: "true" } as any)).toBe(true);
  });
});
