import { describe, expect, test } from "vitest";
import { availableChannels, isOtpChannel, maskPhone, otpMethodForChannel, phoneChannels, smsChannelsEnabled } from "./otp-channel";

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
  test("phone channels follow AZDIGI_SMS_CHANNELS; Zalo-only never offers SMS", () => {
    expect(phoneChannels({} as any)).toEqual([]);
    expect(phoneChannels({ AZDIGI_SMS_CHANNELS: "zalo" } as any)).toEqual([]);
    expect(phoneChannels({ AZDIGI_SMS_ENABLED: "true" } as any)).toEqual(["zalo", "sms"]);
    expect(phoneChannels({ AZDIGI_SMS_ENABLED: "true", AZDIGI_SMS_CHANNELS: " zalo " } as any)).toEqual(["zalo"]);
    expect(phoneChannels({ AZDIGI_SMS_ENABLED: "true", AZDIGI_SMS_CHANNELS: "sms,pigeon" } as any)).toEqual(["sms"]);
    expect(availableChannels({ AZDIGI_SMS_ENABLED: "true", AZDIGI_SMS_CHANNELS: "zalo" } as any)).toEqual(["email", "zalo"]);
  });
});
