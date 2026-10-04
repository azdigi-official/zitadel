import { UserState } from "@zitadel/proto/zitadel/user/v2/user_pb";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { describe, expect, test, vi } from "vitest";
import { decideOtpFirst, otpFirstParams } from "./otp-first";

vi.mock("../zitadel", () => ({ getLoginSettings: vi.fn(), listAuthenticationMethodTypes: vi.fn() }));
vi.mock("./org-lookup", () => ({ isOtpFirstOrg: vi.fn() }));

const base = {
  otpFirstOrg: true,
  loginSettings: { forceMfa: false } as any,
  authMethods: [AuthenticationMethodType.OTP_EMAIL],
  emailVerified: true,
  userState: UserState.ACTIVE,
};

describe("decideOtpFirst", () => {
  test("eligible customer without a password", () => {
    expect(decideOtpFirst(base)).toEqual({ eligible: true, altPassword: false, altPasskey: false });
  });
  test("eligible customer with a password offers it as an alternative; a passkey only when the policy allows it", () => {
    expect(decideOtpFirst({ ...base, authMethods: [AuthenticationMethodType.PASSWORD, AuthenticationMethodType.OTP_EMAIL] })).toEqual({
      eligible: true,
      altPassword: true,
      altPasskey: false,
    });
    const withPasskey = [AuthenticationMethodType.PASSKEY, AuthenticationMethodType.OTP_EMAIL];
    expect(decideOtpFirst({ ...base, authMethods: withPasskey }).eligible && (decideOtpFirst({ ...base, authMethods: withPasskey }) as any).altPasskey).toBe(false);
    expect((decideOtpFirst({ ...base, loginSettings: { forceMfa: false, passkeysType: 1 } as any, authMethods: withPasskey }) as any).altPasskey).toBe(true);
  });
  test("refusals: org, forceMfa, missing method, unverified email, locked user, missing settings", () => {
    expect(decideOtpFirst({ ...base, otpFirstOrg: false })).toEqual({ eligible: false, reason: "org" });
    expect(decideOtpFirst({ ...base, loginSettings: { forceMfa: true } as any })).toEqual({ eligible: false, reason: "forceMfa" });
    expect(decideOtpFirst({ ...base, loginSettings: undefined })).toEqual({ eligible: false, reason: "forceMfa" });
    expect(decideOtpFirst({ ...base, authMethods: [AuthenticationMethodType.PASSWORD] })).toEqual({ eligible: false, reason: "no-otp-email-method" });
    expect(decideOtpFirst({ ...base, emailVerified: false })).toEqual({ eligible: false, reason: "email-unverified" });
    expect(decideOtpFirst({ ...base, userState: UserState.LOCKED })).toEqual({ eligible: false, reason: "user-state" });
  });
});

describe("otpFirstParams", () => {
  test("carries loginName, altPassword, organization and requestId", () => {
    expect(otpFirstParams({ loginName: "a@b.c", organization: "o", requestId: "oidc_1", altPassword: true }).toString()).toBe(
      "loginName=a%40b.c&altPassword=true&organization=o&requestId=oidc_1",
    );
    expect(otpFirstParams({ loginName: "a@b.c", altPassword: false, altPasskey: true }).toString()).toBe(
      "loginName=a%40b.c&altPassword=false&altPasskey=true",
    );
  });
});
