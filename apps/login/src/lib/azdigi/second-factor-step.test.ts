import * as zitadel from "@/lib/server/zitadel";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { beforeEach, describe, expect, test, vi } from "vitest";
import * as issue from "./issue";
import * as otpChannel from "./otp-channel";
import { pickSecondFactorStep, secondFactorStep } from "./second-factor-step";

vi.mock("@/lib/server/zitadel", () => ({ getUserMetadata: vi.fn() }));
vi.mock("./issue", () => ({ registeredMethodsOf: vi.fn() }));
vi.mock("./otp-channel", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./otp-channel")>()),
  phoneChannels: vi.fn(() => []),
}));

const M = AuthenticationMethodType;

describe("which screen verifies the second factor an enrolment page asked for", () => {
  test("codes only: the channel the user chose, email otherwise", () => {
    expect(pickSecondFactorStep([M.PASSWORD, M.OTP_EMAIL], undefined, false)).toEqual({
      kind: "emailCode",
      path: "/otp/email",
    });
    expect(pickSecondFactorStep([M.OTP_EMAIL, M.OTP_SMS], "zalo", true)).toEqual({ kind: "phoneCode", path: "/otp/sms" });
    expect(pickSecondFactorStep([M.OTP_EMAIL, M.OTP_SMS], "sms", true)).toEqual({ kind: "phoneCode", path: "/otp/sms" });
    // a phone channel that is switched off is not offered: back to email
    expect(pickSecondFactorStep([M.OTP_EMAIL, M.OTP_SMS], "zalo", false)).toEqual({ kind: "emailCode", path: "/otp/email" });
    expect(pickSecondFactorStep([M.OTP_EMAIL, M.OTP_SMS], "email", true)).toEqual({ kind: "emailCode", path: "/otp/email" });
    expect(pickSecondFactorStep([M.PASSWORD, M.OTP_SMS], undefined, true)).toEqual({ kind: "phoneCode", path: "/otp/sms" });
  });

  test("a single authenticator app or security key goes to its screen, several kinds to the chooser", () => {
    expect(pickSecondFactorStep([M.PASSWORD, M.TOTP], undefined, false)).toEqual({ kind: "totp", path: "/otp/time-based" });
    expect(pickSecondFactorStep([M.PASSWORD, M.U2F], undefined, false)).toEqual({ kind: "u2f", path: "/u2f" });
    expect(pickSecondFactorStep([M.TOTP, M.OTP_EMAIL], undefined, false)).toEqual({ kind: "choose", path: "/mfa" });
    expect(pickSecondFactorStep([M.TOTP, M.U2F], undefined, false)).toEqual({ kind: "choose", path: "/mfa" });
  });

  test("no second factor: no step (the refusal had another reason)", () => {
    expect(pickSecondFactorStep([M.PASSWORD, M.PASSKEY], undefined, false)).toBeUndefined();
  });
});

describe("the step link", () => {
  const session = {
    id: "s1",
    factors: {
      user: { id: "u1", loginName: "khach@example.vn", organizationId: "customers" },
      password: { verifiedAt: {} },
    },
  } as any;

  beforeEach(() => vi.clearAllMocks());

  test("keeps the flow's context and the validated way back", async () => {
    vi.mocked(issue.registeredMethodsOf).mockResolvedValue([M.PASSWORD, M.OTP_EMAIL]);
    const step = await secondFactorStep({
      serviceConfig: { baseUrl: "x" },
      session,
      returnTo: "/passkey/set?prompt=true",
      requestId: "oidc_1",
    });
    expect(step?.kind).toBe("emailCode");
    const url = new URL(step!.href, "https://login.example");
    expect(url.pathname).toBe("/otp/email");
    expect(Object.fromEntries(url.searchParams)).toEqual({
      loginName: "khach@example.vn",
      organization: "customers",
      sessionId: "s1",
      requestId: "oidc_1",
      returnTo: "/passkey/set?prompt=true",
    });
    expect(zitadel.getUserMetadata).not.toHaveBeenCalled();
  });

  test("an invalid way back is dropped, never forwarded", async () => {
    vi.mocked(issue.registeredMethodsOf).mockResolvedValue([M.PASSWORD, M.OTP_EMAIL]);
    const step = await secondFactorStep({ serviceConfig: { baseUrl: "x" }, session, returnTo: "https://evil.example" });
    expect(new URL(step!.href, "https://login.example").searchParams.has("returnTo")).toBe(false);
  });

  test("the phone channel the user chose is read from their metadata", async () => {
    vi.mocked(issue.registeredMethodsOf).mockResolvedValue([M.OTP_EMAIL, M.OTP_SMS]);
    vi.mocked(zitadel.getUserMetadata).mockResolvedValue("zalo");
    vi.mocked(otpChannel.phoneChannels).mockReturnValue(["zalo"] as any);
    const step = await secondFactorStep({ serviceConfig: { baseUrl: "x" }, session, returnTo: "/passkey/set" });
    expect(step?.href).toMatch(/^\/otp\/sms\?/);
  });

  test("the security key screen has no way back (the flow then ends at the account page)", async () => {
    vi.mocked(issue.registeredMethodsOf).mockResolvedValue([M.PASSWORD, M.U2F]);
    const step = await secondFactorStep({ serviceConfig: { baseUrl: "x" }, session, returnTo: "/passkey/set" });
    expect(step?.kind).toBe("u2f");
    expect(step?.href).not.toContain("returnTo");
  });

  test("methods that cannot be read give no step", async () => {
    vi.mocked(issue.registeredMethodsOf).mockResolvedValue(undefined);
    expect(await secondFactorStep({ serviceConfig: { baseUrl: "x" }, session, returnTo: "/passkey/set" })).toBeUndefined();
  });
});
