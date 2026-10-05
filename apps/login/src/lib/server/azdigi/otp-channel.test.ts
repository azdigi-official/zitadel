import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { beforeEach, describe, expect, test, vi } from "vitest";
import * as session from "../../session";
import * as zitadel from "../../zitadel";
import { setOtpChannel } from "./otp-channel";

vi.mock("next/headers", () => ({ headers: vi.fn(async () => ({ get: () => null })) }));
vi.mock("next-intl/server", () => ({ getTranslations: vi.fn(async () => (key: string) => key) }));
vi.mock("../../service-url", () => ({ getServiceConfig: vi.fn(() => ({ serviceConfig: { baseUrl: "http://api" } })) }));
vi.mock("../../session", () => ({ loadMostRecentSession: vi.fn() }));
vi.mock("../../zitadel", () => ({
  addOTPSMS: vi.fn(),
  getUserByID: vi.fn(),
  listAuthenticationMethodTypes: vi.fn(),
  setUserMetadata: vi.fn(),
}));

const cfg = { baseUrl: "http://api" };
const human = (verified: boolean) => ({ user: { type: { case: "human", value: { phone: { phone: "+84901234567", isVerified: verified } } } } });

describe("setOtpChannel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.mocked(session.loadMostRecentSession).mockResolvedValue({ factors: { user: { id: "u1" } } } as any);
    vi.mocked(zitadel.getUserByID).mockResolvedValue(human(true) as any);
    vi.mocked(zitadel.listAuthenticationMethodTypes).mockResolvedValue({ authMethodTypes: [AuthenticationMethodType.OTP_EMAIL] } as any);
    vi.mocked(zitadel.setUserMetadata).mockResolvedValue({} as any);
    vi.stubEnv("AZDIGI_SMS_ENABLED", "true");
    vi.stubEnv("AZDIGI_SMS_CHANNELS", "zalo,sms");
  });

  test("zalo: grants otp_sms when missing, stores the metadata and sends to /otp/sms", async () => {
    const res = await setOtpChannel({ channel: "zalo", loginName: "a@b.c", organization: "o1", requestId: "oidc_1", altPassword: true });
    expect(zitadel.addOTPSMS).toHaveBeenCalledWith({ serviceConfig: cfg, userId: "u1" });
    expect(zitadel.setUserMetadata).toHaveBeenCalledWith({ serviceConfig: cfg, userId: "u1", key: "azdigi.otp_channel", value: "zalo" });
    expect(res).toEqual({ redirect: "/otp/sms?loginName=a%40b.c&organization=o1&requestId=oidc_1&altPassword=true" });
  });

  test("email: no phone checks, stores and sends to /otp/email", async () => {
    const res = await setOtpChannel({ channel: "email", loginName: "a@b.c" });
    expect(zitadel.getUserByID).not.toHaveBeenCalled();
    expect(zitadel.setUserMetadata).toHaveBeenCalledWith(expect.objectContaining({ value: "email" }));
    expect(res).toEqual({ redirect: "/otp/email?loginName=a%40b.c" });
  });

  test("refuses an unverified phone, an unknown channel and a missing session", async () => {
    vi.mocked(zitadel.getUserByID).mockResolvedValue(human(false) as any);
    expect(await setOtpChannel({ channel: "sms", loginName: "a@b.c" })).toEqual({ error: "errors.phoneNotVerified" });
    expect(zitadel.setUserMetadata).not.toHaveBeenCalled();
    expect(await setOtpChannel({ channel: "pigeon" as any, loginName: "a@b.c" })).toEqual({ error: "errors.unknownChannel" });
    vi.mocked(session.loadMostRecentSession).mockResolvedValue(undefined);
    expect(await setOtpChannel({ channel: "email", loginName: "a@b.c" })).toEqual({ error: "errors.noSession" });
  });

  test("a phone channel that is not offered is refused before anything is written (Zalo-only, or SMS off)", async () => {
    vi.stubEnv("AZDIGI_SMS_CHANNELS", "zalo");
    expect(await setOtpChannel({ channel: "sms", loginName: "a@b.c" })).toEqual({ error: "errors.unknownChannel" });
    vi.stubEnv("AZDIGI_SMS_ENABLED", "false");
    expect(await setOtpChannel({ channel: "zalo", loginName: "a@b.c" })).toEqual({ error: "errors.unknownChannel" });
    expect(await setOtpChannel({ channel: "email", loginName: "a@b.c" })).toEqual({ redirect: "/otp/email?loginName=a%40b.c" });
    expect(zitadel.setUserMetadata).toHaveBeenCalledTimes(1);
  });

  test("a metadata write failure is reported, not thrown", async () => {
    vi.mocked(zitadel.setUserMetadata).mockRejectedValue(new Error("denied"));
    expect(await setOtpChannel({ channel: "email", loginName: "a@b.c" })).toEqual({ error: "errors.couldNotStore" });
  });
});
