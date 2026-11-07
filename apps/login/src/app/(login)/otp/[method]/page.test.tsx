import { decideOtpFirstForUser } from "@/lib/azdigi/otp-first";
import { loadMostRecentSession } from "@/lib/session";
import { redirect } from "next/navigation";
import { beforeEach, expect, test, vi } from "vitest";
import Page from "./page";

vi.mock("@/components/alert", () => ({ Alert: () => null }));
vi.mock("@/components/dynamic-theme", () => ({ DynamicTheme: () => null }));
vi.mock("@/components/login-otp", () => ({ LoginOTP: () => null }));
vi.mock("@/components/translated", () => ({ Translated: () => null }));
vi.mock("@/components/user-avatar", () => ({ UserAvatar: () => null }));
vi.mock("next/navigation", () => ({
  redirect: vi.fn(() => {
    throw new Error("redirect");
  }),
}));
vi.mock("next/headers", () => ({ headers: vi.fn(async () => ({})) }));
vi.mock("next-intl/server", () => ({ getTranslations: vi.fn(async () => (key: string) => key) }));
vi.mock("@/lib/service-url", () => ({ getServiceConfig: () => ({ serviceConfig: {} }) }));
vi.mock("@/lib/server/host", () => ({ getPublicHost: () => "login.example.test" }));
vi.mock("@/lib/cookies", () => ({ getSessionCookieById: vi.fn() }));
vi.mock("@/lib/session", () => ({ loadMostRecentSession: vi.fn() }));
vi.mock("@/lib/azdigi/otp-first", () => ({ decideOtpFirstForUser: vi.fn() }));
vi.mock("@/lib/azdigi/policy", () => ({ hasVerifiedFirstFactor: () => false }));
vi.mock("@/lib/azdigi/decoy", () => ({ decoyOrganization: async () => "customers", decoyLoginName: (s: string) => s }));
vi.mock("@/lib/azdigi/otp-channel", () => ({
  phoneChannels: () => [],
  availableChannels: () => [],
  maskPhone: () => "",
  OTP_CHANNEL_METADATA_KEY: "channel",
}));
vi.mock("@/lib/zitadel", () => ({
  getUserByID: async () => ({ user: { state: 1, type: { case: "human", value: { email: { isVerified: false } } } } }),
  getBrandingSettings: async () => ({}),
  getLoginSettings: async () => ({}),
  getSession: vi.fn(),
  getUserMetadata: vi.fn(),
}));

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(loadMostRecentSession).mockResolvedValue({
    factors: { user: { id: "user", organizationId: "customers", loginName: "customer+alias@example.test" } },
  } as any);
});

const page = () =>
  Page({
    params: Promise.resolve({ method: "email" }),
    searchParams: Promise.resolve({
      loginName: "customer+alias@example.test",
      organization: "customers",
      requestId: "oidc_1",
    }),
  });

test.each([true, false])("an old OTP page recovers to verification with request context (invite=%s)", async (invite) => {
  vi.mocked(decideOtpFirstForUser).mockResolvedValue({ eligible: false, reason: "setup-required", invite });
  await expect(page()).rejects.toThrow("redirect");
  expect(redirect).toHaveBeenCalledWith(
    `/verify?loginName=customer%2Balias%40example.test&organization=customers&requestId=oidc_1&send=true&invite=${invite}`,
  );
});

test("staff MFA refusal still sends the user to password", async () => {
  vi.mocked(decideOtpFirstForUser).mockResolvedValue({ eligible: false, reason: "forceMfa" });
  await expect(page()).rejects.toThrow("redirect");
  expect(redirect).toHaveBeenCalledWith(
    "/password?loginName=customer%2Balias%40example.test&organization=customers&requestId=oidc_1",
  );
});

test("unknown names keep the decoy without a verification redirect", async () => {
  vi.mocked(loadMostRecentSession).mockResolvedValue(undefined);
  await page();
  expect(decideOtpFirstForUser).not.toHaveBeenCalled();
  expect(redirect).not.toHaveBeenCalled();
});
