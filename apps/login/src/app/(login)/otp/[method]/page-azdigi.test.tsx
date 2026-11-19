// AZDIGI: the email-code page as a first factor (OTP-first eligibility, decoy for unknown names, verified-email notice).
import { LoginOTP } from "@/components/login-otp";
import { decideOtpFirstForUser } from "@/lib/azdigi/otp-first";
import * as policy from "@/lib/azdigi/policy";
import { loadMostRecentSession } from "@/lib/server/session";
import { getUserByID } from "@/lib/server/zitadel";
import { redirect } from "next/navigation";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, expect, test, vi } from "vitest";
import Page from "./page";

vi.mock("@/components/alert", () => ({ Alert: () => null }));
vi.mock("@/components/dynamic-theme", () => ({ DynamicTheme: ({ children }: { children: any }) => children }));
vi.mock("@/components/login-otp", () => ({ LoginOTP: () => null }));
vi.mock("@/components/translated", () => ({ Translated: ({ i18nKey }: { i18nKey: string }) => i18nKey }));
vi.mock("@/components/user-avatar", () => ({ UserAvatar: () => null }));
vi.mock("next/navigation", () => ({
  redirect: vi.fn(() => {
    throw new Error("redirect");
  }),
}));
vi.mock("next/headers", () => ({ headers: vi.fn(async () => ({})) }));
vi.mock("next-intl/server", () => ({ getTranslations: vi.fn(async () => (key: string) => key) }));
vi.mock("@/lib/server/service-url", () => ({ getServiceConfig: () => ({ serviceConfig: {} }) }));
vi.mock("@/lib/server/host", () => ({ getPublicHost: () => "login.example.test" }));
vi.mock("@/lib/server/session", () => ({ loadMostRecentSession: vi.fn(), loadSessionById: vi.fn() }));
vi.mock("@/lib/azdigi/otp-first", () => ({ decideOtpFirstForUser: vi.fn() }));
vi.mock("@/lib/azdigi/policy", () => ({ hasVerifiedFirstFactor: vi.fn(() => false) }));
vi.mock("@/lib/azdigi/decoy", () => ({ decoyOrganization: async () => "customers", decoyLoginName: (s: string) => s }));
vi.mock("@/lib/azdigi/otp-channel", () => ({
  phoneChannels: () => [],
  availableChannels: () => [],
  maskPhone: () => "",
  OTP_CHANNEL_METADATA_KEY: "channel",
}));
vi.mock("@/lib/server/zitadel", () => ({
  getUserByID: vi.fn(async () => ({ user: { state: 1, type: { case: "human", value: { email: { isVerified: false } } } } })),
  getBrandingSettings: async () => ({}),
  getLoginSettings: async () => ({}),
  getSession: vi.fn(),
  getUserMetadata: vi.fn(),
}));

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(policy.hasVerifiedFirstFactor).mockReturnValue(false);
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

test.each([true, false])(
  "an old OTP page recovers to verification with request context, without mailing on render (invite=%s)",
  async (invite) => {
    vi.mocked(decideOtpFirstForUser).mockResolvedValue({ eligible: false, reason: "setup-required", invite });
    await expect(page()).rejects.toThrow("redirect");
    expect(redirect).toHaveBeenCalledWith(
      `/verify?loginName=customer%2Balias%40example.test&organization=customers&requestId=oidc_1&invite=${invite}`,
    );
  },
);

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

test.each([
  ["true", true, true],
  [undefined, true, false],
  ["true", false, false],
])(
  "verification feedback requires transition context and a verified live email (%s, %s)",
  async (marker, verified, shown) => {
    vi.mocked(decideOtpFirstForUser).mockResolvedValue({ eligible: true, altPassword: false, altPasskey: false });
    vi.mocked(getUserByID).mockResolvedValue({
      user: { state: 1, type: { case: "human", value: { email: { isVerified: verified } } } },
    } as any);
    const result = await Page({
      params: Promise.resolve({ method: "email" }),
      searchParams: Promise.resolve({ emailVerified: marker }),
    });
    const html = renderToStaticMarkup(result);
    expect(html.includes("verify.emailVerifiedTitle")).toBe(shown);
    expect(html.includes("verify.afterVerificationDescription")).toBe(shown);
  },
);

// the LoginOTP element in the (unrendered) tree the page returns
function loginOtpProps(node: any): any {
  if (!node || typeof node !== "object") return undefined;
  if (Array.isArray(node)) return node.map(loginOtpProps).find(Boolean);
  if (node.type === LoginOTP) return node.props;
  return loginOtpProps(node.props?.children);
}

test.each([
  ["/passkey/set?prompt=true", "/passkey/set?prompt=true"],
  ["/otp/time-based/set", "/otp/time-based/set"],
  ["https://evil.example/passkey/set", undefined],
  ["/account", undefined],
])(
  "an enrolment page's way back reaches the code screen only when it is a known enrolment path (%s)",
  async (returnTo, expected) => {
    // a second-factor screen: the session already has its first factor
    vi.mocked(policy.hasVerifiedFirstFactor).mockReturnValue(true);
    const result = await Page({
      params: Promise.resolve({ method: "email" }),
      searchParams: Promise.resolve({ loginName: "customer+alias@example.test", organization: "customers", returnTo }),
    });
    expect(loginOtpProps(result)?.returnTo).toBe(expected);
  },
);
