// AZDIGI: the action calls lib/azdigi/enrolment-guard.ts (upstream's guard plus the policy rule for strong methods);
// the gate itself is tested in lib/azdigi/enrolment-guard.test.ts.
import { resendVerification, sendVerification, verifyTOTP } from "@/lib/actions/verify";
import { resetLimiters } from "@/lib/azdigi/rate-limit";
import { trySendVerification } from "@/lib/server/verification-email";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { getSessionCookieByLoginName } from "@/lib/server/cookies";
import { createSessionAndUpdateCookie } from "@/lib/server/session-cookie";
import {
  createInviteCode,
  getSession,
  getUserByID,
  listAuthenticationMethodTypes,
  verifyEmail,
  sendEmailCode as zitadelSendEmailCode,
} from "@/lib/server/zitadel";
import { cookies, headers } from "next/headers";

// Mock dependencies
vi.mock("@/lib/server/zitadel", () => ({
  addOTPEmail: vi.fn(),
  verifyEmail: vi.fn(),
  verifyInviteCode: vi.fn(),
  getUserByID: vi.fn(),
  getSession: vi.fn(),
  listAuthenticationMethodTypes: vi.fn(),
  getLoginSettings: vi.fn(),
  sendEmailCode: vi.fn(),
  createInviteCode: vi.fn(),
  verifyTOTPRegistration: vi.fn(),
}));

vi.mock("@/lib/server/session", () => ({
  loadMostRecentSession: vi.fn(),
}));

// AZDIGI: no OTP-first organisation unless a test says so
vi.mock("@/lib/azdigi/org-lookup", () => ({ isOtpFirstOrg: vi.fn(async () => false) }));

vi.mock("@/lib/azdigi/enrolment-guard", () => ({
  enrolmentAuthorizationError: vi.fn(),
}));

vi.mock("next/headers", () => ({
  headers: vi.fn(),
  cookies: vi.fn(),
}));

vi.mock("@/lib/server/cookies", () => ({
  getSessionCookieByLoginName: vi.fn(),
}));

vi.mock("@/lib/server/session-cookie", () => ({
  createSessionAndUpdateCookie: vi.fn(),
}));

vi.mock("@/lib/server/service-url", () => ({
  getServiceConfig: vi.fn(() => ({ serviceConfig: {} })),
}));

vi.mock("@/lib/server/verification-check", () => ({
  setUserVerificationCheckCookie: vi.fn(),
}));

vi.mock("@/lib/server/host", () => ({
  getPublicHostWithProtocol: vi.fn(() => "https://example.com"),
}));

vi.mock("next-intl/server", () => ({
  getTranslations: vi.fn(() => (key: string) => key),
}));

describe("sendVerification", () => {
  let mockVerifyEmail: any;
  let mockGetUserByID: any;
  let mockGetSession: any;
  let mockListAuthenticationMethodTypes: any;
  let mockGetSessionCookieByLoginName: any;
  let mockCreateSessionAndUpdateCookie: any;
  let mockCookies: any;

  beforeEach(() => {
    mockVerifyEmail = verifyEmail;
    mockGetUserByID = getUserByID;
    mockGetSession = getSession;
    mockListAuthenticationMethodTypes = listAuthenticationMethodTypes;
    mockGetSessionCookieByLoginName = getSessionCookieByLoginName;
    mockCreateSessionAndUpdateCookie = createSessionAndUpdateCookie;
    mockCookies = cookies;

    // Default valid checking setup
    mockVerifyEmail.mockResolvedValue({});
    mockGetUserByID.mockResolvedValue({
      user: { userId: "user-1", preferredLoginName: "test@example.com" },
    });
    mockCookies.mockResolvedValue({
      set: vi.fn(),
    });
  });

  test("should handle failing getSession when no auth methods exist (stale cookie scenario)", async () => {
    // 1. Cookie exists
    mockGetSessionCookieByLoginName.mockResolvedValue({
      id: "stale-session-id",
      token: "stale-token",
    });

    // 2. getSession fails (throws or returns null/invalid)
    // Simulating call returning nothing useful or throwing
    mockGetSession.mockRejectedValue(new Error("Session not found"));
    // OR: mockGetSession.mockResolvedValue({}); // depending on how generic client behaves

    // 3. No auth methods (user needs setup)
    mockListAuthenticationMethodTypes.mockResolvedValue({
      authMethodTypes: [],
    });

    // 4. Mock session creation success
    mockCreateSessionAndUpdateCookie.mockResolvedValue({
      session: {
        id: "new-session-id",
        factors: { user: { id: "user-1", loginName: "test@example.com", organizationId: "org-1" } },
      },
    });

    const result = await sendVerification({
      userId: "user-1",
      code: "123456",
      isInvite: false,
    });

    // Expect redirect to authenticator setup
    expect(result).toEqual({
      redirect: "/authenticator/set?sessionId=new-session-id&loginName=test%40example.com",
    });

    // Verify getSession was called (and failed, but we recovered)
    expect(mockGetSession).toHaveBeenCalled();
    // Verify creation was attempted
    expect(mockCreateSessionAndUpdateCookie).toHaveBeenCalled();
    // The signed verification check is issued for the verified user
    const { setUserVerificationCheckCookie } = await import("@/lib/server/verification-check");
    expect(setUserVerificationCheckCookie).toHaveBeenCalledWith("user-1");
  });

  test("should include requestId in /authenticator/set redirect when provided", async () => {
    // 1. No existing session cookie
    mockGetSessionCookieByLoginName.mockResolvedValue(undefined);

    // 2. No auth methods (user needs setup)
    mockListAuthenticationMethodTypes.mockResolvedValue({
      authMethodTypes: [],
    });

    // 3. Mock session creation success
    mockCreateSessionAndUpdateCookie.mockResolvedValue({
      session: {
        id: "new-session-id",
        factors: { user: { id: "user-1", loginName: "test@example.com", organizationId: "org-1" } },
      },
    });

    const result = await sendVerification({
      userId: "user-1",
      code: "123456",
      isInvite: false,
      requestId: "oidc_auth-req-123",
    });

    // Expect redirect to include requestId
    expect(result).toEqual({
      redirect: expect.stringContaining("/authenticator/set?"),
    });
    const redirectUrl = (result as { redirect: string }).redirect;
    const params = new URLSearchParams(redirectUrl.split("?")[1]);
    expect(params.get("requestId")).toBe("oidc_auth-req-123");
    expect(params.get("sessionId")).toBe("new-session-id");
    expect(params.get("loginName")).toBe("test@example.com");
  });

  test("should NOT include requestId in /authenticator/set redirect when not provided", async () => {
    // 1. No existing session cookie
    mockGetSessionCookieByLoginName.mockResolvedValue(undefined);

    // 2. No auth methods (user needs setup)
    mockListAuthenticationMethodTypes.mockResolvedValue({
      authMethodTypes: [],
    });

    // 3. Mock session creation success
    mockCreateSessionAndUpdateCookie.mockResolvedValue({
      session: {
        id: "new-session-id",
        factors: { user: { id: "user-1", loginName: "test@example.com", organizationId: "org-1" } },
      },
    });

    const result = await sendVerification({
      userId: "user-1",
      code: "123456",
      isInvite: false,
      // no requestId
    });

    const redirectUrl = (result as { redirect: string }).redirect;
    const params = new URLSearchParams(redirectUrl.split("?")[1]);
    expect(params.get("requestId")).toBeNull();
  });

  test("should fall back to user.preferredLoginName for session cookie lookup when loginName is undefined", async () => {
    // Simulate the email-link scenario: loginName is undefined but userId is provided
    mockGetSessionCookieByLoginName.mockResolvedValue(undefined);
    mockGetUserByID.mockResolvedValue({
      user: { userId: "user-1", preferredLoginName: "test@example.com" },
    });
    mockListAuthenticationMethodTypes.mockResolvedValue({
      authMethodTypes: [],
    });
    mockCreateSessionAndUpdateCookie.mockResolvedValue({
      session: {
        id: "new-session-id",
        factors: { user: { id: "user-1", loginName: "test@example.com", organizationId: "org-1" } },
      },
    });

    await sendVerification({
      userId: "user-1",
      code: "123456",
      isInvite: false,
      loginName: undefined, // explicitly undefined, like from email link
    });

    // The key assertion: session cookie lookup should use preferredLoginName as fallback
    expect(mockGetSessionCookieByLoginName).toHaveBeenCalledWith({
      loginName: "test@example.com",
      organization: undefined,
    });
  });
});

describe("trySendVerification", () => {
  let mockSendEmailCode: any;
  let mockCreateInviteCode: any;
  let originalBasePath: string | undefined;

  beforeEach(() => {
    originalBasePath = process.env.NEXT_PUBLIC_BASE_PATH;
    process.env.NEXT_PUBLIC_BASE_PATH = "/ui/v2/login";

    vi.clearAllMocks();
    mockSendEmailCode = zitadelSendEmailCode;
    mockCreateInviteCode = createInviteCode;
    mockSendEmailCode.mockResolvedValue({});
    mockCreateInviteCode.mockResolvedValue({});
  });

  afterEach(() => {
    if (originalBasePath === undefined) {
      delete process.env.NEXT_PUBLIC_BASE_PATH;
    } else {
      process.env.NEXT_PUBLIC_BASE_PATH = originalBasePath;
    }
  });

  test("should call sendEmailCode with correct URL template for non-invite and return true", async () => {
    const result = await trySendVerification({
      userId: "user-1",
      isInvite: false,
    });

    expect(result).toBe(true);
    expect(mockSendEmailCode).toHaveBeenCalledWith({
      serviceConfig: {},
      userId: "user-1",
      urlTemplate: "https://example.com/ui/v2/login/verify?code={{.Code}}&userId={{.UserID}}&organization={{.OrgID}}",
    });
    expect(mockCreateInviteCode).not.toHaveBeenCalled();
  });

  test("should call createInviteCode with correct URL template for invite and return true", async () => {
    const result = await trySendVerification({
      userId: "user-1",
      isInvite: true,
    });

    expect(result).toBe(true);
    expect(mockCreateInviteCode).toHaveBeenCalledWith({
      serviceConfig: {},
      userId: "user-1",
      urlTemplate:
        "https://example.com/ui/v2/login/verify?code={{.Code}}&userId={{.UserID}}&organization={{.OrgID}}&invite=true",
    });
    expect(mockSendEmailCode).not.toHaveBeenCalled();
  });

  test("should include URL-encoded requestId in URL template", async () => {
    const result = await trySendVerification({
      userId: "user-1",
      isInvite: false,
      requestId: "req-123",
    });

    expect(result).toBe(true);
    expect(mockSendEmailCode).toHaveBeenCalledWith({
      serviceConfig: {},
      userId: "user-1",
      urlTemplate:
        "https://example.com/ui/v2/login/verify?code={{.Code}}&userId={{.UserID}}&organization={{.OrgID}}&requestId=req-123",
    });
  });

  test("should URL-encode special characters in requestId", async () => {
    const result = await trySendVerification({
      userId: "user-1",
      isInvite: false,
      requestId: "req&id=injected",
    });

    expect(result).toBe(true);
    expect(mockSendEmailCode).toHaveBeenCalledWith({
      serviceConfig: {},
      userId: "user-1",
      urlTemplate:
        "https://example.com/ui/v2/login/verify?code={{.Code}}&userId={{.UserID}}&organization={{.OrgID}}&requestId=req%26id%3Dinjected",
    });
  });

  test("should include invite=true and requestId for invite with requestId", async () => {
    const result = await trySendVerification({
      userId: "user-1",
      isInvite: true,
      requestId: "req-456",
    });

    expect(result).toBe(true);
    expect(mockCreateInviteCode).toHaveBeenCalledWith({
      serviceConfig: {},
      userId: "user-1",
      urlTemplate:
        "https://example.com/ui/v2/login/verify?code={{.Code}}&userId={{.UserID}}&organization={{.OrgID}}&invite=true&requestId=req-456",
    });
  });

  test("should return false when sendEmailCode fails", async () => {
    mockSendEmailCode.mockRejectedValue(new Error("Network error"));

    const result = await trySendVerification({
      userId: "user-1",
      isInvite: false,
    });

    expect(result).toBe(false);
  });

  test("should return false when createInviteCode fails", async () => {
    mockCreateInviteCode.mockRejectedValue(new Error("Already invited"));

    const result = await trySendVerification({
      userId: "user-1",
      isInvite: true,
    });

    expect(result).toBe(false);
  });
});

describe("verifyTOTP", () => {
  let mockLoadMostRecentSession: any;
  let mockVerifyTOTPRegistration: any;
  let mockGetEnrollmentAuthorizationError: any;

  const totpSession = {
    id: "session-1",
    factors: { user: { id: "victim-1", loginName: "victim@example.com" } },
  };

  beforeEach(async () => {
    vi.clearAllMocks();
    const _headers = await import("next/headers");
    vi.mocked(_headers.headers).mockResolvedValue(new Headers() as any);

    mockLoadMostRecentSession = vi.mocked((await import("@/lib/server/session")).loadMostRecentSession);
    mockVerifyTOTPRegistration = vi.mocked((await import("@/lib/server/zitadel")).verifyTOTPRegistration);
    mockGetEnrollmentAuthorizationError = vi.mocked(
      (await import("@/lib/azdigi/enrolment-guard")).enrolmentAuthorizationError,
    );

    mockLoadMostRecentSession.mockResolvedValue(totpSession);
  });

  test("rejects TOTP enrollment on an unauthenticated (identify-only) session", async () => {
    mockGetEnrollmentAuthorizationError.mockResolvedValue(
      "You have to authenticate or have a valid User Verification Check",
    );

    const result = await verifyTOTP("123456", "victim@example.com", "org-1");

    expect(result).toEqual({ error: "You have to authenticate or have a valid User Verification Check" });
    expect(mockGetEnrollmentAuthorizationError).toHaveBeenCalledWith({
      serviceConfig: {},
      session: totpSession,
      userId: "victim-1",
      method: "totp",
    });
    expect(mockVerifyTOTPRegistration).not.toHaveBeenCalled();
  });

  test("verifies TOTP registration when the session is authorized", async () => {
    mockGetEnrollmentAuthorizationError.mockResolvedValue(null);
    mockVerifyTOTPRegistration.mockResolvedValue({ done: true });

    const result = await verifyTOTP("123456", "victim@example.com", "org-1");

    expect(mockVerifyTOTPRegistration).toHaveBeenCalledWith({
      serviceConfig: {},
      code: "123456",
      userId: "victim-1",
    });
    expect(result).toEqual({ done: true });
  });

  test("throws when the session has no user id", async () => {
    mockLoadMostRecentSession.mockResolvedValue({ id: "session-1", factors: {} });

    await expect(verifyTOTP("123456")).rejects.toThrow("No user id found in session.");
    expect(mockVerifyTOTPRegistration).not.toHaveBeenCalled();
  });
});

describe("sendVerification in the OTP-first organisation (AZDIGI)", () => {
  const customer = {
    userId: "cust-1",
    preferredLoginName: "khach@example.vn",
    details: { resourceOwner: "customers" },
    type: { case: "human", value: { email: { email: "khach@example.vn", isVerified: true } } },
  };

  beforeEach(async () => {
    vi.clearAllMocks();
    const orgLookup = await import("@/lib/azdigi/org-lookup");
    vi.mocked(orgLookup.isOtpFirstOrg).mockImplementation(async (_cfg, org) => org === "customers");
    vi.mocked(verifyEmail).mockResolvedValue({} as any);
    vi.mocked(getUserByID).mockResolvedValue({ user: customer } as any);
    vi.mocked(getSessionCookieByLoginName).mockResolvedValue({ id: "s1", token: "t" } as any);
    vi.mocked(getSession).mockResolvedValue({
      session: { id: "s1", factors: { user: { id: "cust-1", loginName: "khach@example.vn", organizationId: "customers" } } },
    } as any);
  });

  test("a freshly verified customer gets the email code as first factor and continues to /otp/email", async () => {
    const zitadel = await import("@/lib/server/zitadel");
    vi.mocked(listAuthenticationMethodTypes).mockResolvedValue({ authMethodTypes: [] } as any);
    vi.mocked(zitadel.addOTPEmail).mockResolvedValue({} as any);

    const result = await sendVerification({ userId: "cust-1", code: "123456", isInvite: false, requestId: "oidc_1" });

    expect(zitadel.addOTPEmail).toHaveBeenCalledWith(expect.objectContaining({ userId: "cust-1" }));
    expect((result as { redirect: string }).redirect).toMatch(/^\/otp\/email\?/);
    expect((result as { redirect: string }).redirect).toContain("emailVerified=true");
    expect((result as { redirect: string }).redirect).toContain("requestId=oidc_1");
  });

  test("when the method cannot be granted the stock authenticator set-up applies", async () => {
    const zitadel = await import("@/lib/server/zitadel");
    vi.mocked(listAuthenticationMethodTypes).mockResolvedValue({ authMethodTypes: [] } as any);
    vi.mocked(zitadel.addOTPEmail).mockRejectedValue(new Error("denied"));

    const result = await sendVerification({ userId: "cust-1", code: "123456", isInvite: false });

    expect((result as { redirect: string }).redirect).toMatch(/^\/authenticator\/set\?/);
  });

  test("staff (not OTP-first) without a primary method still go to the authenticator set-up", async () => {
    const zitadel = await import("@/lib/server/zitadel");
    vi.mocked(getUserByID).mockResolvedValue({ user: { ...customer, details: { resourceOwner: "internal" } } } as any);
    vi.mocked(listAuthenticationMethodTypes).mockResolvedValue({ authMethodTypes: [] } as any);

    const result = await sendVerification({ userId: "cust-1", code: "123456", isInvite: false });

    expect(zitadel.addOTPEmail).not.toHaveBeenCalled();
    expect((result as { redirect: string }).redirect).toMatch(/^\/authenticator\/set\?/);
  });
});

describe("resendVerification limits (AZDIGI)", () => {
  const fromIp = (ip: string) => new Headers({ "cf-connecting-ip": ip });

  beforeEach(() => {
    vi.clearAllMocks();
    resetLimiters();
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-11-19T03:00:00Z"));
    vi.mocked(headers).mockResolvedValue(fromIp("203.0.113.7") as any);
    vi.mocked(createInviteCode).mockResolvedValue({} as any);
    vi.mocked(zitadelSendEmailCode).mockResolvedValue({} as any);
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  test("one mail per user and kind per minute; the resend button works again once the minute has passed", async () => {
    expect(await resendVerification({ userId: "u1", isInvite: true })).not.toHaveProperty("error");
    expect(await resendVerification({ userId: "u1", isInvite: true })).toEqual({ error: "errors.tooManyCodeRequests" });
    expect(createInviteCode).toHaveBeenCalledTimes(1);

    vi.setSystemTime(new Date("2026-11-19T03:01:01Z"));
    expect(await resendVerification({ userId: "u1", isInvite: true })).not.toHaveProperty("error");
    expect(createInviteCode).toHaveBeenCalledTimes(2);
  });

  test("the minute is shared with the automatic send that led to /verify", async () => {
    const { claimVerifyPageSend } = await import("@/lib/azdigi/rate-limit");
    expect(claimVerifyPageSend("u2", "email")).toBe(true);
    expect(await resendVerification({ userId: "u2", isInvite: false })).toEqual({ error: "errors.tooManyCodeRequests" });
    expect(zitadelSendEmailCode).not.toHaveBeenCalled();
  });

  test("one client cannot mail many users: the per-IP code budget applies before Zitadel is called", async () => {
    for (let i = 0; i < 20; i++) {
      expect(await resendVerification({ userId: `victim-${i}`, isInvite: true })).not.toHaveProperty("error");
    }
    expect(await resendVerification({ userId: "victim-20", isInvite: true })).toEqual({
      error: "errors.tooManyCodeRequests",
    });
    expect(createInviteCode).toHaveBeenCalledTimes(20);
    // another client is not affected
    vi.mocked(headers).mockResolvedValue(fromIp("198.51.100.9") as any);
    expect(await resendVerification({ userId: "victim-20", isInvite: true })).not.toHaveProperty("error");
  });
});
