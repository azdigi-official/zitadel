import * as issueModule from "@/lib/azdigi/issue";
import { PolicyRejectedError } from "@/lib/azdigi/issue";
import { loginWithOIDCAndSession } from "@/lib/server/oidc";
import * as sessionModule from "@/lib/server/session";
import * as zitadelModule from "@/lib/server/zitadel";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/server/session");
vi.mock("@/lib/server/zitadel");
vi.mock("@/lib/azdigi/issue", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/azdigi/issue")>();
  return { ...actual, guardedCreateCallback: vi.fn() };
});
vi.mock("@/lib/server/grpc/interceptors/error-classification", () => ({
  isClassifiedError: (error: unknown): boolean =>
    typeof error === "object" && error !== null && "code" in error && typeof (error as any).code === "number",
}));

vi.mock("@zitadel/client", () => ({
  Code: { FailedPrecondition: 9 },
  ConnectError: class MockConnectError extends Error {
    code: number;
    constructor(msg: string, code: number) {
      super(msg);
      this.code = code;
    }
  },
  create: vi.fn(),
}));

describe("loginWithOIDCAndSession", () => {
  const mockServiceUrl = "https://zitadel.example.com";
  const mockAuthRequest = "auth-123";
  const mockSessionId = "session-123";

  let mockSessions: any[];
  let mockCookies: any[];

  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});

    mockSessions = [
      {
        id: mockSessionId,
        factors: {
          user: {
            id: "user-123",
            loginName: "test@example.com",
            organizationId: "org-123",
          },
          password: {
            verifiedAt: { seconds: BigInt(Math.floor(Date.now() / 1000)) },
          },
        },
      },
    ];

    mockCookies = [
      {
        id: mockSessionId,
        token: "token-123",
        loginName: "test@example.com",
        creationTs: new Date().toISOString(),
        expirationTs: new Date(Date.now() + 3600000).toISOString(),
        changeTs: new Date().toISOString(),
      },
    ];
  });

  it("should redirect to callback URL when session is valid", async () => {
    vi.mocked(sessionModule.checkSessionPolicy).mockResolvedValue({ ok: true });
    vi.mocked(issueModule.guardedCreateCallback).mockResolvedValue({
      callbackUrl: "https://app.example.com/callback",
    } as any);

    const result = await loginWithOIDCAndSession({
      serviceUrl: mockServiceUrl,
      authRequest: mockAuthRequest,
      sessionId: mockSessionId,
      sessions: mockSessions,
      sessionCookies: mockCookies,
    });

    expect(result).toEqual({ redirect: "https://app.example.com/callback" });
  });

  // AZDIGI: an invalid session is answered with the screen the organisation's policy names; no callback is created
  it("should redirect to the policy's next step when the session is invalid, without a callback", async () => {
    vi.mocked(sessionModule.checkSessionPolicy).mockResolvedValue({
      ok: false,
      reason: "second-factor-missing",
      next: "mfa",
    });

    const result = await loginWithOIDCAndSession({
      serviceUrl: mockServiceUrl,
      authRequest: mockAuthRequest,
      sessionId: mockSessionId,
      sessions: mockSessions,
      sessionCookies: mockCookies,
    });

    expect(result).toEqual({
      redirect: `/mfa?loginName=test%40example.com&organization=org-123&requestId=oidc_${mockAuthRequest}`,
    });
    expect(issueModule.guardedCreateCallback).not.toHaveBeenCalled();
  });

  it("should follow the wrapper's refusal (it re-reads the session with its token)", async () => {
    vi.mocked(sessionModule.checkSessionPolicy).mockResolvedValue({ ok: true });
    vi.mocked(issueModule.guardedCreateCallback).mockRejectedValue(
      new PolicyRejectedError({ ok: false, reason: "no-first-factor", next: "otpEmail" }, mockSessions[0]),
    );

    const result = await loginWithOIDCAndSession({
      serviceUrl: mockServiceUrl,
      authRequest: mockAuthRequest,
      sessionId: mockSessionId,
      sessions: mockSessions,
      sessionCookies: mockCookies,
    });

    expect(result).toEqual({
      redirect: `/otp/email?loginName=test%40example.com&organization=org-123&requestId=oidc_${mockAuthRequest}`,
    });
  });

  it("should not create a callback for an invalid session without a user factor", async () => {
    vi.mocked(sessionModule.checkSessionPolicy).mockResolvedValue({ ok: false, reason: "no-user", next: "loginname" });

    const result = await loginWithOIDCAndSession({
      serviceUrl: mockServiceUrl,
      authRequest: mockAuthRequest,
      sessionId: mockSessionId,
      sessions: [{ id: mockSessionId, factors: {} }],
      sessionCookies: mockCookies,
    });

    expect(result).toEqual({ redirect: `/loginname?requestId=oidc_${mockAuthRequest}` });
    expect(issueModule.guardedCreateCallback).not.toHaveBeenCalled();
  });

  it("should return error when session not found", async () => {
    const result = await loginWithOIDCAndSession({
      serviceUrl: mockServiceUrl,
      authRequest: mockAuthRequest,
      sessionId: "nonexistent",
      sessions: mockSessions,
      sessionCookies: mockCookies,
    });

    expect(result).toEqual({ error: "Session not found or invalid" });
  });

  it("should return error when cookie not found", async () => {
    vi.mocked(sessionModule.checkSessionPolicy).mockResolvedValue({ ok: true });

    const result = await loginWithOIDCAndSession({
      serviceUrl: mockServiceUrl,
      authRequest: mockAuthRequest,
      sessionId: mockSessionId,
      sessions: mockSessions,
      sessionCookies: [],
    });

    expect(result).toEqual({ error: "Session not found or invalid" });
  });

  it("should handle error code 9 with default redirect", async () => {
    const { ConnectError } = await import("@zitadel/client");
    vi.mocked(sessionModule.checkSessionPolicy).mockResolvedValue({ ok: true });
    vi.mocked(issueModule.guardedCreateCallback).mockRejectedValue(new ConnectError("already handled", 9));
    vi.mocked(zitadelModule.getLoginSettings).mockResolvedValue({
      defaultRedirectUri: "https://default.example.com",
    } as any);

    const result = await loginWithOIDCAndSession({
      serviceUrl: mockServiceUrl,
      authRequest: mockAuthRequest,
      sessionId: mockSessionId,
      sessions: mockSessions,
      sessionCookies: mockCookies,
    });

    expect(result).toEqual({ redirect: "https://default.example.com" });
  });

  it("should redirect to /signedin when error code 9 and no default URI", async () => {
    const { ConnectError } = await import("@zitadel/client");
    vi.mocked(sessionModule.checkSessionPolicy).mockResolvedValue({ ok: true });
    vi.mocked(issueModule.guardedCreateCallback).mockRejectedValue(new ConnectError("already handled", 9));
    vi.mocked(zitadelModule.getLoginSettings).mockResolvedValue({} as any);

    const result = await loginWithOIDCAndSession({
      serviceUrl: mockServiceUrl,
      authRequest: mockAuthRequest,
      sessionId: mockSessionId,
      sessions: mockSessions,
      sessionCookies: mockCookies,
    });

    expect(result).toHaveProperty("redirect");
    if ("redirect" in result) {
      expect(result.redirect).toContain("/signedin");
      expect(result.redirect).toContain("loginName=test%40example.com");
      expect(result.redirect).toContain("organization=org-123");
    }
  });

  it("should return unknown error for non-code-9 errors", async () => {
    vi.mocked(sessionModule.checkSessionPolicy).mockResolvedValue({ ok: true });
    vi.mocked(issueModule.guardedCreateCallback).mockRejectedValue({
      code: 13,
      message: "Internal error",
    });

    const result = await loginWithOIDCAndSession({
      serviceUrl: mockServiceUrl,
      authRequest: mockAuthRequest,
      sessionId: mockSessionId,
      sessions: mockSessions,
      sessionCookies: mockCookies,
    });

    expect(result).toEqual({ error: "Unknown error occurred" });
  });

  it("should reject javascript: defaultRedirectUri in FailedPrecondition path (XSS prevention)", async () => {
    const { ConnectError } = await import("@zitadel/client");
    vi.mocked(sessionModule.checkSessionPolicy).mockResolvedValue({ ok: true });
    vi.mocked(issueModule.guardedCreateCallback).mockRejectedValue(new ConnectError("already handled", 9));
    vi.mocked(zitadelModule.getLoginSettings).mockResolvedValue({
      defaultRedirectUri: "javascript:alert(document.cookie)",
    } as any);

    const result = await loginWithOIDCAndSession({
      serviceUrl: mockServiceUrl,
      authRequest: mockAuthRequest,
      sessionId: mockSessionId,
      sessions: mockSessions,
      sessionCookies: mockCookies,
    });

    // Should NOT redirect to the javascript: URI — must fall back to /signedin
    expect(result).toHaveProperty("redirect");
    if ("redirect" in result) {
      expect(result.redirect).not.toContain("javascript:");
      expect(result.redirect).toContain("/signedin");
    }
  });

  it("should reject data: defaultRedirectUri in FailedPrecondition path (XSS prevention)", async () => {
    const { ConnectError } = await import("@zitadel/client");
    vi.mocked(sessionModule.checkSessionPolicy).mockResolvedValue({ ok: true });
    vi.mocked(issueModule.guardedCreateCallback).mockRejectedValue(new ConnectError("already handled", 9));
    vi.mocked(zitadelModule.getLoginSettings).mockResolvedValue({
      defaultRedirectUri: "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    } as any);

    const result = await loginWithOIDCAndSession({
      serviceUrl: mockServiceUrl,
      authRequest: mockAuthRequest,
      sessionId: mockSessionId,
      sessions: mockSessions,
      sessionCookies: mockCookies,
    });

    // Should NOT redirect to the data: URI — must fall back to /signedin
    expect(result).toHaveProperty("redirect");
    if ("redirect" in result) {
      expect(result.redirect).not.toContain("data:");
      expect(result.redirect).toContain("/signedin");
    }
  });
});
