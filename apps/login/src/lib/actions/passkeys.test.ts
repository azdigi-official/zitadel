import { registerPasskeyLink, sendPasskey, verifyPasskeyRegistration } from "@/lib/actions/passkeys";
import { ENROLMENT_REFUSED } from "@/lib/azdigi/enrolment-guard";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { beforeEach, describe, expect, test, vi } from "vitest";

// AZDIGI: adding a passkey goes through lib/azdigi/enrolment-guard.ts: a session the organisation's policy accepts,
// or the first set-up of an account with no sign-in method that was verified in this browser
vi.mock("@/lib/azdigi/org-lookup", () => ({ isOtpFirstOrg: vi.fn(async () => false) }));
vi.mock("@/lib/azdigi/passkey-registration-proof", () => ({
  rememberCodeStartedRegistration: vi.fn(),
  wasStartedWithCode: vi.fn(),
}));

// Mock all the dependencies
vi.mock("next/headers", () => ({
  headers: vi.fn(),
}));

vi.mock("@zitadel/client", () => ({
  create: vi.fn((_schema: unknown, data: unknown) => data),
  Duration: vi.fn(),
  Timestamp: vi.fn(),
  timestampDate: vi.fn(),
}));

vi.mock("@/lib/server/service-url", () => ({
  getServiceConfig: vi.fn(),
}));

vi.mock("@/lib/server/zitadel", () => ({
  getLoginSettings: vi.fn(),
  getSession: vi.fn(),
  getUserByID: vi.fn(),
  listUsers: vi.fn(),
  createPasskeyRegistrationLink: vi.fn(),
  registerPasskey: vi.fn(),
  verifyPasskeyRegistration: vi.fn(),
  listAuthenticationMethodTypes: vi.fn(),
}));

vi.mock("@/lib/server/session-cookie", () => ({
  setSessionAndUpdateCookie: vi.fn(),
  createSessionAndUpdateCookie: vi.fn(),
}));

vi.mock("@/lib/server/cookies", () => ({
  getSessionCookieById: vi.fn(),
  getSessionCookieByLoginName: vi.fn(),
  getMostRecentSessionCookie: vi.fn(),
}));

vi.mock("@/lib/server/verify-helper", () => ({
  checkEmailVerification: vi.fn(),
  checkUserVerification: vi.fn(),
}));

vi.mock("@/lib/server/host", () => ({
  getPublicHost: vi.fn(),
  getPublicHostWithProtocol: vi.fn(() => "https://test.com"),
}));

vi.mock("@/lib/actions/flow", () => ({
  completeFlowOrGetUrl: vi.fn(),
}));

// Mock translations - returns the key itself for testing
vi.mock("next-intl/server", () => ({
  getTranslations: vi.fn(() => (key: string) => key),
}));

describe("sendPasskey", () => {
  let mockHeaders: any;
  let mockGetServiceUrlFromHeaders: any;
  let mockGetLoginSettings: any;
  let mockGetUserByID: any;
  let mockListUsers: any;
  let mockSetSessionAndUpdateCookie: any;
  let mockCreateSessionAndUpdateCookie: any;
  let mockGetSessionCookieById: any;
  let mockGetSessionCookieByLoginName: any;
  let mockGetMostRecentSessionCookie: any;
  let mockCheckEmailVerification: any;
  let mockCompleteFlowOrGetUrl: any;

  beforeEach(async () => {
    vi.clearAllMocks();

    // Import mocked modules
    const { headers } = await import("next/headers");
    const { getServiceConfig } = await import("@/lib/server/service-url");
    const { getLoginSettings, getUserByID, listUsers } = await import("@/lib/server/zitadel");
    const { setSessionAndUpdateCookie, createSessionAndUpdateCookie } = await import("@/lib/server/session-cookie");
    const { getSessionCookieById, getSessionCookieByLoginName, getMostRecentSessionCookie } =
      await import("@/lib/server/cookies");
    const { checkEmailVerification } = await import("@/lib/server/verify-helper");
    const { completeFlowOrGetUrl } = await import("@/lib/actions/flow");
    const { getPublicHost } = await import("@/lib/server/host");

    // Setup mocks
    mockHeaders = vi.mocked(headers);
    mockGetServiceUrlFromHeaders = vi.mocked(getServiceConfig);
    mockGetLoginSettings = vi.mocked(getLoginSettings);
    mockGetUserByID = vi.mocked(getUserByID);
    mockListUsers = vi.mocked(listUsers);
    mockSetSessionAndUpdateCookie = vi.mocked(setSessionAndUpdateCookie);
    mockCreateSessionAndUpdateCookie = vi.mocked(createSessionAndUpdateCookie);
    mockCreateSessionAndUpdateCookie.mockResolvedValue({
      session: { id: "new-session", factors: { user: { id: "user-1", loginName: "user" } } } as any,
      sessionCookie: { id: "new-session", token: "token", loginName: "user" },
    });
    mockGetSessionCookieById = vi.mocked(getSessionCookieById);
    mockGetSessionCookieByLoginName = vi.mocked(getSessionCookieByLoginName);
    mockGetMostRecentSessionCookie = vi.mocked(getMostRecentSessionCookie);
    mockCheckEmailVerification = vi.mocked(checkEmailVerification);
    mockCompleteFlowOrGetUrl = vi.mocked(completeFlowOrGetUrl);
    vi.mocked(getPublicHost).mockReturnValue("test.com");

    // Default mock implementations
    const headersList = new Headers();
    headersList.set("host", "test.com");
    mockHeaders.mockResolvedValue(headersList);
    mockGetServiceUrlFromHeaders.mockReturnValue({
      serviceUrl: "https://example.com",
    });
    mockGetLoginSettings.mockResolvedValue({
      multiFactorCheckLifetime: {
        seconds: BigInt(300),
        nanos: 0,
      },
    });
  });

  describe("Session Cookie Retrieval", () => {
    test("should return error when session cookie not found by sessionId", async () => {
      mockGetSessionCookieById.mockResolvedValue(null);

      const result = await sendPasskey({
        sessionId: "test-session-id",
        checks: { webAuthN: { credentialAssertionData: {} } } as any,
      });

      expect(result).toEqual({
        error: "couldNotFindSession",
      });
      expect(mockGetSessionCookieById).toHaveBeenCalledWith({
        sessionId: "test-session-id",
      });
    });

    test("should return error when session cookie is not found by loginName", async () => {
      mockGetSessionCookieByLoginName.mockResolvedValue(null); // Not found
      mockCreateSessionAndUpdateCookie.mockRejectedValue(new Error("Creation failed")); // Force creation failure

      const result = await sendPasskey({
        loginName: "test@example.com",
        organization: "org-123",
        checks: { webAuthN: { credentialAssertionData: {} } } as any,
      });

      expect(result).toEqual({
        error: "couldNotFindSession",
      });
      expect(mockGetSessionCookieByLoginName).toHaveBeenCalledWith({
        loginName: "test@example.com",
        organization: "org-123",
      });
    });

    test("should return error when no session cookie found (most recent fallback)", async () => {
      mockGetMostRecentSessionCookie.mockResolvedValue(null);

      const result = await sendPasskey({
        checks: { webAuthN: { credentialAssertionData: {} } } as any,
      });

      expect(result).toEqual({
        error: "couldNotFindSession",
      });
      expect(mockGetMostRecentSessionCookie).toHaveBeenCalled();
    });
  });

  describe("Session Update Failures", () => {
    beforeEach(() => {
      mockGetSessionCookieById.mockResolvedValue({
        id: "session-123",
        token: "session-token",
        loginName: "test@example.com",
      });
    });

    test("should return error when setSessionAndUpdateCookie fails", async () => {
      mockSetSessionAndUpdateCookie.mockResolvedValue({
        error: "Failed to update session",
      });

      const result = await sendPasskey({
        sessionId: "session-123",
        checks: { webAuthN: { credentialAssertionData: {} } } as any,
      });

      expect(result).toEqual({
        error: "couldNotUpdateSession",
      });
    });

    test("should return error when setSessionAndUpdateCookie returns undefined", async () => {
      mockSetSessionAndUpdateCookie.mockResolvedValue(undefined as any);

      const result = await sendPasskey({
        sessionId: "session-123",
        checks: { webAuthN: { credentialAssertionData: {} } } as any,
      });

      expect(result).toEqual({
        error: "couldNotUpdateSession",
      });
    });

    test("should fallback to createSessionAndUpdateCookie when setSessionAndUpdateCookie fails and checks are present", async () => {
      mockSetSessionAndUpdateCookie.mockRejectedValue(new Error("session already terminated"));

      mockCreateSessionAndUpdateCookie.mockResolvedValue({
        session: {
          id: "new-session-123",
          factors: {
            user: {
              id: "user-123",
              loginName: "test@example.com",
            },
          },
        },
        sessionCookie: {
          id: "new-session-123",
          token: "new-token",
        },
      });

      mockListUsers.mockResolvedValue({
        details: { totalResult: BigInt(1) },
        result: [{ userId: "user-123" }],
      });

      mockGetUserByID.mockResolvedValue({
        user: {
          id: "user-123",
          type: {
            case: "human",
            value: { email: { isVerified: true } },
          },
        },
      });

      mockCheckEmailVerification.mockResolvedValue(true);
      mockCompleteFlowOrGetUrl.mockResolvedValue({ redirect: "/dashboard" });

      const result = await sendPasskey({
        sessionId: "session-123",
        checks: { webAuthN: { credentialAssertionData: {} } } as any,
      });

      // It should succeed with the new session
      expect(result).toEqual({
        redirect: "/dashboard",
      });

      expect(mockCreateSessionAndUpdateCookie).toHaveBeenCalled();
    });
  });

  describe("User Validation", () => {
    beforeEach(() => {
      mockGetSessionCookieById.mockResolvedValue({
        id: "session-123",
        token: "session-token",
        loginName: "test@example.com",
      });
      mockSetSessionAndUpdateCookie.mockResolvedValue({
        sessionId: "session-123",
        sessionToken: "new-token",
        factors: {
          user: {
            id: "user-123",
          },
        },
      });
    });

    test("should return error when getUserByID fails", async () => {
      mockGetUserByID.mockRejectedValue(new Error("User not found"));

      const result = await sendPasskey({
        sessionId: "session-123",
        checks: { webAuthN: { credentialAssertionData: {} } } as any,
      });

      expect(result).toEqual({
        error: "verify.errors.couldNotGetUser",
      });
    });
  });

  describe("Successful Passkey Verification", () => {
    beforeEach(() => {
      mockGetSessionCookieById.mockResolvedValue({
        id: "session-123",
        token: "session-token",
        loginName: "test@example.com",
      });
      mockSetSessionAndUpdateCookie.mockResolvedValue({
        id: "session-123",
        factors: {
          user: {
            id: "user-123",
            loginName: "test@example.com",
          },
        },
      });
      mockGetUserByID.mockResolvedValue({
        user: {
          id: "user-123",
          type: {
            case: "human",
            value: {
              email: {
                isVerified: true,
              },
            },
          },
        },
      });
      mockCheckEmailVerification.mockResolvedValue(true);
    });

    test("should redirect on successful verification without requestId", async () => {
      mockCompleteFlowOrGetUrl.mockResolvedValue({ redirect: "/dashboard" });

      const result = await sendPasskey({
        sessionId: "session-123",
        checks: { webAuthN: { credentialAssertionData: {} } } as any,
      });

      expect(result).toEqual({
        redirect: "/dashboard",
      });
    });

    test("should redirect on successful verification with requestId", async () => {
      mockCompleteFlowOrGetUrl.mockResolvedValue({ redirect: "/auth/callback" });

      const result = await sendPasskey({
        sessionId: "session-123",
        requestId: "request-123",
        checks: { webAuthN: { credentialAssertionData: {} } } as any,
      });

      expect(result).toEqual({
        redirect: "/auth/callback",
      });
    });

    test("should redirect for email verification when required", async () => {
      mockCheckEmailVerification.mockReturnValue({ redirect: "/verify" });

      const result = await sendPasskey({
        sessionId: "session-123",
        checks: { webAuthN: { credentialAssertionData: {} } } as any,
      });

      expect(result).toHaveProperty("redirect");
      if ("redirect" in result) {
        expect(result.redirect).toContain("/verify");
      }
    });
  });

  describe("Fallback Error Handling - Critical Fix", () => {
    beforeEach(() => {
      mockGetSessionCookieById.mockResolvedValue({
        id: "session-123",
        token: "session-token",
        loginName: "test@example.com",
      });
      mockSetSessionAndUpdateCookie.mockResolvedValue({
        id: "session-123",
        factors: {
          user: {
            id: "user-123",
            loginName: "test@example.com",
          },
        },
      });
      mockGetUserByID.mockResolvedValue({
        user: {
          id: "user-123",
          type: {
            case: "human",
            value: {
              email: {
                isVerified: true,
              },
            },
          },
        },
      });
      mockCheckEmailVerification.mockResolvedValue(true);
    });

    test("should return fallback error when completeFlowOrGetUrl returns undefined", async () => {
      mockCompleteFlowOrGetUrl.mockResolvedValue(undefined);

      const result = await sendPasskey({
        sessionId: "session-123",
        checks: { webAuthN: { credentialAssertionData: {} } } as any,
      });

      expect(result).toEqual({
        error: "verify.errors.couldNotDetermineRedirect",
      });
    });

    test("should return fallback error when completeFlowOrGetUrl returns empty string", async () => {
      mockCompleteFlowOrGetUrl.mockResolvedValue("");

      const result = await sendPasskey({
        sessionId: "session-123",
        checks: { webAuthN: { credentialAssertionData: {} } } as any,
      });

      expect(result).toEqual({
        error: "verify.errors.couldNotDetermineRedirect",
      });
    });
  });

  describe("Custom Lifetime Handling", () => {
    beforeEach(() => {
      mockGetSessionCookieById.mockResolvedValue({
        id: "session-123",
        token: "session-token",
        loginName: "test@example.com",
      });
      mockSetSessionAndUpdateCookie.mockResolvedValue({
        id: "session-123",
        factors: {
          user: {
            id: "user-123",
            loginName: "test@example.com",
          },
        },
      });
      mockGetUserByID.mockResolvedValue({
        user: {
          id: "user-123",
          type: {
            case: "human",
            value: {
              email: {
                isVerified: true,
              },
            },
          },
        },
      });
      mockCheckEmailVerification.mockResolvedValue(true);
      mockCompleteFlowOrGetUrl.mockResolvedValue({ redirect: "/dashboard" });
    });

    test("should ignore a caller-supplied lifetime and use the login policy", async () => {
      await sendPasskey({
        sessionId: "session-123",
        // not part of the command type any more, but a direct POST to the action can still send it
        lifetime: { seconds: BigInt(10 * 365 * 24 * 60 * 60), nanos: 0 },
        checks: { webAuthN: { credentialAssertionData: {} } },
      } as any);

      expect(mockSetSessionAndUpdateCookie).toHaveBeenCalledWith(
        expect.objectContaining({
          lifetime: expect.objectContaining({
            seconds: BigInt(300),
          }),
        }),
      );
    });

    test("should use default lifetime from login settings when not provided", async () => {
      await sendPasskey({
        sessionId: "session-123",
        checks: { webAuthN: { credentialAssertionData: {} } } as any,
      });

      expect(mockSetSessionAndUpdateCookie).toHaveBeenCalledWith(
        expect.objectContaining({
          lifetime: expect.objectContaining({
            seconds: BigInt(300),
          }),
        }),
      );
    });
  });
});

describe("registerPasskeyLink", () => {
  let mockHeaders: any;
  let mockGetServiceConfig: any;
  let mockGetSession: any;
  let mockGetSessionCookieById: any;
  let mockCreatePasskeyRegistrationLink: any;
  let mockRegisterPasskey: any;
  let mockListAuthenticationMethodTypes: any;
  let mockGetPublicHost: any;
  let mockCheckUserVerification: any;

  beforeEach(async () => {
    vi.clearAllMocks();

    const { headers } = await import("next/headers");
    const { getServiceConfig } = await import("@/lib/server/service-url");
    const { getSession, createPasskeyRegistrationLink, registerPasskey, listAuthenticationMethodTypes } =
      await import("@/lib/server/zitadel");
    const { getSessionCookieById } = await import("@/lib/server/cookies");
    const { getPublicHost } = await import("@/lib/server/host");
    const { checkUserVerification } = await import("@/lib/server/verify-helper");

    mockHeaders = vi.mocked(headers);
    mockGetServiceConfig = vi.mocked(getServiceConfig);
    mockGetSession = vi.mocked(getSession);
    mockGetSessionCookieById = vi.mocked(getSessionCookieById);
    mockCreatePasskeyRegistrationLink = vi.mocked(createPasskeyRegistrationLink);
    mockRegisterPasskey = vi.mocked(registerPasskey);
    mockListAuthenticationMethodTypes = vi.mocked(listAuthenticationMethodTypes);
    mockGetPublicHost = vi.mocked(getPublicHost);
    mockCheckUserVerification = vi.mocked(checkUserVerification);

    const headersList = new Headers();
    headersList.set("host", "test.com");
    mockHeaders.mockResolvedValue(headersList);
    mockGetServiceConfig.mockReturnValue({ serviceConfig: { baseUrl: "https://example.com" } });
    mockGetPublicHost.mockReturnValue("test.com");

    const { getLoginSettings } = await import("@/lib/server/zitadel");
    vi.mocked(getLoginSettings).mockResolvedValue({ forceMfa: false, secondFactors: [], multiFactors: [] } as any);
    mockListAuthenticationMethodTypes.mockResolvedValue({ authMethodTypes: [AuthenticationMethodType.PASSWORD] });
  });

  test("should return error when neither sessionId nor userId is provided", async () => {
    const result = await registerPasskeyLink({});
    expect(result).toEqual({ error: "Either sessionId or userId must be provided" });
  });

  test("should return error when session cookie is not found", async () => {
    mockGetSessionCookieById.mockResolvedValue(null);

    const result = await registerPasskeyLink({ sessionId: "session-123" });
    expect(result).toEqual({ error: "Could not get session cookie" });
  });

  describe("IDP-authenticated session", () => {
    const sessionCookie = {
      id: "session-123",
      token: "session-token",
      loginName: "max@zitadel.com",
    };

    const idpSession = {
      session: {
        id: "session-123",
        factors: {
          user: { id: "user-123", loginName: "max@zitadel.com", verifiedAt: { seconds: BigInt(1700000000), nanos: 0 } },
          intent: {
            verifiedAt: { seconds: BigInt(1700000000), nanos: 0 },
          },
        },
      },
    };

    test("should succeed for session authenticated via IDP intent", async () => {
      mockGetSessionCookieById.mockResolvedValue(sessionCookie);
      mockGetSession.mockResolvedValue(idpSession);
      mockCreatePasskeyRegistrationLink.mockResolvedValue({
        code: { id: "code-id", code: "code-value" },
      });
      mockRegisterPasskey.mockResolvedValue({
        passkeyId: "passkey-123",
        publicKeyCredentialCreationOptions: {},
      });

      const result = await registerPasskeyLink({ sessionId: "session-123" });

      expect(result).toHaveProperty("passkeyId");
      expect(mockRegisterPasskey).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: "user-123",
          domain: "test.com",
        }),
      );
    });

    test("should not require user verification or auth method check when IDP session is valid", async () => {
      mockGetSessionCookieById.mockResolvedValue(sessionCookie);
      mockGetSession.mockResolvedValue(idpSession);
      mockCreatePasskeyRegistrationLink.mockResolvedValue({
        code: { id: "code-id", code: "code-value" },
      });
      mockRegisterPasskey.mockResolvedValue({
        passkeyId: "passkey-123",
        publicKeyCredentialCreationOptions: {},
      });

      await registerPasskeyLink({ sessionId: "session-123" });

      // Should NOT call checkUserVerification because the session is already valid via IDP intent.
      // AZDIGI: the user's methods ARE read, by the policy (a password must not get past a configured TOTP).
      expect(mockCheckUserVerification).not.toHaveBeenCalled();
    });
  });

  describe("password-authenticated session", () => {
    test("should succeed for session authenticated via password", async () => {
      mockGetSessionCookieById.mockResolvedValue({
        id: "session-123",
        token: "session-token",
        loginName: "max@zitadel.com",
      });
      mockGetSession.mockResolvedValue({
        session: {
          id: "session-123",
          factors: {
            user: { id: "user-123", loginName: "max@zitadel.com", verifiedAt: { seconds: BigInt(1700000000), nanos: 0 } },
            password: {
              verifiedAt: { seconds: BigInt(1700000000), nanos: 0 },
            },
          },
        },
      });
      mockCreatePasskeyRegistrationLink.mockResolvedValue({
        code: { id: "code-id", code: "code-value" },
      });
      mockRegisterPasskey.mockResolvedValue({
        passkeyId: "passkey-123",
        publicKeyCredentialCreationOptions: {},
      });

      const result = await registerPasskeyLink({ sessionId: "session-123" });

      expect(result).toHaveProperty("passkeyId");
    });
  });

  describe("session with no valid factors", () => {
    test("should return error when session has no verified factors and user has auth methods", async () => {
      mockGetSessionCookieById.mockResolvedValue({
        id: "session-123",
        token: "session-token",
        loginName: "max@zitadel.com",
      });
      mockGetSession.mockResolvedValue({
        session: {
          id: "session-123",
          factors: {
            user: { id: "user-123", loginName: "max@zitadel.com", verifiedAt: { seconds: BigInt(1700000000), nanos: 0 } },
            // No password, no webAuthN, no intent
          },
        },
      });
      mockListAuthenticationMethodTypes.mockResolvedValue({
        authMethodTypes: [1], // has at least one auth method
      });

      const result = await registerPasskeyLink({ sessionId: "session-123" });

      expect(result).toEqual({ error: ENROLMENT_REFUSED });
      expect(mockRegisterPasskey).not.toHaveBeenCalled();
    });

    test("should check user verification when session has no factors and user has no auth methods", async () => {
      mockGetSessionCookieById.mockResolvedValue({
        id: "session-123",
        token: "session-token",
        loginName: "max@zitadel.com",
      });
      mockGetSession.mockResolvedValue({
        session: {
          id: "session-123",
          factors: {
            user: { id: "user-123", loginName: "max@zitadel.com", verifiedAt: { seconds: BigInt(1700000000), nanos: 0 } },
          },
        },
      });
      mockListAuthenticationMethodTypes.mockResolvedValue({
        authMethodTypes: [],
      });
      mockCheckUserVerification.mockResolvedValue(false);

      const result = await registerPasskeyLink({ sessionId: "session-123" });

      expect(result).toEqual({ error: ENROLMENT_REFUSED });
      expect(mockCheckUserVerification).toHaveBeenCalledWith("user-123");
    });

    test("should proceed when session has no factors but user verification passes", async () => {
      mockGetSessionCookieById.mockResolvedValue({
        id: "session-123",
        token: "session-token",
        loginName: "max@zitadel.com",
      });
      mockGetSession.mockResolvedValue({
        session: {
          id: "session-123",
          factors: {
            user: { id: "user-123", loginName: "max@zitadel.com", verifiedAt: { seconds: BigInt(1700000000), nanos: 0 } },
          },
        },
      });
      mockListAuthenticationMethodTypes.mockResolvedValue({
        authMethodTypes: [],
      });
      mockCheckUserVerification.mockResolvedValue(true);
      mockCreatePasskeyRegistrationLink.mockResolvedValue({
        code: { id: "code-id", code: "code-value" },
      });
      mockRegisterPasskey.mockResolvedValue({
        passkeyId: "passkey-123",
        publicKeyCredentialCreationOptions: {},
      });

      const result = await registerPasskeyLink({ sessionId: "session-123" });

      expect(result).toHaveProperty("passkeyId");
    });
  });
});

describe("passkey enrolment past the forced second factor (AZDIGI)", () => {
  const staffSession = {
    session: {
      id: "session-1",
      factors: {
        user: {
          id: "staff-1",
          loginName: "staff@example.com",
          organizationId: "internal",
          verifiedAt: { seconds: BigInt(1700000000), nanos: 0 },
        },
        password: { verifiedAt: { seconds: BigInt(1700000000), nanos: 0 } },
      },
    },
  };

  beforeEach(async () => {
    vi.clearAllMocks();
    const { headers } = await import("next/headers");
    const { getServiceConfig } = await import("@/lib/server/service-url");
    const { getPublicHost } = await import("@/lib/server/host");
    const zitadel = await import("@/lib/server/zitadel");
    const cookies = await import("@/lib/server/cookies");
    vi.mocked(headers).mockResolvedValue(new Headers() as any);
    vi.mocked(getServiceConfig).mockReturnValue({ serviceConfig: { baseUrl: "https://example.com" } } as any);
    vi.mocked(getPublicHost).mockReturnValue("test.com");
    vi.mocked(cookies.getSessionCookieById).mockResolvedValue({ id: "session-1", token: "t" } as any);
    vi.mocked(zitadel.getSession).mockResolvedValue(staffSession as any);
    // staff: MFA forced, and this member already set up an authenticator app
    vi.mocked(zitadel.getLoginSettings).mockResolvedValue({
      forceMfa: true,
      secondFactors: [1, 2],
      multiFactors: [],
    } as any);
    vi.mocked(zitadel.listAuthenticationMethodTypes).mockResolvedValue({
      authMethodTypes: [AuthenticationMethodType.PASSWORD, AuthenticationMethodType.TOTP],
    } as any);
  });

  test("a known password alone cannot start a passkey registration", async () => {
    const zitadel = await import("@/lib/server/zitadel");
    expect(await registerPasskeyLink({ sessionId: "session-1" })).toEqual({ error: ENROLMENT_REFUSED });
    expect(zitadel.createPasskeyRegistrationLink).not.toHaveBeenCalled();
    expect(zitadel.registerPasskey).not.toHaveBeenCalled();
  });

  test("nor finish one through the session path", async () => {
    await expect(
      verifyPasskeyRegistration({ passkeyId: "p1", publicKeyCredential: {}, passkeyName: "k", sessionId: "session-1" }),
    ).rejects.toThrow(ENROLMENT_REFUSED);
  });

  test("the first set-up of a staff member with no strong factor is allowed after the password", async () => {
    const zitadel = await import("@/lib/server/zitadel");
    vi.mocked(zitadel.listAuthenticationMethodTypes).mockResolvedValue({
      authMethodTypes: [AuthenticationMethodType.PASSWORD],
    } as any);
    vi.mocked(zitadel.createPasskeyRegistrationLink).mockResolvedValue({ code: { id: "c", code: "v" } } as any);
    vi.mocked(zitadel.registerPasskey).mockResolvedValue({ passkeyId: "p1" } as any);
    expect(await registerPasskeyLink({ sessionId: "session-1" })).toHaveProperty("passkeyId", "p1");
  });

  test("a code-started registration can only be finished by the browser that started it", async () => {
    const zitadel = await import("@/lib/server/zitadel");
    const proof = await import("@/lib/azdigi/passkey-registration-proof");
    vi.mocked(zitadel.getUserByID).mockResolvedValue({ user: { preferredLoginName: "new@example.com" } } as any);

    vi.mocked(proof.wasStartedWithCode).mockResolvedValue(false);
    await expect(
      verifyPasskeyRegistration({ passkeyId: "p1", publicKeyCredential: {}, passkeyName: "k", userId: "u1" }),
    ).rejects.toThrow(ENROLMENT_REFUSED);
    expect(proof.wasStartedWithCode).toHaveBeenCalledWith("u1", "p1");

    vi.mocked(proof.wasStartedWithCode).mockResolvedValue(true);
    vi.mocked(zitadel.verifyPasskeyRegistration).mockResolvedValue({} as any);
    await expect(
      verifyPasskeyRegistration({ passkeyId: "p1", publicKeyCredential: {}, passkeyName: "k", userId: "u1" }),
    ).resolves.toMatchObject({ loginName: "new@example.com" });
  });

  test("a registration started with the emailed code remembers this browser", async () => {
    const zitadel = await import("@/lib/server/zitadel");
    const proof = await import("@/lib/azdigi/passkey-registration-proof");
    const sessionCookie = await import("@/lib/server/session-cookie");
    vi.mocked(zitadel.getUserByID).mockResolvedValue({ user: { preferredLoginName: "new@example.com" } } as any);
    vi.mocked(sessionCookie.createSessionAndUpdateCookie).mockResolvedValue({ session: { id: "s2" } } as any);
    vi.mocked(zitadel.registerPasskey).mockResolvedValue({ passkeyId: "p9" } as any);

    await registerPasskeyLink({ userId: "u1", code: "v", codeId: "c" });

    expect(proof.rememberCodeStartedRegistration).toHaveBeenCalledWith("u1", "p9");
  });
});
