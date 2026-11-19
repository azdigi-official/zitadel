import { approveDeviceAuthorization, denyDeviceAuthorization } from "@/lib/actions/device";
import { beforeEach, describe, expect, test, vi } from "vitest";

vi.mock("@/lib/server/zitadel", () => ({
  authorizeOrDenyDeviceAuthorization: vi.fn(),
  getDeviceAuthorizationRequest: vi.fn(),
}));

vi.mock("@/lib/server/cookies", () => ({
  getSessionCookieById: vi.fn(),
}));

// AZDIGI: every grant goes through the guarded wrapper (lib/azdigi/issue.ts, tested there); here it passes the call on
// so upstream's assertions about the session token still apply
vi.mock("@/lib/azdigi/issue", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/azdigi/issue")>();
  const zitadel = await import("@/lib/server/zitadel");
  return {
    ...actual,
    guardedDeviceAuthorization: vi.fn((args: Parameters<typeof zitadel.authorizeOrDenyDeviceAuthorization>[0]) =>
      zitadel.authorizeOrDenyDeviceAuthorization(args),
    ),
  };
});

vi.mock("@/lib/server/session", () => ({
  sessionVerdict: vi.fn(),
  loadSession: vi.fn(),
}));

vi.mock("@/lib/server/device-code-check", () => ({
  checkDeviceCodeCheckCookie: vi.fn(),
  deleteDeviceCodeCheckCookie: vi.fn(),
}));

vi.mock("@/lib/server/service-url", () => ({
  getServiceConfig: vi.fn(() => ({ serviceConfig: { baseUrl: "https://example.com" } })),
}));

vi.mock("next-intl/server", () => ({
  getTranslations: vi.fn(async () => (key: string) => key),
}));

vi.mock("next/headers", () => ({
  headers: vi.fn(() => new Headers()),
}));

const cookie = {
  id: "session-1",
  token: "token-1",
  loginName: "user@example.com",
  organization: "org-1",
};

const session = {
  id: "session-1",
  factors: { user: { id: "user-1", loginName: "user@example.com", organizationId: "org-1" } },
};

describe("device authorization actions", () => {
  let authorizeOrDenyDeviceAuthorization: any;
  let getDeviceAuthorizationRequest: any;
  let loadSession: any;
  let getSessionCookieById: any;
  let sessionVerdict: any;
  let checkDeviceCodeCheckCookie: any;
  let deleteDeviceCodeCheckCookie: any;

  beforeEach(async () => {
    vi.clearAllMocks();
    const zitadel = await import("@/lib/server/zitadel");
    const cookies = await import("@/lib/server/cookies");
    const sessionLib = await import("@/lib/server/session");
    const deviceCodeCheck = await import("@/lib/server/device-code-check");

    authorizeOrDenyDeviceAuthorization = vi.mocked(zitadel.authorizeOrDenyDeviceAuthorization);
    getDeviceAuthorizationRequest = vi.mocked(zitadel.getDeviceAuthorizationRequest);
    loadSession = vi.mocked(sessionLib.loadSession);
    getSessionCookieById = vi.mocked(cookies.getSessionCookieById);
    sessionVerdict = vi.mocked(sessionLib.sessionVerdict);
    checkDeviceCodeCheckCookie = vi.mocked(deviceCodeCheck.checkDeviceCodeCheckCookie);
    deleteDeviceCodeCheckCookie = vi.mocked(deviceCodeCheck.deleteDeviceCodeCheckCookie);

    getSessionCookieById.mockResolvedValue(cookie);
    loadSession.mockResolvedValue(session);
    checkDeviceCodeCheckCookie.mockResolvedValue(true);
    sessionVerdict.mockResolvedValue({ ok: true });
    getDeviceAuthorizationRequest.mockResolvedValue({
      deviceAuthorizationRequest: { id: "device-request-1", appName: "My Device" },
    });
    authorizeOrDenyDeviceAuthorization.mockResolvedValue({ details: {} });
  });

  describe("approveDeviceAuthorization", () => {
    test("approves with the session of the cookie identified by sessionId", async () => {
      const res = await approveDeviceAuthorization({
        userCode: "ABCD-1234",
        sessionId: "session-1",
        organization: "org-1",
      });

      expect(checkDeviceCodeCheckCookie).toHaveBeenCalledWith("ABCD-1234");
      expect(getSessionCookieById).toHaveBeenCalledWith({ sessionId: "session-1", organization: "org-1" });
      expect(loadSession).toHaveBeenCalledWith(expect.anything(), cookie);
      expect(getDeviceAuthorizationRequest).toHaveBeenCalledWith({
        serviceConfig: expect.anything(),
        userCode: "ABCD-1234",
      });
      expect(authorizeOrDenyDeviceAuthorization).toHaveBeenCalledWith({
        serviceConfig: expect.anything(),
        deviceAuthorizationId: "device-request-1",
        session: { sessionId: "session-1", sessionToken: "token-1" },
      });
      expect(res).toEqual({ redirect: expect.stringContaining("/signedin?") });
      expect((res as { redirect: string }).redirect).toContain("requestId=device_ABCD-1234");
      expect(deleteDeviceCodeCheckCookie).toHaveBeenCalled();
    });

    test("redirects to the code entry page and does not approve when the device code check fails", async () => {
      checkDeviceCodeCheckCookie.mockResolvedValue(false);

      const res = await approveDeviceAuthorization({ userCode: "ABCD-1234", sessionId: "session-1" });

      expect(res).toEqual({ redirect: "/device?user_code=ABCD-1234" });
      expect(getDeviceAuthorizationRequest).not.toHaveBeenCalled();
      expect(authorizeOrDenyDeviceAuthorization).not.toHaveBeenCalled();
    });

    test("returns an error and does not approve when the session is stale", async () => {
      loadSession.mockResolvedValue(undefined);

      const res = await approveDeviceAuthorization({ userCode: "ABCD-1234", sessionId: "session-1" });

      expect(res).toEqual({ error: "sessionExpired" });
      expect(authorizeOrDenyDeviceAuthorization).not.toHaveBeenCalled();
    });

    test("never takes the session token from the caller", async () => {
      await approveDeviceAuthorization({
        userCode: "ABCD-1234",
        sessionId: "session-1",
        sessionToken: "attacker-token",
      } as any);

      expect(authorizeOrDenyDeviceAuthorization).toHaveBeenCalledWith(
        expect.objectContaining({ session: { sessionId: "session-1", sessionToken: "token-1" } }),
      );
    });

    test("returns an error and does not approve when no cookie matches", async () => {
      getSessionCookieById.mockResolvedValue(undefined);

      const res = await approveDeviceAuthorization({ userCode: "ABCD-1234", sessionId: "session-1" });

      expect(res).toHaveProperty("error");
      expect(authorizeOrDenyDeviceAuthorization).not.toHaveBeenCalled();
    });

    test("AZDIGI: a refused session continues at the step the policy names and is not approved", async () => {
      // e.g. a staff password session whose second factor has expired: back to /mfa, not to the password page
      sessionVerdict.mockResolvedValue({ ok: false, reason: "second-factor-missing", next: "mfa" });

      const res = await approveDeviceAuthorization({ userCode: "ABCD-1234", sessionId: "session-1" });

      expect(res).toEqual({
        redirect: "/mfa?loginName=user%40example.com&organization=org-1&requestId=device_ABCD-1234",
      });
      expect(getDeviceAuthorizationRequest).not.toHaveBeenCalled();
      expect(authorizeOrDenyDeviceAuthorization).not.toHaveBeenCalled();
    });
  });

  describe("denyDeviceAuthorization", () => {
    test("denies the request without passing the session to the backend", async () => {
      await denyDeviceAuthorization({ userCode: "ABCD-1234", sessionId: "session-1", organization: "org-1" });

      expect(getSessionCookieById).toHaveBeenCalledWith({ sessionId: "session-1", organization: "org-1" });

      expect(getDeviceAuthorizationRequest).toHaveBeenCalledWith({
        serviceConfig: expect.anything(),
        userCode: "ABCD-1234",
      });
      expect(authorizeOrDenyDeviceAuthorization).toHaveBeenCalledWith({
        serviceConfig: expect.anything(),
        deviceAuthorizationId: "device-request-1",
      });
      expect(deleteDeviceCodeCheckCookie).toHaveBeenCalled();
    });

    test("redirects to the code entry page and does not deny when the device code check fails", async () => {
      checkDeviceCodeCheckCookie.mockResolvedValue(false);

      const res = await denyDeviceAuthorization({ userCode: "ABCD-1234", sessionId: "session-1" });

      expect(res).toEqual({ redirect: "/device?user_code=ABCD-1234" });
      expect(authorizeOrDenyDeviceAuthorization).not.toHaveBeenCalled();
    });

    test("returns an error and does not deny without a session cookie", async () => {
      getSessionCookieById.mockResolvedValue(undefined);

      const res = await denyDeviceAuthorization({ userCode: "ABCD-1234", sessionId: "session-1" });

      expect(res).toEqual({ error: "unknownContext" });
      expect(authorizeOrDenyDeviceAuthorization).not.toHaveBeenCalled();
    });

    test("returns an error and does not deny when the session is stale", async () => {
      loadSession.mockResolvedValue(undefined);

      const res = await denyDeviceAuthorization({ userCode: "ABCD-1234", sessionId: "session-1" });

      expect(res).toEqual({ error: "sessionExpired" });
      expect(authorizeOrDenyDeviceAuthorization).not.toHaveBeenCalled();
    });
  });
});
