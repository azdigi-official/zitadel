import * as issueModule from "@/lib/azdigi/issue";
import { loginWithSAMLAndSession } from "@/lib/server/saml";
import * as sessionModule from "@/lib/server/session";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/server/session");
vi.mock("@/lib/server/zitadel");
vi.mock("@/lib/azdigi/issue", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/azdigi/issue")>();
  return { ...actual, guardedCreateResponse: vi.fn() };
});
vi.mock("@/lib/server/grpc/interceptors/error-classification", () => ({
  isClassifiedError: (error: unknown): boolean =>
    typeof error === "object" && error !== null && "code" in error && typeof (error as any).code === "number",
}));

vi.mock("@zitadel/client", () => ({
  Code: { FailedPrecondition: 9 },
  create: vi.fn(),
}));

describe("loginWithSAMLAndSession", () => {
  const mockServiceConfig = { baseUrl: "https://zitadel.example.com" };
  const mockSamlRequest = "saml-123";
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

  const login = (sessions = mockSessions) =>
    loginWithSAMLAndSession({
      serviceConfig: mockServiceConfig as any,
      samlRequest: mockSamlRequest,
      sessionId: mockSessionId,
      sessions,
      sessionCookies: mockCookies,
    });

  it("should redirect to the SAML response URL when session is valid", async () => {
    vi.mocked(sessionModule.checkSessionPolicy).mockResolvedValue({ ok: true });
    vi.mocked(issueModule.guardedCreateResponse).mockResolvedValue({
      url: "https://sp.example.com/acs",
      binding: { case: "redirect", value: {} },
    } as any);

    const result = await login();

    expect(result).toEqual({ redirect: "https://sp.example.com/acs" });
  });

  // AZDIGI: an invalid session is answered with the screen the organisation's policy names; no SAML response is created
  it("should redirect to the policy's next step when the session is invalid, without a response", async () => {
    vi.mocked(sessionModule.checkSessionPolicy).mockResolvedValue({
      ok: false,
      reason: "no-first-factor",
      next: "password",
    });

    const result = await login();

    expect(result).toEqual({
      redirect: `/password?loginName=test%40example.com&organization=org-123&requestId=saml_${mockSamlRequest}`,
    });
    expect(issueModule.guardedCreateResponse).not.toHaveBeenCalled();
  });

  it("should not create a SAML response for an invalid session without a user factor", async () => {
    vi.mocked(sessionModule.checkSessionPolicy).mockResolvedValue({ ok: false, reason: "no-user", next: "loginname" });

    const result = await login([{ id: mockSessionId, factors: {} }]);

    expect(result).toEqual({ redirect: `/loginname?requestId=saml_${mockSamlRequest}` });
    expect(issueModule.guardedCreateResponse).not.toHaveBeenCalled();
  });
});
