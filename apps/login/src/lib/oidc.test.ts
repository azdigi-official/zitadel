/**
 * loginWithOIDCAndSession after the AZDIGI change: the session is checked with checkSessionPolicy (fresh policy) and
 * tokens are requested through the guarded wrapper; a refusal redirects to the screen the verdict names.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import * as issueModule from "./azdigi/issue";
import { PolicyRejectedError } from "./azdigi/issue";
import { loginWithOIDCAndSession } from "./oidc";
import * as sessionModule from "./session";
import * as zitadelModule from "./zitadel";

vi.mock("./session", () => ({ checkSessionPolicy: vi.fn() }));
vi.mock("./zitadel", () => ({ getLoginSettings: vi.fn() }));
vi.mock("./azdigi/issue", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./azdigi/issue")>();
  return { ...actual, guardedCreateCallback: vi.fn() };
});

describe("loginWithOIDCAndSession", () => {
  const serviceConfig = { baseUrl: "https://zitadel.example.com" };
  const authRequest = "auth-123";
  const sessionId = "session-123";

  let sessions: any[];
  let sessionCookies: any[];

  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.mocked(sessionModule.checkSessionPolicy).mockResolvedValue({ ok: true });

    sessions = [
      {
        id: sessionId,
        factors: {
          user: { id: "user-123", loginName: "test@example.com", organizationId: "org-123" },
          password: { verifiedAt: { seconds: BigInt(Math.floor(Date.now() / 1000)) } },
        },
      },
    ];
    sessionCookies = [{ id: sessionId, token: "token-123", loginName: "test@example.com", creationTs: "", expirationTs: "", changeTs: "" }];
  });

  it("redirects to the callback URL when the policy accepts the session", async () => {
    vi.mocked(issueModule.guardedCreateCallback).mockResolvedValue({ callbackUrl: "https://app.example.com/callback" } as any);

    const result = await loginWithOIDCAndSession({ serviceConfig, authRequest, sessionId, sessions, sessionCookies });

    expect(result).toEqual({ redirect: "https://app.example.com/callback" });
    expect(issueModule.guardedCreateCallback).toHaveBeenCalledWith({
      serviceConfig,
      authRequestId: authRequest,
      session: { sessionId, sessionToken: "token-123" },
    });
  });

  it("redirects to the screen the verdict names when the policy refuses, without asking for tokens", async () => {
    vi.mocked(sessionModule.checkSessionPolicy).mockResolvedValue({ ok: false, reason: "second-factor-missing", next: "mfa" });

    const result = await loginWithOIDCAndSession({ serviceConfig, authRequest, sessionId, sessions, sessionCookies });

    expect(result).toEqual({ redirect: "/mfa?loginName=test%40example.com&organization=org-123&requestId=oidc_auth-123" });
    expect(issueModule.guardedCreateCallback).not.toHaveBeenCalled();
  });

  it("follows the wrapper's refusal too (it re-reads the session with its token)", async () => {
    vi.mocked(issueModule.guardedCreateCallback).mockRejectedValue(
      new PolicyRejectedError({ ok: false, reason: "no-first-factor", next: "otpEmail" }, sessions[0]),
    );

    const result = await loginWithOIDCAndSession({ serviceConfig, authRequest, sessionId, sessions, sessionCookies });

    expect(result).toEqual({ redirect: "/otp/email?loginName=test%40example.com&organization=org-123&requestId=oidc_auth-123" });
  });

  it("returns an error when the cookie is missing", async () => {
    const result = await loginWithOIDCAndSession({ serviceConfig, authRequest, sessionId, sessions, sessionCookies: [] });

    expect(result).toEqual({ error: "Session not found or invalid" });
    expect(issueModule.guardedCreateCallback).not.toHaveBeenCalled();
  });

  it("returns an error when the session is unknown", async () => {
    const result = await loginWithOIDCAndSession({ serviceConfig, authRequest, sessionId: "other", sessions, sessionCookies });

    expect(result).toEqual({ error: "Session not found or invalid" });
  });

  it("handles error code 9 with the default redirect URI", async () => {
    vi.mocked(issueModule.guardedCreateCallback).mockRejectedValue({ code: 9 });
    vi.mocked(zitadelModule.getLoginSettings).mockResolvedValue({ defaultRedirectUri: "https://default.example.com" } as any);

    const result = await loginWithOIDCAndSession({ serviceConfig, authRequest, sessionId, sessions, sessionCookies });

    expect(result).toEqual({ redirect: "https://default.example.com" });
  });

  it("redirects to /signedin on error code 9 without a default URI", async () => {
    vi.mocked(issueModule.guardedCreateCallback).mockRejectedValue({ code: 9 });
    vi.mocked(zitadelModule.getLoginSettings).mockResolvedValue({} as any);

    const result = await loginWithOIDCAndSession({ serviceConfig, authRequest, sessionId, sessions, sessionCookies });

    expect(result).toEqual({ redirect: "/signedin?loginName=test%40example.com&organization=org-123" });
  });

  it("returns an unknown error for other failures", async () => {
    vi.mocked(issueModule.guardedCreateCallback).mockRejectedValue({ code: 13, message: "boom" });

    const result = await loginWithOIDCAndSession({ serviceConfig, authRequest, sessionId, sessions, sessionCookies });

    expect(result).toEqual({ error: "Unknown error occurred" });
  });
});
