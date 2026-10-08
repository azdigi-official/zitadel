import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { describe, expect, test, vi, beforeEach } from "vitest";
import * as zitadel from "../zitadel";
import { guardedCreateCallback, guardedCreateResponse, guardedDeviceAuthorization, isPolicyRejected, PolicyRejectedError, redirectForVerdict } from "./issue";
import * as orgLookup from "./org-lookup";

vi.mock("../zitadel", () => ({
  getSession: vi.fn(),
  getLoginSettings: vi.fn(),
  listAuthenticationMethodTypes: vi.fn(),
  createCallback: vi.fn(),
  createResponse: vi.fn(),
  authorizeOrDenyDeviceAuthorization: vi.fn(),
  getAuthRequest: vi.fn(),
  getOrgsByDomain: vi.fn(),
}));
vi.mock("./org-lookup", () => ({ isOtpFirstOrg: vi.fn() }));

const cfg = { baseUrl: "http://api" };
const ref = { sessionId: "s1", sessionToken: "tok" };
const at = { seconds: BigInt(Math.floor(Date.now() / 1000) - 10), nanos: 0 };
const future = { seconds: BigInt(Math.floor(Date.now() / 1000) + 3600), nanos: 0 };

function session(factors: any) {
  return { id: "s1", expirationDate: future, factors: { user: { id: "u1", organizationId: "100", loginName: "a@b.c", verifiedAt: at }, ...factors } };
}

describe("guarded token issuance", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.mocked(zitadel.getLoginSettings).mockResolvedValue({ forceMfa: false, secondFactors: [3], multiFactors: [] } as any);
    vi.mocked(orgLookup.isOtpFirstOrg).mockResolvedValue(true);
    vi.mocked(zitadel.listAuthenticationMethodTypes).mockResolvedValue({ authMethodTypes: [] } as any);
    vi.mocked(zitadel.getAuthRequest).mockResolvedValue({ authRequest: { scope: ["openid"] } } as any);
  });

  test("user-only session gets no OIDC callback, no SAML response, no device grant", async () => {
    vi.mocked(zitadel.getSession).mockResolvedValue({ session: session({}) } as any);
    await expect(guardedCreateCallback({ serviceConfig: cfg, authRequestId: "a", session: ref })).rejects.toBeInstanceOf(PolicyRejectedError);
    await expect(guardedCreateResponse({ serviceConfig: cfg, samlRequestId: "a", session: ref })).rejects.toBeInstanceOf(PolicyRejectedError);
    await expect(guardedDeviceAuthorization({ serviceConfig: cfg, deviceAuthorizationId: "d", session: ref })).rejects.toBeInstanceOf(PolicyRejectedError);
    expect(zitadel.createCallback).not.toHaveBeenCalled();
    expect(zitadel.createResponse).not.toHaveBeenCalled();
    expect(zitadel.authorizeOrDenyDeviceAuthorization).not.toHaveBeenCalled();
  });

  test("settings are read fresh and the raw call happens with the session reference", async () => {
    vi.mocked(zitadel.getSession).mockResolvedValue({ session: session({ otpEmail: { verifiedAt: at } }) } as any);
    vi.mocked(zitadel.createCallback).mockResolvedValue({ callbackUrl: "https://rp/cb" } as any);
    const res = await guardedCreateCallback({ serviceConfig: cfg, authRequestId: "a", session: ref });
    expect(res.callbackUrl).toBe("https://rp/cb");
    expect(zitadel.getLoginSettings).toHaveBeenCalledWith({ serviceConfig: cfg, organization: "100", fresh: true });
    const req = vi.mocked(zitadel.createCallback).mock.calls[0][0].req as any;
    expect(req.authRequestId).toBe("a");
    expect(req.callbackKind.value.sessionId).toBe("s1");
  });

  test("a request scoped to another organisation gets no callback and restarts there without the account name", async () => {
    vi.mocked(zitadel.getSession).mockResolvedValue({ session: session({ otpEmail: { verifiedAt: at } }) } as any);
    vi.mocked(zitadel.getAuthRequest).mockResolvedValue({ authRequest: { scope: ["openid", "urn:zitadel:iam:org:id:900"] } } as any);
    const error = await guardedCreateCallback({ serviceConfig: cfg, authRequestId: "a", session: ref }).catch((e) => e);
    expect(isPolicyRejected(error)).toBe(true);
    expect(error.verdict).toEqual({ ok: false, reason: "org-mismatch", next: "loginname", organization: "900" });
    expect(zitadel.createCallback).not.toHaveBeenCalled();
    expect(redirectForVerdict(error.verdict, error.session, "oidc_a")).toBe("/loginname?organization=900&requestId=oidc_a");
  });

  test("a request scoped to the user's own organisation gets its callback", async () => {
    vi.mocked(zitadel.getSession).mockResolvedValue({ session: session({ otpEmail: { verifiedAt: at } }) } as any);
    vi.mocked(zitadel.getAuthRequest).mockResolvedValue({ authRequest: { scope: ["openid", "urn:zitadel:iam:org:id:100"] } } as any);
    vi.mocked(zitadel.createCallback).mockResolvedValue({ callbackUrl: "https://rp/cb" } as any);
    expect((await guardedCreateCallback({ serviceConfig: cfg, authRequestId: "a", session: ref })).callbackUrl).toBe("https://rp/cb");
  });

  test("an auth request Zitadel no longer has is reported as already handled (code 9), never answered with tokens", async () => {
    vi.mocked(zitadel.getSession).mockResolvedValue({ session: session({ otpEmail: { verifiedAt: at } }) } as any);
    vi.mocked(zitadel.getAuthRequest).mockRejectedValue(Object.assign(new Error("not found"), { code: 5 }));
    await expect(guardedCreateCallback({ serviceConfig: cfg, authRequestId: "a", session: ref })).rejects.toMatchObject({ code: 9 });
    vi.mocked(zitadel.getAuthRequest).mockResolvedValue({} as any);
    await expect(guardedCreateCallback({ serviceConfig: cfg, authRequestId: "a", session: ref })).rejects.toMatchObject({ code: 9 });
    expect(zitadel.createCallback).not.toHaveBeenCalled();
  });

  test("a session that cannot be loaded is refused", async () => {
    vi.mocked(zitadel.getSession).mockRejectedValue(new Error("not found"));
    await expect(guardedCreateCallback({ serviceConfig: cfg, authRequestId: "a", session: ref })).rejects.toMatchObject({ verdict: { reason: "no-user" } });
  });

  test("device denial without a session passes through", async () => {
    vi.mocked(zitadel.authorizeOrDenyDeviceAuthorization).mockResolvedValue({} as any);
    await guardedDeviceAuthorization({ serviceConfig: cfg, deviceAuthorizationId: "d" });
    expect(zitadel.getSession).not.toHaveBeenCalled();
    expect(zitadel.authorizeOrDenyDeviceAuthorization).toHaveBeenCalledWith({ serviceConfig: cfg, deviceAuthorizationId: "d", session: undefined });
  });

  test("redirectForVerdict builds the next screen", () => {
    const s = session({}) as any;
    expect(redirectForVerdict({ ok: false, reason: "no-first-factor", next: "otpEmail" }, s, "oidc_1")).toBe(
      "/otp/email?loginName=a%40b.c&organization=100&requestId=oidc_1",
    );
    expect(redirectForVerdict({ ok: false, reason: "second-factor-missing", next: "mfa" }, s)).toBe("/mfa?loginName=a%40b.c&organization=100");
    expect(redirectForVerdict({ ok: false, reason: "second-factor-missing", next: "mfaSetup" }, { ...s, id: "s1" }, "oidc_1")).toBe(
      "/mfa/set?loginName=a%40b.c&organization=100&requestId=oidc_1&force=true&checkAfter=true&sessionId=s1",
    );
    expect(redirectForVerdict({ ok: false, reason: "no-user", next: "loginname" }, undefined)).toBe("/loginname?");
    expect(isPolicyRejected(new PolicyRejectedError({ ok: false, reason: "expired", next: "loginname" }, undefined))).toBe(true);
    expect(isPolicyRejected(new Error("x"))).toBe(false);
  });

  test("a user who set up TOTP gets no callback for an email code alone; registered methods unreadable → refused", async () => {
    vi.mocked(zitadel.getSession).mockResolvedValue({ session: session({ otpEmail: { verifiedAt: at } }) } as any);
    vi.mocked(zitadel.listAuthenticationMethodTypes).mockResolvedValue({
      authMethodTypes: [AuthenticationMethodType.TOTP, AuthenticationMethodType.OTP_EMAIL],
    } as any);
    const ref = { sessionId: "s", sessionToken: "t" };
    await expect(guardedCreateCallback({ serviceConfig: {} as any, authRequestId: "ar", session: ref })).rejects.toBeInstanceOf(PolicyRejectedError);
    vi.mocked(zitadel.listAuthenticationMethodTypes).mockRejectedValue(new Error("down"));
    await expect(guardedCreateCallback({ serviceConfig: {} as any, authRequestId: "ar", session: ref })).rejects.toBeInstanceOf(PolicyRejectedError);
    expect(zitadel.createCallback).not.toHaveBeenCalled();
  });
});
