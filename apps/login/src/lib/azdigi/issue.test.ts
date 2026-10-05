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
}));
vi.mock("./org-lookup", () => ({ isOtpFirstOrg: vi.fn() }));

const cfg = { baseUrl: "http://api" };
const ref = { sessionId: "s1", sessionToken: "tok" };
const at = { seconds: BigInt(Math.floor(Date.now() / 1000) - 10), nanos: 0 };
const future = { seconds: BigInt(Math.floor(Date.now() / 1000) + 3600), nanos: 0 };

function session(factors: any) {
  return { id: "s1", expirationDate: future, factors: { user: { id: "u1", organizationId: "o1", loginName: "a@b.c", verifiedAt: at }, ...factors } };
}

describe("guarded token issuance", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.mocked(zitadel.getLoginSettings).mockResolvedValue({ forceMfa: false, secondFactors: [3], multiFactors: [] } as any);
    vi.mocked(orgLookup.isOtpFirstOrg).mockResolvedValue(true);
    vi.mocked(zitadel.listAuthenticationMethodTypes).mockResolvedValue({ authMethodTypes: [] } as any);
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
    expect(zitadel.getLoginSettings).toHaveBeenCalledWith({ serviceConfig: cfg, organization: "o1", fresh: true });
    const req = vi.mocked(zitadel.createCallback).mock.calls[0][0].req as any;
    expect(req.authRequestId).toBe("a");
    expect(req.callbackKind.value.sessionId).toBe("s1");
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
      "/otp/email?loginName=a%40b.c&organization=o1&requestId=oidc_1",
    );
    expect(redirectForVerdict({ ok: false, reason: "second-factor-missing", next: "mfa" }, s)).toBe("/mfa?loginName=a%40b.c&organization=o1");
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
