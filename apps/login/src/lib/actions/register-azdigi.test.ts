import * as orgLookup from "@/lib/azdigi/org-lookup";
import { sendVerificationOnce } from "@/lib/azdigi/verification-mail";
import * as sessionCookie from "@/lib/server/session-cookie";
import * as zitadel from "@/lib/server/zitadel";
import { beforeEach, describe, expect, test, vi } from "vitest";
import { registerUser, registerUserAndLinkToIDP } from "./register";

vi.mock("@/lib/azdigi/verification-mail", () => ({ sendVerificationOnce: vi.fn(async () => true) }));
vi.mock("next/headers", () => ({
  headers: vi.fn(async () => new Headers()),
  cookies: vi.fn(async () => ({ set: vi.fn() })),
}));
vi.mock("next-intl/server", () => ({ getTranslations: vi.fn(async () => (key: string) => key) }));
vi.mock("@/lib/server/service-url", () => ({
  getServiceConfig: vi.fn(() => ({ serviceConfig: { baseUrl: "http://api" } })),
}));
vi.mock("@/lib/azdigi/org-lookup", () => ({ registrationOrgId: vi.fn() }));
vi.mock("@/lib/server/verification-check", () => ({ setUserVerificationCheckCookie: vi.fn() }));
vi.mock("@/lib/server/fingerprint", () => ({ getBindingIdCookie: vi.fn(async () => ({ value: "binding-id" })) }));
vi.mock("@/lib/server/idp-flow-proof", () => ({ isIdpFlowProofValid: vi.fn(() => true) }));
vi.mock("@/lib/actions/flow", () => ({ completeFlowOrGetUrl: vi.fn(async () => ({ redirect: "/signedin" })) }));
vi.mock("@/lib/server/verify-helper", () => ({ checkEmailVerification: vi.fn(), checkMFAFactors: vi.fn() }));
vi.mock("@/lib/server/session-cookie", () => ({
  createSessionAndUpdateCookie: vi.fn(),
  createSessionForIdpAndUpdateCookie: vi.fn(),
}));
vi.mock("@/lib/server/zitadel", () => ({
  addHumanUser: vi.fn(),
  addIDPLink: vi.fn(),
  getLoginSettings: vi.fn(),
  getUserByID: vi.fn(),
  listAuthenticationMethodTypes: vi.fn(),
  retrieveIDPIntent: vi.fn(),
}));

const cfg = { baseUrl: "http://api" };
const base = {
  email: "new@example.test",
  firstName: "New",
  lastName: "User",
  organization: "org-from-client",
  requestId: "oidc_1",
};

describe("registerUser (AZDIGI)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(orgLookup.registrationOrgId).mockResolvedValue("customers-id");
    vi.mocked(zitadel.getLoginSettings).mockResolvedValue({ allowRegister: true, allowLocalAuthentication: true } as any);
    vi.mocked(zitadel.addHumanUser).mockResolvedValue({ userId: "u1" } as any);
    vi.mocked(sessionCookie.createSessionAndUpdateCookie).mockResolvedValue({
      session: { id: "s1", factors: { user: { id: "u1", loginName: "new@example.test", organizationId: "customers-id" } } },
    } as any);
  });

  test("ignores the organisation sent by the client and re-reads allowRegister fresh", async () => {
    await registerUser({ ...base, method: "otp" });
    expect(zitadel.getLoginSettings).toHaveBeenCalledWith({ serviceConfig: cfg, organization: "customers-id", fresh: true });
    expect(zitadel.addHumanUser).toHaveBeenCalledWith(
      expect.objectContaining({ organization: "customers-id", password: undefined }),
    );
  });

  test("email-code registration sends the code and goes to /verify (no passkey setup)", async () => {
    const res = await registerUser({ ...base, method: "otp", password: "should-be-dropped" });
    expect(res).toEqual({
      redirect: "/verify?loginName=new%40example.test&organization=customers-id&requestId=oidc_1&userId=u1&codeSent=true",
    });
    expect(sendVerificationOnce).toHaveBeenCalledWith({ userId: "u1", isInvite: false, requestId: "oidc_1" });
  });

  test("refuses when registration is off or the organisation cannot be resolved", async () => {
    vi.mocked(zitadel.getLoginSettings).mockResolvedValue({ allowRegister: false } as any);
    expect(await registerUser({ ...base, method: "otp" })).toEqual({ error: "errors.registerNotAllowed" });
    vi.mocked(orgLookup.registrationOrgId).mockResolvedValue(undefined);
    expect(await registerUser({ ...base, method: "otp" })).toEqual({ error: "errors.registerNotAllowed" });
    expect(zitadel.addHumanUser).not.toHaveBeenCalled();
  });

  test("a pasted email loses its outer whitespace before the account is created", async () => {
    await registerUser({ ...base, email: "  new@example.test\t", method: "otp" });
    expect(zitadel.addHumanUser).toHaveBeenCalledWith(expect.objectContaining({ email: "new@example.test" }));
  });

  test.each(["new @example.test", "new@exa mple.test", "new\u00a0@example.test"])(
    "refuses an email with inner whitespace: %j",
    async (email) => {
      expect(await registerUser({ ...base, email, method: "otp" })).toEqual({ error: "errors.whitespace" });
      expect(
        await registerUserAndLinkToIDP({ ...base, email, idpId: "i", idpUserId: "u", idpUserName: "n" } as any),
      ).toEqual({
        error: "errors.whitespace",
      });
      expect(orgLookup.registrationOrgId).not.toHaveBeenCalled();
      expect(zitadel.addHumanUser).not.toHaveBeenCalled();
    },
  );
});
