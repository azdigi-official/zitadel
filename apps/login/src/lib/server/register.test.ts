import { beforeEach, describe, expect, test, vi } from "vitest";
import * as orgLookup from "../azdigi/org-lookup";
import * as zitadel from "../zitadel";
import * as cookie from "./cookie";
import { registerUser } from "./register";

vi.mock("next/headers", () => ({ headers: vi.fn(async () => ({ get: () => null })), cookies: vi.fn(async () => ({ set: vi.fn() })) }));
vi.mock("next-intl/server", () => ({ getTranslations: vi.fn(async () => (key: string) => key) }));
vi.mock("../service-url", () => ({ getServiceConfig: vi.fn(() => ({ serviceConfig: { baseUrl: "http://api" } })) }));
vi.mock("../azdigi/org-lookup", () => ({ resolveOrgIdByName: vi.fn() }));
vi.mock("../fingerprint", () => ({ getOrSetFingerprintId: vi.fn(async () => "fp") }));
vi.mock("../client", () => ({ completeFlowOrGetUrl: vi.fn(async () => ({ redirect: "/signedin" })) }));
vi.mock("../verify-helper", () => ({ checkEmailVerification: vi.fn(), checkMFAFactors: vi.fn() }));
vi.mock("./cookie", () => ({ createSessionAndUpdateCookie: vi.fn(), createSessionForIdpAndUpdateCookie: vi.fn() }));
vi.mock("../zitadel", () => ({
  addHumanUser: vi.fn(),
  addIDPLink: vi.fn(),
  getLoginSettings: vi.fn(),
  getUserByID: vi.fn(),
  listAuthenticationMethodTypes: vi.fn(),
}));

const cfg = { baseUrl: "http://api" };
const base = { email: "new@example.test", firstName: "New", lastName: "User", organization: "org-from-client", requestId: "oidc_1" };

describe("registerUser (AZDIGI)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(orgLookup.resolveOrgIdByName).mockResolvedValue("customers-id");
    vi.mocked(zitadel.getLoginSettings).mockResolvedValue({ allowRegister: true } as any);
    vi.mocked(zitadel.addHumanUser).mockResolvedValue({ userId: "u1" } as any);
    vi.mocked(cookie.createSessionAndUpdateCookie).mockResolvedValue({
      session: { id: "s1", factors: { user: { id: "u1", loginName: "new@example.test", organizationId: "customers-id" } } },
    } as any);
  });

  test("ignores the organisation sent by the client and re-reads allowRegister fresh", async () => {
    await registerUser({ ...base, method: "otp" });
    expect(zitadel.getLoginSettings).toHaveBeenCalledWith({ serviceConfig: cfg, organization: "customers-id", fresh: true });
    expect(zitadel.addHumanUser).toHaveBeenCalledWith(expect.objectContaining({ organization: "customers-id", password: undefined }));
  });

  test("email-code registration goes to /verify with send=true (no passkey setup)", async () => {
    const res = await registerUser({ ...base, method: "otp", password: "should-be-dropped" });
    expect(res).toEqual({
      redirect: "/verify?loginName=new%40example.test&organization=customers-id&requestId=oidc_1&userId=u1&send=true",
    });
  });

  test("refuses when registration is off or the organisation cannot be resolved", async () => {
    vi.mocked(zitadel.getLoginSettings).mockResolvedValue({ allowRegister: false } as any);
    expect(await registerUser({ ...base, method: "otp" })).toEqual({ error: "disabled.description" });
    vi.mocked(orgLookup.resolveOrgIdByName).mockResolvedValue(undefined);
    expect(await registerUser({ ...base, method: "otp" })).toEqual({ error: "disabled.description" });
    expect(zitadel.addHumanUser).not.toHaveBeenCalled();
  });
});
