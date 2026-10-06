import { afterEach, describe, expect, test, vi } from "vitest";
import { decoyLoginName, decoyOrganization, decoyOtpRedirect } from "./decoy";
import * as zitadel from "../zitadel";
import * as orgLookup from "./org-lookup";

vi.mock("./org-lookup", () => ({ isOtpFirstOrg: vi.fn(), resolveOtpFirstOrgIds: vi.fn() }));
vi.mock("../zitadel", () => ({ getLoginSettings: vi.fn() }));

const cfg = { baseUrl: "http://api" };

describe("decoy for unknown names in a customer context", () => {
  afterEach(() => vi.resetAllMocks());

  test("the shown name is normalised like a real preferred login name", () => {
    expect(decoyLoginName("  Alice@Example.TEST ")).toBe("alice@example.test");
  });

  test("organisation: the context one when it is OTP-first, the single OTP-first one without context, else none", async () => {
    vi.mocked(orgLookup.isOtpFirstOrg).mockResolvedValueOnce(true).mockResolvedValueOnce(false);
    expect(await decoyOrganization(cfg, "100")).toBe("100");
    expect(await decoyOrganization(cfg, "200")).toBeUndefined();
    vi.mocked(orgLookup.resolveOtpFirstOrgIds).mockResolvedValueOnce(new Set(["100"])).mockResolvedValueOnce(new Set());
    expect(await decoyOrganization(cfg, undefined)).toBe("100");
    expect(await decoyOrganization(cfg, undefined)).toBeUndefined();
  });

  test("redirect: the same /otp/email parameters as a real customer (alternatives from the organisation policy)", async () => {
    vi.mocked(orgLookup.resolveOtpFirstOrgIds).mockResolvedValue(new Set(["100"]));
    vi.mocked(zitadel.getLoginSettings).mockResolvedValue({ allowLocalAuthentication: true, allowUsernamePassword: true, passkeysType: 1 } as any);
    const r = await decoyOtpRedirect(cfg, { loginName: "Ghost@Example.test", contextOrg: undefined, requestId: "oidc_1" });
    expect(r).toEqual({ redirect: "/otp/email?loginName=ghost%40example.test&altPassword=true&altPasskey=true&organization=100&requestId=oidc_1" });
    vi.mocked(orgLookup.isOtpFirstOrg).mockResolvedValue(false);
    expect(await decoyOtpRedirect(cfg, { loginName: "x@y.z", contextOrg: "200" })).toBeUndefined();
  });
});
