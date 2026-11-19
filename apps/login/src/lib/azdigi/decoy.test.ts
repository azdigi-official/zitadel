import * as zitadel from "@/lib/server/zitadel";
import { afterEach, describe, expect, test, vi } from "vitest";
import { decoyLoginName, decoyOrganization, decoyOtpRedirect, withMinimumDurationWhen } from "./decoy";
import * as orgLookup from "./org-lookup";

vi.mock("./org-lookup", () => ({ isOtpFirstOrg: vi.fn(), resolveOtpFirstOrgIds: vi.fn() }));
vi.mock("@/lib/server/zitadel", () => ({ getLoginSettings: vi.fn() }));

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
    vi.mocked(orgLookup.resolveOtpFirstOrgIds)
      .mockResolvedValueOnce(new Set(["100"]))
      .mockResolvedValueOnce(new Set());
    expect(await decoyOrganization(cfg, undefined)).toBe("100");
    expect(await decoyOrganization(cfg, undefined)).toBeUndefined();
  });

  test("redirect: the same /otp/email parameters as a real customer (alternatives from the organisation policy)", async () => {
    vi.mocked(orgLookup.resolveOtpFirstOrgIds).mockResolvedValue(new Set(["100"]));
    vi.mocked(zitadel.getLoginSettings).mockResolvedValue({
      allowLocalAuthentication: true,
      allowUsernamePassword: true,
      passkeysType: 1,
    } as any);
    const r = await decoyOtpRedirect(cfg, { loginName: "Ghost@Example.test", contextOrg: undefined, requestId: "oidc_1" });
    expect(r).toEqual({
      redirect:
        "/otp/email?loginName=ghost%40example.test&altPassword=true&altPasskey=true&organization=100&requestId=oidc_1",
    });
    vi.mocked(orgLookup.isOtpFirstOrg).mockResolvedValue(false);
    expect(await decoyOtpRedirect(cfg, { loginName: "x@y.z", contextOrg: "200" })).toBeUndefined();
  });
});

describe("withMinimumDurationWhen (password refusals)", () => {
  test("a refusal answered at once still takes the minimum time; a success does not wait", async () => {
    vi.useFakeTimers();
    try {
      let refused = false;
      const refusal = withMinimumDurationWhen(
        async () => ({ error: "x" }),
        (r) => "error" in r,
        1500,
        0,
      ).then(() => {
        refused = true;
      });
      await vi.advanceTimersByTimeAsync(1499);
      expect(refused).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      await refusal;
      expect(refused).toBe(true);

      let succeeded = false;
      const success = withMinimumDurationWhen(
        async () => ({ redirect: "/account" }),
        (r) => "error" in r,
        1500,
        0,
      ).then(() => {
        succeeded = true;
      });
      await vi.advanceTimersByTimeAsync(0);
      await success;
      expect(succeeded).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  test("a failure that throws waits too, then throws", async () => {
    vi.useFakeTimers();
    try {
      const failing = withMinimumDurationWhen(
        async () => {
          throw new Error("boom");
        },
        () => true,
        1000,
        0,
      ).catch((e: Error) => e.message);
      await vi.advanceTimersByTimeAsync(1000);
      expect(await failing).toBe("boom");
    } finally {
      vi.useRealTimers();
    }
  });
});
