import { afterEach, describe, expect, test, vi } from "vitest";
import { clearOtpFirstOrgCache, isOtpFirstOrg, otpFirstOrgNames, resolveOtpFirstOrgIds } from "./org-lookup";

const listOrganizations = vi.fn();
vi.mock("../service", () => ({ createServiceForHost: vi.fn(async () => ({ listOrganizations })) }));

describe("otpFirstOrgNames", () => {
  test("defaults to AZDIGI Customers and reads a comma separated env", () => {
    expect(otpFirstOrgNames({} as any)).toEqual(["AZDIGI Customers"]);
    expect(otpFirstOrgNames({ AZDIGI_OTP_FIRST_ORG_NAMES: " A , B ,, " } as any)).toEqual(["A", "B"]);
    expect(otpFirstOrgNames({ AZDIGI_OTP_FIRST_ORG_NAMES: "" } as any)).toEqual([]);
  });
});

describe("resolveOtpFirstOrgIds", () => {
  const cfg = { baseUrl: "http://api" };
  afterEach(() => {
    clearOtpFirstOrgCache();
    listOrganizations.mockReset();
    delete process.env.AZDIGI_OTP_FIRST_ORG_NAMES;
  });

  test("looks names up one by one and caches the ids", async () => {
    process.env.AZDIGI_OTP_FIRST_ORG_NAMES = "A,B";
    listOrganizations.mockResolvedValueOnce({ result: [{ id: "1" }] }).mockResolvedValueOnce({ result: [{ id: "2" }] });
    expect([...(await resolveOtpFirstOrgIds(cfg))].sort()).toEqual(["1", "2"]);
    expect(listOrganizations).toHaveBeenCalledTimes(2);
    expect(await isOtpFirstOrg(cfg, "1")).toBe(true);
    expect(await isOtpFirstOrg(cfg, "9")).toBe(false);
    expect(await isOtpFirstOrg(cfg, undefined)).toBe(false);
    expect(listOrganizations).toHaveBeenCalledTimes(2);
  });

  test("fails closed when the lookup errors and keeps the last known set", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    listOrganizations.mockRejectedValueOnce(new Error("denied"));
    expect((await resolveOtpFirstOrgIds(cfg, 0)).size).toBe(0);
    clearOtpFirstOrgCache();
    listOrganizations.mockResolvedValueOnce({ result: [{ id: "1" }] });
    await resolveOtpFirstOrgIds(cfg, 0);
    listOrganizations.mockRejectedValueOnce(new Error("denied"));
    expect([...(await resolveOtpFirstOrgIds(cfg, 10 * 60 * 1000))]).toEqual(["1"]);
    warn.mockRestore();
  });
});
