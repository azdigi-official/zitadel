import { describe, expect, test, vi } from "vitest";
import * as zitadel from "../zitadel";
import { orgIdsInScopes, requiredOrgIds, sessionInScopedOrg } from "./org-scope";

vi.mock("../zitadel", () => ({ getOrgsByDomain: vi.fn() }));

const cfg = { baseUrl: "http://api" };
const sessionIn = (organizationId: string) => ({ factors: { user: { organizationId } } }) as any;

describe("organisation scopes", () => {
  test("ids are read from urn:zitadel:iam:org:id scopes only", () => {
    expect(orgIdsInScopes(["openid", "urn:zitadel:iam:org:id:123", "urn:zitadel:iam:org:id:x"])).toEqual(["123"]);
    expect(orgIdsInScopes(undefined)).toEqual([]);
  });

  test("no organisation scope admits everyone; an id scope admits that organisation", async () => {
    expect(await requiredOrgIds(cfg, ["openid", "email"])).toBeNull();
    expect(Array.from((await requiredOrgIds(cfg, ["openid", "urn:zitadel:iam:org:id:42"])) ?? [])).toEqual(["42"]);
  });

  test("a primary domain resolves to its organisation; an unknown or ambiguous one admits nobody", async () => {
    vi.mocked(zitadel.getOrgsByDomain).mockResolvedValueOnce({ result: [{ id: "7" }] } as any);
    expect(Array.from((await requiredOrgIds(cfg, ["urn:zitadel:iam:org:domain:primary:staff.example"])) ?? [])).toEqual(["7"]);
    vi.mocked(zitadel.getOrgsByDomain).mockResolvedValueOnce({ result: [] } as any);
    expect((await requiredOrgIds(cfg, ["urn:zitadel:iam:org:domain:primary:nope.example"]))?.size).toBe(0);
    vi.mocked(zitadel.getOrgsByDomain).mockRejectedValueOnce(new Error("down"));
    expect((await requiredOrgIds(cfg, ["urn:zitadel:iam:org:domain:primary:x.example"]))?.size).toBe(0);
  });

  test("SSO selection skips sessions of another organisation when the request names one", () => {
    expect(sessionInScopedOrg(sessionIn("1"), ["openid"])).toBe(true);
    expect(sessionInScopedOrg(sessionIn("1"), ["urn:zitadel:iam:org:id:1"])).toBe(true);
    expect(sessionInScopedOrg(sessionIn("2"), ["urn:zitadel:iam:org:id:1"])).toBe(false);
  });
});
