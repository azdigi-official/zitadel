// The Zitadel session wrappers of the login (lib/zitadel.ts) against a service that behaves like Zitadel v4.11 does
// for the login's service user: GetSession without a token returns the session, SetSession and DeleteSession accept
// any token. The wrappers must make all of that unreachable from a cookie that names someone else's session.
import { beforeEach, describe, expect, test, vi } from "vitest";
import * as cookies from "../cookies";
import * as service from "../service";
import { deleteSession, getSession, listSessions, setSession } from "../zitadel";

vi.mock("../service", () => ({ createServiceForHost: vi.fn() }));
vi.mock("../cookies", () => ({ getAllSessions: vi.fn() }));

const cfg = { baseUrl: "http://api" };
const REAL = "real-token";
const api = {
  getSession: vi.fn(async ({ sessionToken }: { sessionId: string; sessionToken?: string }) => {
    if (sessionToken && sessionToken !== REAL) throw Object.assign(new Error("permission denied"), { code: 7 });
    return { session: { id: "victim", factors: { user: { id: "victim-user" } } } };
  }),
  setSession: vi.fn(async () => ({ sessionToken: "brand-new-valid-token" })),
  deleteSession: vi.fn(async () => ({})),
  listSessions: vi.fn(async () => ({ sessions: [{ id: "victim", factors: { user: { id: "victim-user" } } }] })),
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(service.createServiceForHost).mockResolvedValue(api as any);
});

const forgedTokens: [string, any][] = [["a missing token", undefined], ["an empty token", ""], ["a wrong token", "guess"]];

describe("session wrappers refuse a session id that comes without its token", () => {
  test.each(forgedTokens)("getSession with %s returns nothing", async (_label, token) => {
    await expect(getSession({ serviceConfig: cfg, sessionId: "victim", sessionToken: token })).rejects.toMatchObject({ code: 7 });
  });

  test.each(forgedTokens)("setSession with %s never updates, so no new token is handed out", async (_label, token) => {
    await expect(setSession({ serviceConfig: cfg, sessionId: "victim", sessionToken: token, challenges: undefined, lifetime: {} as any })).rejects.toMatchObject({ code: 7 });
    expect(api.setSession).not.toHaveBeenCalled();
  });

  test.each(forgedTokens)("deleteSession with %s never ends the session", async (_label, token) => {
    await expect(deleteSession({ serviceConfig: cfg, sessionId: "victim", sessionToken: token })).rejects.toMatchObject({ code: 7 });
    expect(api.deleteSession).not.toHaveBeenCalled();
  });

  test("listSessions never asks Zitadel to list by id; a forged cookie yields no session", async () => {
    for (const cookie of [{ id: "victim" }, { id: "victim", token: "" }, { id: "victim", token: "guess" }]) {
      vi.mocked(cookies.getAllSessions).mockResolvedValue([cookie] as any);
      expect(await listSessions({ serviceConfig: cfg, ids: ["victim"] })).toEqual({ sessions: [] });
    }
    expect(api.listSessions).not.toHaveBeenCalled();
  });
});

describe("with the session's own token everything still works", () => {
  test("getSession, setSession (verified first), deleteSession (verified first), listSessions", async () => {
    expect((await getSession({ serviceConfig: cfg, sessionId: "victim", sessionToken: REAL })).session?.id).toBe("victim");

    await setSession({ serviceConfig: cfg, sessionId: "victim", sessionToken: REAL, challenges: undefined, lifetime: {} as any });
    expect(api.setSession).toHaveBeenCalledTimes(1);
    expect(api.getSession.mock.invocationCallOrder.at(-1)!).toBeLessThan(api.setSession.mock.invocationCallOrder[0]!);

    await deleteSession({ serviceConfig: cfg, sessionId: "victim", sessionToken: REAL });
    expect(api.deleteSession).toHaveBeenCalledTimes(1);

    vi.mocked(cookies.getAllSessions).mockResolvedValue([{ id: "victim", token: REAL }] as any);
    expect((await listSessions({ serviceConfig: cfg, ids: ["victim"] })).sessions).toHaveLength(1);
  });
});
