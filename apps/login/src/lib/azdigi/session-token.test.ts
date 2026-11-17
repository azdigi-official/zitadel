import { beforeEach, describe, expect, test, vi } from "vitest";
import { isSessionToken, listSessionsByToken, requireSessionToken, SessionTokenRequiredError, verifySessionToken } from "./session-token";

const permissionDenied = () => Object.assign(new Error("permission denied"), { code: 7 });
const notFound = () => Object.assign(new Error("not found"), { code: 5 });

/** Zitadel as measured: a wrong token is refused; a MISSING token would return the session to the login's service user. */
function zitadel(sessions: Record<string, { token: string; user: string }>) {
  return vi.fn(async ({ sessionId, sessionToken }: { sessionId: string; sessionToken: string }) => {
    const session = sessions[sessionId];
    if (!session) throw notFound();
    if (sessionToken && sessionToken !== session.token) throw permissionDenied();
    return { session: { id: sessionId, user: session.user } };
  });
}

describe("a session token is required", () => {
  test.each([undefined, null, "", 0, {}, [], "x".repeat(201)])("%j is not a session token", (value) => {
    expect(isSessionToken(value)).toBe(false);
    expect(() => requireSessionToken(value)).toThrow(SessionTokenRequiredError);
  });

  test("the rejection looks like Zitadel's own: code 7, which callers treat as signed out", () => {
    try {
      requireSessionToken(undefined);
      throw new Error("not reached");
    } catch (error) {
      expect((error as { code?: number }).code).toBe(7);
    }
  });

  test("a non-empty string is accepted", () => {
    expect(isSessionToken("tok")).toBe(true);
    expect(() => requireSessionToken("tok")).not.toThrow();
  });
});

describe("verifying a token before a call Zitadel does not check", () => {
  const sessions = { victim: { token: "real", user: "victim-user" } };

  test("the right token returns the session", async () => {
    expect(await verifySessionToken(zitadel(sessions), "victim", "real")).toEqual({ id: "victim", user: "victim-user" });
  });

  test("a missing or empty token never reaches Zitadel, which would have returned the session", async () => {
    for (const token of [undefined, "", null]) {
      const getSession = zitadel(sessions);
      await expect(verifySessionToken(getSession, "victim", token)).rejects.toMatchObject({ code: 7 });
      expect(getSession).not.toHaveBeenCalled();
    }
  });

  test("a wrong token is refused by Zitadel and the refusal is passed on", async () => {
    await expect(verifySessionToken(zitadel(sessions), "victim", "guess")).rejects.toMatchObject({ code: 7 });
  });
});

describe("listing only the sessions this browser holds", () => {
  const sessions = { mine: { token: "t-mine", user: "me" }, victim: { token: "t-victim", user: "victim-user" }, other: { token: "t-other", user: "me-too" } };
  let getSession: ReturnType<typeof zitadel>;
  beforeEach(() => {
    getSession = zitadel(sessions);
  });

  test("sessions with their own token are returned", async () => {
    const out = await listSessionsByToken(getSession, ["mine", "other"], [{ id: "mine", token: "t-mine" }, { id: "other", token: "t-other" }]);
    expect(out).toEqual([{ id: "mine", user: "me" }, { id: "other", user: "me-too" }]);
  });

  test.each([
    ["no token field", { id: "victim" }],
    ["an empty token", { id: "victim", token: "" }],
    ["a wrong token", { id: "victim", token: "guess" }],
    ["a token that is not a string", { id: "victim", token: 12345 }],
  ])("a cookie naming someone else's session with %s gets nothing about it", async (_label, forged) => {
    const out = await listSessionsByToken(getSession, ["mine", "victim"], [{ id: "mine", token: "t-mine" }, forged]);
    expect(out).toEqual([{ id: "mine", user: "me" }]);
    expect(JSON.stringify(out)).not.toContain("victim-user");
  });

  test("an id without any cookie is never looked up", async () => {
    expect(await listSessionsByToken(getSession, ["victim"], [])).toEqual([]);
    expect(getSession).not.toHaveBeenCalled();
  });

  test("a session that is gone is left out; an outage is not swallowed", async () => {
    expect(await listSessionsByToken(getSession, ["gone", "mine"], [{ id: "gone", token: "t" }, { id: "mine", token: "t-mine" }])).toEqual([{ id: "mine", user: "me" }]);
    const down = vi.fn(async () => {
      throw Object.assign(new Error("unavailable"), { code: 14 });
    });
    await expect(listSessionsByToken(down, ["mine"], [{ id: "mine", token: "t-mine" }])).rejects.toMatchObject({ code: 14 });
  });

  test("a repeated id is read once", async () => {
    await listSessionsByToken(getSession, ["mine", "mine"], [{ id: "mine", token: "t-mine" }]);
    expect(getSession).toHaveBeenCalledTimes(1);
  });
});
