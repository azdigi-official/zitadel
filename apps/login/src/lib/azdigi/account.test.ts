import * as cookies from "@/lib/server/cookies";
import * as service from "@/lib/server/service";
import * as sessionLib from "@/lib/server/session";
import * as zitadel from "@/lib/server/zitadel";
import { AuthFactorState } from "@zitadel/proto/zitadel/user/v2/user_pb";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { beforeEach, describe, expect, test, vi } from "vitest";
import { loadAccount } from "./account";
import { accountSignInUrl, accountUrl } from "./account-url";
import * as issue from "./issue";

vi.mock("@/lib/server/cookies", () => ({ getAllSessions: vi.fn(), getSessionCookieById: vi.fn() }));
vi.mock("@/lib/server/service", () => ({ createServiceForHost: vi.fn() }));
vi.mock("@/lib/server/session", () => ({
  checkSessionPolicy: vi.fn(),
  isSessionValid: vi.fn(),
  loadMostRecentSession: vi.fn(),
}));
vi.mock("@/lib/server/zitadel", () => ({ getSession: vi.fn(), listAuthenticationMethodTypes: vi.fn() }));
vi.mock("./issue", () => ({ redirectForVerdict: vi.fn() }));

const cfg = { baseUrl: "http://api" };
const STAFF = "org-staff";
const sessionOf = (id: string, organizationId = STAFF) =>
  ({
    id: `session-${id}`,
    factors: { user: { id, loginName: `${id}@azdigi.com`, displayName: `User ${id}`, organizationId } },
  }) as any;

const listPasskeys = vi.fn();

/** the browser holds these session cookies (token "tok-<id>"); Zitadel answers each with its session, or not at all */
function browserHolds(...entries: { id: string; changeTs: number; session?: any; organization?: string }[]) {
  vi.mocked(cookies.getAllSessions).mockResolvedValue(
    entries.map((entry) => ({
      id: entry.id,
      token: `tok-${entry.id}`,
      changeTs: String(entry.changeTs),
      organization: entry.organization,
    })) as any,
  );
  vi.mocked(zitadel.getSession).mockImplementation(async ({ sessionId }: any) => {
    const entry = entries.find((candidate) => candidate.id === sessionId);
    if (!entry?.session) throw Object.assign(new Error("not found"), { code: 5 });
    return { session: entry.session } as any;
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(service.createServiceForHost).mockResolvedValue({ listPasskeys } as any);
  vi.mocked(sessionLib.isSessionValid).mockResolvedValue(true);
  vi.mocked(sessionLib.checkSessionPolicy).mockResolvedValue({ ok: true } as any);
  vi.mocked(cookies.getAllSessions).mockResolvedValue([]);
  vi.mocked(zitadel.listAuthenticationMethodTypes).mockResolvedValue({ authMethodTypes: [] } as any);
  listPasskeys.mockResolvedValue({ result: [] });
});

describe("account page: whose account", () => {
  test("it is the user of the browser's own session, and every read is for that user", async () => {
    browserHolds({ id: "session-alice", changeTs: 1, session: sessionOf("alice") });
    const out = await loadAccount({ serviceConfig: cfg, params: {} });
    expect(out).toMatchObject({
      kind: "ok",
      account: { userId: "alice", loginName: "alice@azdigi.com", organizationId: STAFF },
    });
    expect(zitadel.getSession).toHaveBeenCalledWith({
      serviceConfig: cfg,
      sessionId: "session-alice",
      sessionToken: "tok-session-alice",
    });
    expect(zitadel.listAuthenticationMethodTypes).toHaveBeenCalledWith({ serviceConfig: cfg, userId: "alice" });
    expect(listPasskeys).toHaveBeenCalledWith({ userId: "alice" });
  });

  test("a login name in the URL only selects among this browser's cookies: someone else's name finds no session", async () => {
    // the cookie lookup is by login name; a name this browser never signed in with has no cookie
    vi.mocked(sessionLib.loadMostRecentSession).mockResolvedValue(undefined);
    const out = await loadAccount({ serviceConfig: cfg, params: { loginName: "bob@azdigi.com" } });
    expect(out).toEqual({ kind: "signin" });
    expect(sessionLib.loadMostRecentSession).toHaveBeenCalledWith({
      serviceConfig: cfg,
      sessionParams: { loginName: "bob@azdigi.com", organization: undefined },
    });
    expect(zitadel.listAuthenticationMethodTypes).not.toHaveBeenCalled();
    expect(listPasskeys).not.toHaveBeenCalled();
  });

  test("a session id in the URL must be one of this browser's cookies and is read with that cookie's token", async () => {
    vi.mocked(cookies.getSessionCookieById).mockResolvedValueOnce(undefined);
    expect(await loadAccount({ serviceConfig: cfg, params: { sessionId: "someone-elses" } })).toEqual({ kind: "signin" });
    expect(zitadel.getSession).not.toHaveBeenCalled();

    vi.mocked(cookies.getSessionCookieById).mockResolvedValueOnce({ id: "session-alice", token: "tok" } as any);
    vi.mocked(zitadel.getSession).mockResolvedValueOnce({ session: sessionOf("alice") } as any);
    const out = await loadAccount({ serviceConfig: cfg, params: { sessionId: "session-alice" } });
    expect(out).toMatchObject({ kind: "ok", account: { userId: "alice" } });
    expect(zitadel.getSession).toHaveBeenCalledWith({ serviceConfig: cfg, sessionId: "session-alice", sessionToken: "tok" });
  });

  test("a cookie whose session Zitadel no longer accepts means signed out", async () => {
    vi.mocked(cookies.getSessionCookieById).mockResolvedValueOnce({ id: "gone", token: "tok" } as any);
    vi.mocked(zitadel.getSession).mockRejectedValueOnce(Object.assign(new Error("not found"), { code: 5 }));
    expect(await loadAccount({ serviceConfig: cfg, params: { sessionId: "gone" } })).toEqual({ kind: "signin" });
  });

  test("an organisation in the URL never shows another organisation's account", async () => {
    // the cookie claims the staff organisation, the session Zitadel returns belongs to the customers'
    browserHolds({ id: "session-alice", changeTs: 1, organization: STAFF, session: sessionOf("alice", "org-customers") });
    expect(await loadAccount({ serviceConfig: cfg, params: { organization: STAFF } })).toEqual({ kind: "signin" });
    expect(zitadel.listAuthenticationMethodTypes).not.toHaveBeenCalled();
    expect(sessionLib.checkSessionPolicy).not.toHaveBeenCalled();
  });

  test("a session a step short of the organisation's policy shows nothing and continues at the missing step", async () => {
    // a customer with a passkey who signed in with an email code: sending them to the start would loop
    const half = sessionOf("alice");
    browserHolds({ id: "session-alice", changeTs: 1, session: half });
    vi.mocked(sessionLib.isSessionValid).mockResolvedValue(false);
    const verdict = { ok: false, reason: "second-factor-missing", next: "mfa" };
    vi.mocked(sessionLib.checkSessionPolicy).mockResolvedValue(verdict as any);
    vi.mocked(issue.redirectForVerdict).mockReturnValue("/mfa?loginName=alice%40azdigi.com");
    expect(await loadAccount({ serviceConfig: cfg, params: {} })).toEqual({
      kind: "continue",
      url: "/mfa?loginName=alice%40azdigi.com",
    });
    expect(issue.redirectForVerdict).toHaveBeenCalledWith(verdict, half);
    expect(zitadel.listAuthenticationMethodTypes).not.toHaveBeenCalled();
    expect(listPasskeys).not.toHaveBeenCalled();
  });

  test("a sign-in that was started and abandoned does not hide an older, complete session", async () => {
    const complete = sessionOf("alice");
    const abandoned = sessionOf("bob");
    browserHolds(
      { id: "session-bob", changeTs: 20, session: abandoned },
      { id: "session-alice", changeTs: 10, session: complete },
    );
    vi.mocked(sessionLib.isSessionValid).mockImplementation(async ({ session }: any) => session === complete);
    const out = await loadAccount({ serviceConfig: cfg, params: {} });
    expect(out).toMatchObject({ kind: "ok", account: { userId: "alice" } });
    // the newest one was looked at first
    expect(vi.mocked(sessionLib.isSessionValid).mock.calls.map(([arg]: any) => arg.session.id)).toEqual([
      "session-bob",
      "session-alice",
    ]);
  });

  test("with several complete sessions the most recently used one is shown", async () => {
    browserHolds(
      { id: "session-alice", changeTs: 10, session: sessionOf("alice") },
      { id: "session-bob", changeTs: 20, session: sessionOf("bob") },
    );
    expect(await loadAccount({ serviceConfig: cfg, params: {} })).toMatchObject({ kind: "ok", account: { userId: "bob" } });
  });

  test("a cookie stuffed with sessions is not read past a small number", async () => {
    browserHolds(...Array.from({ length: 40 }, (_, i) => ({ id: `s${i}`, changeTs: i })));
    expect(await loadAccount({ serviceConfig: cfg, params: {} })).toEqual({ kind: "signin" });
    expect(vi.mocked(zitadel.getSession).mock.calls.length).toBe(5);
  });

  test("nobody signed in: sign in", async () => {
    expect(await loadAccount({ serviceConfig: cfg, params: {} })).toEqual({ kind: "signin" });
    expect(sessionLib.checkSessionPolicy).not.toHaveBeenCalled();
  });

  test("a session without a user is not an account", async () => {
    browserHolds({ id: "s", changeTs: 1, session: { id: "s", factors: {} } });
    expect(await loadAccount({ serviceConfig: cfg, params: {} })).toEqual({ kind: "signin" });
  });
});

describe("account page: what it shows", () => {
  beforeEach(() => {
    browserHolds({ id: "session-alice", changeTs: 1, session: sessionOf("alice") });
  });

  test("ready passkeys by name; a U2F key is a second factor, not a passkey", async () => {
    vi.mocked(zitadel.listAuthenticationMethodTypes).mockResolvedValue({
      authMethodTypes: [
        AuthenticationMethodType.PASSWORD,
        AuthenticationMethodType.PASSKEY,
        AuthenticationMethodType.U2F,
        AuthenticationMethodType.TOTP,
      ],
    } as any);
    listPasskeys.mockResolvedValue({
      result: [
        { id: "c1", name: "MacBook", state: AuthFactorState.READY },
        { id: "c2", name: "half done", state: AuthFactorState.NOT_READY },
        { id: "c3", name: "iPhone", state: AuthFactorState.READY },
      ],
    });
    const out = await loadAccount({ serviceConfig: cfg, params: {} });
    expect(out).toMatchObject({
      kind: "ok",
      account: { passkeys: ["MacBook", "iPhone"], hasPassword: true, secondFactors: ["totp", "u2f"] },
    });
    // nothing a later request could use to address a credential leaves this function
    expect(JSON.stringify(out)).not.toMatch(/c1|c2|c3/);
  });

  test("a customer with only email codes", async () => {
    vi.mocked(zitadel.listAuthenticationMethodTypes).mockResolvedValue({
      authMethodTypes: [AuthenticationMethodType.OTP_EMAIL],
    } as any);
    const out = await loadAccount({ serviceConfig: cfg, params: {} });
    expect(out).toMatchObject({ kind: "ok", account: { passkeys: [], hasPassword: false, secondFactors: ["otpEmail"] } });
  });

  test("an unreadable passkey list is unknown, never none", async () => {
    listPasskeys.mockRejectedValue(Object.assign(new Error("denied"), { code: 7 }));
    const out = await loadAccount({ serviceConfig: cfg, params: {} });
    expect(out).toMatchObject({ kind: "ok", account: { passkeys: null } });
  });
});

describe("account page: URLs", () => {
  test("the page URL carries only which session, never a user id", () => {
    expect(accountUrl({ loginName: "an@azdigi.com", organization: "7" })).toBe(
      "/account?loginName=an%40azdigi.com&organization=7",
    );
    expect(accountUrl({ sessionId: "s1" })).toBe("/account?sessionId=s1");
    expect(accountUrl({})).toBe("/account?");
  });

  test("signing in keeps the login name and organisation", () => {
    expect(accountSignInUrl({ loginName: "an@azdigi.com", organization: "7", sessionId: "s1" })).toBe(
      "/loginname?loginName=an%40azdigi.com&organization=7",
    );
  });
});
