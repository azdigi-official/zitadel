/**
 * The public server action: challenges are built on the server (never returnCode), OTP codes never come back to
 * the browser, a user-only session may only request an OTP when OTP-first applies, and send/verify are rate limited.
 */
import { create } from "@zitadel/client";
import { RequestChallengesSchema } from "@zitadel/proto/zitadel/session/v2/challenge_pb";
import { ChecksSchema } from "@zitadel/proto/zitadel/session/v2/session_service_pb";
import { beforeEach, describe, expect, test, vi } from "vitest";
import * as otpFirst from "../azdigi/otp-first";
import { resetLimiters } from "../azdigi/rate-limit";
import * as cookies from "../cookies";
import * as zitadel from "../zitadel";
import * as cookie from "./cookie";
import { buildServerChallenges } from "../azdigi/challenges";
import { updateOrCreateSession } from "./session";

const headerValues: Record<string, string> = {};
vi.mock("next/headers", () => ({ headers: vi.fn(async () => ({ get: (n: string) => headerValues[n.toLowerCase()] ?? null })) }));
vi.mock("next-intl/server", () => ({ getTranslations: vi.fn(async () => (key: string, args?: Record<string, unknown>) => (args ? `${key}:${JSON.stringify(args)}` : key)) }));
vi.mock("../service-url", () => ({ getServiceConfig: vi.fn(() => ({ serviceConfig: { baseUrl: "http://api" } })) }));
vi.mock("./host", () => ({ getPublicHost: vi.fn(() => "login.azdigi.com") }));
vi.mock("../client", () => ({ completeFlowOrGetUrl: vi.fn() }));
vi.mock("../cookies", () => ({
  getMostRecentSessionCookie: vi.fn(),
  getSessionCookieById: vi.fn(),
  getSessionCookieByLoginName: vi.fn(),
  removeSessionFromCookie: vi.fn(),
}));
vi.mock("./cookie", () => ({ createSessionAndUpdateCookie: vi.fn(), setSessionAndUpdateCookie: vi.fn() }));
vi.mock("../zitadel", () => ({
  deleteSession: vi.fn(),
  getLoginSettings: vi.fn(),
  getSecuritySettings: vi.fn(),
  getSession: vi.fn(),
  getUserByID: vi.fn(),
  humanMFAInitSkipped: vi.fn(),
  listAuthenticationMethodTypes: vi.fn(),
  listUsers: vi.fn(),
}));
vi.mock("../azdigi/otp-first", () => ({ decideOtpFirstForUser: vi.fn() }));

const at = { seconds: BigInt(Math.floor(Date.now() / 1000) - 10), nanos: 0 };
const recentCookie = { id: "s1", token: "tok", loginName: "a@b.c", organization: "o1", creationTs: "", expirationTs: "", changeTs: "" } as any;

function liveSession(factors: Record<string, unknown> = {}) {
  return { id: "s1", factors: { user: { id: "u1", organizationId: "o1", loginName: "a@b.c", verifiedAt: at }, ...factors } } as any;
}

describe("buildServerChallenges", () => {
  test("rebuilds the email challenge with our link template and drops returnCode", () => {
    process.env.NEXT_PUBLIC_BASE_PATH = "/ui/v2/login";
    const requested = create(RequestChallengesSchema, { otpEmail: { deliveryType: { case: "returnCode", value: {} } }, otpSms: { returnCode: true } });
    const built = buildServerChallenges(requested, "login.azdigi.com", "oidc_1")!;
    expect(built.otpEmail?.deliveryType.case).toBe("sendCode");
    expect((built.otpEmail?.deliveryType as any).value.urlTemplate).toBe(
      "https://login.azdigi.com/ui/v2/login/otp/email?code={{.Code}}&userId={{.UserID}}&sessionId={{.SessionID}}&requestId=oidc_1",
    );
    expect(built.otpSms?.returnCode).toBe(false);
  });

  test("keeps only the user verification requirement of a WebAuthn challenge and sets the domain", () => {
    const requested = create(RequestChallengesSchema, { webAuthN: { domain: "evil.example", userVerificationRequirement: 2 } });
    const built = buildServerChallenges(requested, "login.localhost:8090")!;
    expect(built.webAuthN?.domain).toBe("login.localhost");
    expect(built.webAuthN?.userVerificationRequirement).toBe(2);
    expect(built.otpEmail).toBeUndefined();
    expect(buildServerChallenges(undefined, "x")).toBeUndefined();
  });
});

describe("updateOrCreateSession", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetLimiters();
    for (const k of Object.keys(headerValues)) delete headerValues[k];
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.mocked(cookies.getSessionCookieByLoginName).mockResolvedValue(recentCookie);
    vi.mocked(zitadel.getLoginSettings).mockResolvedValue({ secondFactorCheckLifetime: { seconds: BigInt(3600), nanos: 0 } } as any);
    vi.mocked(zitadel.getUserByID).mockResolvedValue({ user: { state: 1, type: { case: "human", value: { email: { isVerified: true } } } } } as any);
  });

  test("eligible user-only session: challenge is sent server-built and the OTP code is not in the response", async () => {
    vi.mocked(zitadel.getSession).mockResolvedValue({ session: liveSession() } as any);
    vi.mocked(otpFirst.decideOtpFirstForUser).mockResolvedValue({ eligible: true, altPassword: false });
    vi.mocked(cookie.setSessionAndUpdateCookie).mockResolvedValue({
      ...liveSession(),
      challenges: { otpEmail: "123456", otpSms: "654321", webAuthN: undefined },
    } as any);

    const res = await updateOrCreateSession({
      loginName: "a@b.c",
      organization: "o1",
      requestId: "oidc_1",
      challenges: create(RequestChallengesSchema, { otpEmail: { deliveryType: { case: "returnCode", value: {} } } }),
    });

    expect("error" in res).toBe(false);
    const call = vi.mocked(cookie.setSessionAndUpdateCookie).mock.calls[0][0];
    expect(call.challenges?.otpEmail?.deliveryType.case).toBe("sendCode");
    expect((res as any).challenges).toBeUndefined();
    expect(JSON.stringify(res, (_k, v) => (typeof v === "bigint" ? v.toString() : v))).not.toContain("123456");
  });

  test("user-only session of a non-eligible user is refused and sent to the password page", async () => {
    vi.mocked(zitadel.getSession).mockResolvedValue({ session: liveSession() } as any);
    vi.mocked(otpFirst.decideOtpFirstForUser).mockResolvedValue({ eligible: false, reason: "forceMfa" });

    const res = await updateOrCreateSession({ loginName: "a@b.c", organization: "o1", requestId: "oidc_1", challenges: create(RequestChallengesSchema, { otpEmail: {} }) });

    expect(res).toEqual({ error: "otpFirstNotAllowed", redirect: "/password?loginName=a%40b.c&organization=o1&requestId=oidc_1" });
    expect(cookie.setSessionAndUpdateCookie).not.toHaveBeenCalled();
  });

  test("a session with a verified password may request an email code as a second factor without eligibility", async () => {
    vi.mocked(zitadel.getSession).mockResolvedValue({ session: liveSession({ password: { verifiedAt: at } }) } as any);
    vi.mocked(cookie.setSessionAndUpdateCookie).mockResolvedValue({ ...liveSession({ password: { verifiedAt: at } }), challenges: undefined } as any);
    const res = await updateOrCreateSession({ loginName: "a@b.c", challenges: create(RequestChallengesSchema, { otpEmail: {} }) });
    expect("error" in res).toBe(false);
    expect(otpFirst.decideOtpFirstForUser).not.toHaveBeenCalled();
  });

  test("code sends are limited to 3 per login name in 10 minutes", async () => {
    vi.mocked(zitadel.getSession).mockResolvedValue({ session: liveSession({ password: { verifiedAt: at } }) } as any);
    vi.mocked(cookie.setSessionAndUpdateCookie).mockResolvedValue({ ...liveSession(), challenges: undefined } as any);
    const send = () => updateOrCreateSession({ loginName: "a@b.c", challenges: create(RequestChallengesSchema, { otpEmail: {} }) });
    for (let i = 0; i < 3; i++) expect("error" in (await send())).toBe(false);
    const fourth = await send();
    expect(fourth).toEqual({ error: 'tooManyCodeRequests:{"minutes":10}' });
    expect(cookie.setSessionAndUpdateCookie).toHaveBeenCalledTimes(3);
  });

  test("code sends are limited to 20 per client IP", async () => {
    headerValues["cf-connecting-ip"] = "203.0.113.9";
    vi.mocked(zitadel.getSession).mockResolvedValue({ session: liveSession({ password: { verifiedAt: at } }) } as any);
    vi.mocked(cookie.setSessionAndUpdateCookie).mockResolvedValue({ ...liveSession(), challenges: undefined } as any);
    for (let i = 0; i < 20; i++) {
      vi.mocked(cookies.getSessionCookieByLoginName).mockResolvedValue({ ...recentCookie, loginName: `u${i}@b.c` });
      vi.mocked(zitadel.getSession).mockResolvedValue({ session: liveSession({ password: { verifiedAt: at }, user: { id: "u", organizationId: "o1", loginName: `u${i}@b.c`, verifiedAt: at } }) } as any);
      expect("error" in (await updateOrCreateSession({ loginName: `u${i}@b.c`, challenges: create(RequestChallengesSchema, { otpEmail: {} }) }))).toBe(false);
    }
    const res = await updateOrCreateSession({ loginName: "z@b.c", challenges: create(RequestChallengesSchema, { otpEmail: {} }) });
    expect((res as any).error).toMatch(/^tooManyCodeRequests/);
  });

  test("code attempts: wrong codes are mapped with the attempts left, the 3rd attempt in 10 minutes is not sent to Zitadel (it would lock the user)", async () => {
    vi.mocked(zitadel.getSession).mockResolvedValue({ session: liveSession() } as any);
    vi.mocked(otpFirst.decideOtpFirstForUser).mockResolvedValue({ eligible: true, altPassword: false });
    vi.mocked(cookie.setSessionAndUpdateCookie).mockRejectedValue({ rawMessage: "Code is invalid (CODE-woT0xc)" });
    const attempt = () => updateOrCreateSession({ loginName: "a@b.c", checks: create(ChecksSchema, { otpEmail: { code: "000000" } }) });
    expect(await attempt()).toEqual({ error: 'codeInvalid:{"remaining":1}', failedAttempts: undefined });
    expect(await attempt()).toEqual({ error: 'codeInvalid:{"remaining":0}', failedAttempts: undefined });
    expect(await attempt()).toEqual({ error: 'tooManyCodeAttempts:{"minutes":10}' });
    expect(cookie.setSessionAndUpdateCookie).toHaveBeenCalledTimes(2);
  });

  test("a locked user is reported as locked", async () => {
    vi.mocked(zitadel.getSession).mockResolvedValue({ session: liveSession({ password: { verifiedAt: at } }) } as any);
    vi.mocked(cookie.setSessionAndUpdateCookie).mockRejectedValue({ rawMessage: "User is locked (COMMAND-S6h4R)" });
    const res = await updateOrCreateSession({ loginName: "a@b.c", checks: create(ChecksSchema, { otpEmail: { code: "000000" } }) });
    expect(res).toEqual({ error: "userLocked", locked: true });
  });

  test("a successful code clears the attempt window", async () => {
    vi.mocked(zitadel.getSession).mockResolvedValue({ session: liveSession() } as any);
    vi.mocked(otpFirst.decideOtpFirstForUser).mockResolvedValue({ eligible: true, altPassword: false });
    vi.mocked(cookie.setSessionAndUpdateCookie).mockRejectedValueOnce({ rawMessage: "Code is invalid (CODE-woT0xc)" }).mockResolvedValueOnce({ ...liveSession({ otpEmail: { verifiedAt: at } }), challenges: undefined } as any).mockRejectedValue({ rawMessage: "Code is invalid (CODE-woT0xc)" });
    const attempt = () => updateOrCreateSession({ loginName: "a@b.c", checks: create(ChecksSchema, { otpEmail: { code: "000000" } }) });
    await attempt();
    expect("sessionId" in (await attempt())).toBe(true);
    expect(await attempt()).toEqual({ error: 'codeInvalid:{"remaining":1}', failedAttempts: undefined });
  });

  test("without a cookie the session is created with a user check only, challenges come afterwards", async () => {
    vi.mocked(cookies.getSessionCookieByLoginName).mockResolvedValue(undefined as any);
    vi.mocked(cookie.createSessionAndUpdateCookie).mockResolvedValue({ session: liveSession(), sessionCookie: recentCookie } as any);
    vi.mocked(zitadel.getSession).mockResolvedValue({ session: liveSession() } as any);
    vi.mocked(otpFirst.decideOtpFirstForUser).mockResolvedValue({ eligible: true, altPassword: true });
    vi.mocked(cookie.setSessionAndUpdateCookie).mockResolvedValue({ ...liveSession(), challenges: undefined } as any);
    await updateOrCreateSession({ loginName: "a@b.c", challenges: create(RequestChallengesSchema, { otpEmail: {} }) });
    const created = vi.mocked(cookie.createSessionAndUpdateCookie).mock.calls[0][0];
    expect(created.challenges).toBeUndefined();
    expect(created.checks.user?.search.case).toBe("loginName");
    expect(vi.mocked(cookie.setSessionAndUpdateCookie).mock.calls[0][0].challenges?.otpEmail).toBeDefined();
  });

  test("the WebAuthn challenge is still returned to the browser", async () => {
    vi.mocked(cookie.setSessionAndUpdateCookie).mockResolvedValue({ ...liveSession(), challenges: { webAuthN: { publicKeyCredentialRequestOptions: { publicKey: {} } } } } as any);
    const res = await updateOrCreateSession({ loginName: "a@b.c", challenges: create(RequestChallengesSchema, { webAuthN: { domain: "", userVerificationRequirement: 1 } }) });
    expect((res as any).challenges.webAuthN).toBeDefined();
    expect(zitadel.getSession).not.toHaveBeenCalled();
  });
});
