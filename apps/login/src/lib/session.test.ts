/**
 * isSessionValid / findValidSession after the AZDIGI change: the verdict comes from lib/azdigi/policy.ts with the
 * organisation's FRESH login settings and the OTP-first allow-list; the user's own auth methods no longer matter.
 * The policy matrix itself lives in lib/azdigi/policy.test.ts.
 */
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { SecondFactorType } from "@zitadel/proto/zitadel/settings/v2/login_settings_pb";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import * as orgLookup from "./azdigi/org-lookup";
import { checkSessionPolicy, findValidSession, isSessionValid } from "./session";
import * as zitadelModule from "./zitadel";

vi.mock("./zitadel", () => ({
  getLoginSettings: vi.fn(),
  getUserByID: vi.fn(),
  getSession: vi.fn(),
  // users here have no TOTP / security key / passkey unless a test says otherwise
  listAuthenticationMethodTypes: vi.fn(async () => ({ authMethodTypes: [] })),
}));
vi.mock("./azdigi/org-lookup", () => ({ isOtpFirstOrg: vi.fn() }));
vi.mock("./cookies", () => ({ getMostRecentCookieWithLoginname: vi.fn() }));

const serviceConfig = { baseUrl: "https://id.example" };
const originalEnv = process.env;

const ts = (offsetSeconds: number) => ({ seconds: BigInt(Math.floor(Date.now() / 1000) + offsetSeconds), nanos: 0 }) as any;

function session(factors: Record<string, unknown>, overrides: Record<string, unknown> = {}): any {
  return {
    id: "session-id",
    expirationDate: ts(3600),
    changeDate: ts(-10),
    factors: {
      user: { id: "user-1", organizationId: "org-1", loginName: "a@b.c", verifiedAt: ts(-60) },
      ...factors,
    },
    ...overrides,
  };
}

const customers = { forceMfa: false, forceMfaLocalOnly: false, secondFactors: [SecondFactorType.OTP_EMAIL], multiFactors: [] } as any;
const internal = { forceMfa: true, forceMfaLocalOnly: true, secondFactors: [SecondFactorType.OTP, SecondFactorType.U2F], multiFactors: [] } as any;

describe("isSessionValid", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env = { ...originalEnv };
    delete process.env.EMAIL_VERIFICATION;
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.mocked(zitadelModule.getLoginSettings).mockResolvedValue(customers);
    vi.mocked(orgLookup.isOtpFirstOrg).mockResolvedValue(true);
  });

  afterEach(() => {
    process.env = originalEnv;
    vi.restoreAllMocks();
  });

  test("returns false without a user factor and never calls the API", async () => {
    expect(await isSessionValid({ serviceConfig, session: { id: "x", factors: undefined } as any })).toBe(false);
    expect(zitadelModule.getLoginSettings).not.toHaveBeenCalled();
  });

  test("reads the login settings fresh for the user's organisation", async () => {
    await isSessionValid({ serviceConfig, session: session({ password: { verifiedAt: ts(-5) } }) });
    expect(zitadelModule.getLoginSettings).toHaveBeenCalledWith({ serviceConfig, organization: "org-1", fresh: true });
    expect(orgLookup.isOtpFirstOrg).toHaveBeenCalledWith(serviceConfig, "org-1");
  });

  test("customers: email code alone is valid, user-only is not", async () => {
    expect(await isSessionValid({ serviceConfig, session: session({ otpEmail: { verifiedAt: ts(-5) } }) })).toBe(true);
    expect(await isSessionValid({ serviceConfig, session: session({}) })).toBe(false);
  });

  test("email code alone is refused when the organisation is not allow-listed", async () => {
    vi.mocked(orgLookup.isOtpFirstOrg).mockResolvedValue(false);
    expect(await isSessionValid({ serviceConfig, session: session({ otpEmail: { verifiedAt: ts(-5) } }) })).toBe(false);
  });

  test("forceMfa organisation: password alone is refused, password + TOTP accepted, password + email code refused", async () => {
    vi.mocked(zitadelModule.getLoginSettings).mockResolvedValue(internal);
    vi.mocked(orgLookup.isOtpFirstOrg).mockResolvedValue(false);
    expect(await isSessionValid({ serviceConfig, session: session({ password: { verifiedAt: ts(-5) } }) })).toBe(false);
    expect(await isSessionValid({ serviceConfig, session: session({ password: { verifiedAt: ts(-5) }, totp: { verifiedAt: ts(-5) } }) })).toBe(true);
    expect(await isSessionValid({ serviceConfig, session: session({ password: { verifiedAt: ts(-5) }, otpEmail: { verifiedAt: ts(-5) } }) })).toBe(false);
  });

  test("a user-verified passkey satisfies a forceMfa organisation", async () => {
    vi.mocked(zitadelModule.getLoginSettings).mockResolvedValue(internal);
    expect(await isSessionValid({ serviceConfig, session: session({ webAuthN: { verifiedAt: ts(-5), userVerified: true } }) })).toBe(true);
  });

  test("expired sessions and missing settings are refused", async () => {
    expect(await isSessionValid({ serviceConfig, session: session({ password: { verifiedAt: ts(-5) } }, { expirationDate: ts(-1) }) })).toBe(false);
    vi.mocked(zitadelModule.getLoginSettings).mockResolvedValue(undefined);
    expect(await isSessionValid({ serviceConfig, session: session({ password: { verifiedAt: ts(-5) } }) })).toBe(false);
  });

  test("a session without expiration date is treated as not expired", async () => {
    expect(await isSessionValid({ serviceConfig, session: session({ password: { verifiedAt: ts(-5) } }, { expirationDate: undefined }) })).toBe(true);
  });

  test("checkSessionPolicy exposes the next step for the caller", async () => {
    expect(await checkSessionPolicy({ serviceConfig, session: session({}) })).toEqual({ ok: false, reason: "no-first-factor", next: "otpEmail" });
    vi.mocked(zitadelModule.getLoginSettings).mockResolvedValue(internal);
    // no second factor registered (e.g. removed by an administrator): set one up
    expect(await checkSessionPolicy({ serviceConfig, session: session({ password: { verifiedAt: ts(-5) } }) })).toEqual({
      ok: false,
      reason: "second-factor-missing",
      next: "mfaSetup",
    });
    vi.mocked(zitadelModule.listAuthenticationMethodTypes).mockResolvedValueOnce({
      authMethodTypes: [AuthenticationMethodType.PASSWORD, AuthenticationMethodType.TOTP],
    } as any);
    expect(await checkSessionPolicy({ serviceConfig, session: session({ password: { verifiedAt: ts(-5) } }) })).toEqual({
      ok: false,
      reason: "second-factor-missing",
      next: "mfa",
    });
  });

  describe("email verification", () => {
    test("refuses an unverified email when EMAIL_VERIFICATION is enabled", async () => {
      process.env.EMAIL_VERIFICATION = "true";
      vi.mocked(zitadelModule.getUserByID).mockResolvedValue({ user: { type: { case: "human", value: { email: { isVerified: false } } } } } as any);
      expect(await isSessionValid({ serviceConfig, session: session({ password: { verifiedAt: ts(-5) } }) })).toBe(false);
    });

    test("accepts a verified email and skips the lookup when disabled", async () => {
      process.env.EMAIL_VERIFICATION = "true";
      vi.mocked(zitadelModule.getUserByID).mockResolvedValue({ user: { type: { case: "human", value: { email: { isVerified: true } } } } } as any);
      expect(await isSessionValid({ serviceConfig, session: session({ password: { verifiedAt: ts(-5) } }) })).toBe(true);
      delete process.env.EMAIL_VERIFICATION;
      vi.mocked(zitadelModule.getUserByID).mockClear();
      expect(await isSessionValid({ serviceConfig, session: session({ password: { verifiedAt: ts(-5) } }) })).toBe(true);
      expect(zitadelModule.getUserByID).not.toHaveBeenCalled();
    });
  });
});

describe("findValidSession", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.mocked(zitadelModule.getLoginSettings).mockResolvedValue(customers);
    vi.mocked(orgLookup.isOtpFirstOrg).mockResolvedValue(true);
  });

  test("returns the most recent session that satisfies the policy, honouring hints", async () => {
    const stale = session({}, { id: "user-only", changeDate: ts(-1) });
    const good = session({ password: { verifiedAt: ts(-5) } }, { id: "good", changeDate: ts(-100) });
    expect((await findValidSession({ serviceConfig, sessions: [stale, good] }))?.id).toBe("good");
    expect(await findValidSession({ serviceConfig, sessions: [stale, good], authRequest: { hintUserId: "other" } as any })).toBeUndefined();
    expect((await findValidSession({ serviceConfig, sessions: [stale, good], authRequest: { loginHint: "a@b.c" } as any }))?.id).toBe("good");
  });
});
