/**
 * isSessionValid / findValidSession after the AZDIGI change: the verdict comes from lib/azdigi/policy.ts with the
 * organisation's FRESH login settings and the OTP-first allow-list. Upstream's own MFA rule (shouldEnforceMFA plus
 * the user's configured methods) is replaced, so its tests are replaced too; the full policy matrix, including the
 * cases upstream covered (a password or presence-only WebAuthn never gets past a configured TOTP / security key),
 * lives in lib/azdigi/policy.test.ts. loadMostRecentSession / loadSessionById are upstream's and keep upstream's tests.
 */
import * as orgLookup from "@/lib/azdigi/org-lookup";
import * as cookiesModule from "@/lib/server/cookies";
import {
  checkSessionPolicy,
  findValidSession,
  isSessionValid,
  loadMostRecentSession,
  loadSessionById,
} from "@/lib/server/session";
import * as zitadelModule from "@/lib/server/zitadel";
import { Code, ConnectError } from "@connectrpc/connect";
import { SecondFactorType } from "@zitadel/proto/zitadel/settings/v2/login_settings_pb";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

vi.mock("@/lib/server/zitadel", () => ({
  getLoginSettings: vi.fn(),
  getUserByID: vi.fn(),
  getSession: vi.fn(),
  // users here have no TOTP / security key / passkey unless a test says otherwise
  listAuthenticationMethodTypes: vi.fn(async () => ({ authMethodTypes: [] })),
}));
vi.mock("@/lib/azdigi/org-lookup", () => ({ isOtpFirstOrg: vi.fn() }));
vi.mock("@/lib/server/cookies", () => ({ getMostRecentCookieWithLoginname: vi.fn(), getSessionCookieById: vi.fn() }));

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

const customers = {
  forceMfa: false,
  forceMfaLocalOnly: false,
  secondFactors: [SecondFactorType.OTP_EMAIL],
  multiFactors: [],
} as any;
const internal = {
  forceMfa: true,
  forceMfaLocalOnly: true,
  secondFactors: [SecondFactorType.OTP, SecondFactorType.U2F],
  multiFactors: [],
} as any;

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
    expect(
      await isSessionValid({
        serviceConfig,
        session: session({ password: { verifiedAt: ts(-5) }, totp: { verifiedAt: ts(-5) } }),
      }),
    ).toBe(true);
    expect(
      await isSessionValid({
        serviceConfig,
        session: session({ password: { verifiedAt: ts(-5) }, otpEmail: { verifiedAt: ts(-5) } }),
      }),
    ).toBe(false);
  });

  test("a user-verified passkey satisfies a forceMfa organisation", async () => {
    vi.mocked(zitadelModule.getLoginSettings).mockResolvedValue(internal);
    expect(
      await isSessionValid({ serviceConfig, session: session({ webAuthN: { verifiedAt: ts(-5), userVerified: true } }) }),
    ).toBe(true);
  });

  test("expired sessions and missing settings are refused", async () => {
    expect(
      await isSessionValid({
        serviceConfig,
        session: session({ password: { verifiedAt: ts(-5) } }, { expirationDate: ts(-1) }),
      }),
    ).toBe(false);
    vi.mocked(zitadelModule.getLoginSettings).mockResolvedValue(undefined);
    expect(await isSessionValid({ serviceConfig, session: session({ password: { verifiedAt: ts(-5) } }) })).toBe(false);
  });

  test("a session without expiration date is treated as not expired", async () => {
    expect(
      await isSessionValid({
        serviceConfig,
        session: session({ password: { verifiedAt: ts(-5) } }, { expirationDate: undefined }),
      }),
    ).toBe(true);
  });

  test("checkSessionPolicy exposes the next step for the caller", async () => {
    expect(await checkSessionPolicy({ serviceConfig, session: session({}) })).toEqual({
      ok: false,
      reason: "no-first-factor",
      next: "otpEmail",
    });
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
      vi.mocked(zitadelModule.getUserByID).mockResolvedValue({
        user: { type: { case: "human", value: { email: { isVerified: false } } } },
      } as any);
      expect(await isSessionValid({ serviceConfig, session: session({ password: { verifiedAt: ts(-5) } }) })).toBe(false);
    });

    test("accepts a verified email and skips the lookup when disabled", async () => {
      process.env.EMAIL_VERIFICATION = "true";
      vi.mocked(zitadelModule.getUserByID).mockResolvedValue({
        user: { type: { case: "human", value: { email: { isVerified: true } } } },
      } as any);
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
    expect(
      await findValidSession({ serviceConfig, sessions: [stale, good], authRequest: { hintUserId: "other" } as any }),
    ).toBeUndefined();
    expect(
      (await findValidSession({ serviceConfig, sessions: [stale, good], authRequest: { loginHint: "a@b.c" } as any }))?.id,
    ).toBe("good");
  });
});

describe("findValidSession organisation scope (#46)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.mocked(zitadelModule.getLoginSettings).mockResolvedValue(customers);
    vi.mocked(orgLookup.isOtpFirstOrg).mockResolvedValue(true);
  });

  test("an application that names its organisation never gets another organisation's session", async () => {
    const other = session({ password: { verifiedAt: ts(-5) } }, { id: "other-org" });
    other.factors.user.organizationId = "org-2";
    const own = session({ password: { verifiedAt: ts(-5) } }, { id: "own-org", changeDate: ts(-100) });
    const scoped = { scope: ["openid", "urn:zitadel:iam:org:id:1"] } as any;
    other.factors.user.organizationId = "2";
    own.factors.user.organizationId = "1";
    expect((await findValidSession({ serviceConfig, sessions: [other, own], authRequest: scoped }))?.id).toBe("own-org");
    expect(await findValidSession({ serviceConfig, sessions: [other], authRequest: scoped })).toBeUndefined();
    // without an organisation scope any valid session may be used
    expect(
      (await findValidSession({ serviceConfig, sessions: [other], authRequest: { scope: ["openid"] } as any }))?.id,
    ).toBe("other-org");
  });
});

describe("loadMostRecentSession", () => {
  const serviceConfig = { baseUrl: "https://zitadel-abc123.zitadel.cloud" };
  const sessionParams = { loginName: "test@example.com", organization: "test-org-id" };
  const cookie = { id: "session-id", token: "session-token", loginName: "test@example.com", organization: "test-org-id" };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  test("returns undefined without calling getSession when no cookie is found", async () => {
    vi.mocked(cookiesModule.getMostRecentCookieWithLoginname).mockResolvedValue(undefined as any);

    const result = await loadMostRecentSession({ serviceConfig, sessionParams });

    expect(result).toBeUndefined();
    expect(zitadelModule.getSession).not.toHaveBeenCalled();
  });

  test("returns the session when getSession succeeds", async () => {
    const session = { id: "session-id", factors: { user: { id: "user-id" } } };
    vi.mocked(cookiesModule.getMostRecentCookieWithLoginname).mockResolvedValue(cookie as any);
    vi.mocked(zitadelModule.getSession).mockResolvedValue({ session } as any);

    const result = await loadMostRecentSession({ serviceConfig, sessionParams });

    expect(result).toBe(session);
    expect(zitadelModule.getSession).toHaveBeenCalledWith({
      serviceConfig,
      sessionId: cookie.id,
      sessionToken: cookie.token,
    });
  });

  test.each([
    ["NotFound", Code.NotFound, "Session does not exist (QUERY-SFeaa)"],
    ["PermissionDenied", Code.PermissionDenied, "Permission denied (QUERY-dsfr3)"],
  ])(
    "returns undefined instead of throwing when getSession rejects with %s (stale cookie)",
    async (_name, code, message) => {
      // The `sessions` cookie can outlive the server-side session (NotFound), or hold a token that
      // no longer matches a session that still exists (PermissionDenied). loadMostRecentSession
      // must treat both the same as no session.
      const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      const error = new ConnectError(message, code);
      vi.mocked(cookiesModule.getMostRecentCookieWithLoginname).mockResolvedValue(cookie as any);
      vi.mocked(zitadelModule.getSession).mockRejectedValue(error);

      const result = await loadMostRecentSession({ serviceConfig, sessionParams });

      expect(result).toBeUndefined();
      expect(consoleSpy).toHaveBeenCalledWith("[Session] Could not load session", error);
      consoleSpy.mockRestore();
    },
  );

  test("re-throws other ConnectErrors (real failures must propagate)", async () => {
    const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const unavailable = new ConnectError("backend unavailable", Code.Unavailable);
    vi.mocked(cookiesModule.getMostRecentCookieWithLoginname).mockResolvedValue(cookie as any);
    vi.mocked(zitadelModule.getSession).mockRejectedValue(unavailable);

    await expect(loadMostRecentSession({ serviceConfig, sessionParams })).rejects.toBe(unavailable);
    expect(consoleSpy).not.toHaveBeenCalled();
    consoleSpy.mockRestore();
  });

  test("re-throws non-ConnectError rejections (only coded NotFound or PermissionDenied is treated as no session)", async () => {
    // The guard is `instanceof ConnectError && (code === NotFound || code === PermissionDenied)`; anything that is not a
    // ConnectError (e.g. an unexpected runtime error) must not be mistaken for a stale
    // cookie and must propagate.
    const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const unexpected = new Error("boom");
    vi.mocked(cookiesModule.getMostRecentCookieWithLoginname).mockResolvedValue(cookie as any);
    vi.mocked(zitadelModule.getSession).mockRejectedValue(unexpected);

    await expect(loadMostRecentSession({ serviceConfig, sessionParams })).rejects.toBe(unexpected);
    expect(consoleSpy).not.toHaveBeenCalled();
    consoleSpy.mockRestore();
  });
});

describe("loadSessionById", () => {
  const serviceConfig = { baseUrl: "https://zitadel-abc123.zitadel.cloud" };
  const cookie = { id: "session-id", token: "session-token", loginName: "test@example.com", organization: "test-org-id" };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(cookiesModule.getSessionCookieById).mockResolvedValue(cookie as any);
  });

  test.each([
    ["NotFound", Code.NotFound, "Session does not exist"],
    ["PermissionDenied", Code.PermissionDenied, "Permission denied (QUERY-dsfr3)"],
  ])("returns undefined when getSession rejects with %s (stale cookie)", async (_name, code, message) => {
    const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const error = new ConnectError(message, code);
    vi.mocked(zitadelModule.getSession).mockRejectedValue(error);

    await expect(loadSessionById(serviceConfig, "session-id", "test-org-id")).resolves.toBeUndefined();
    expect(consoleSpy).toHaveBeenCalledWith("[Session] Could not load session", error);
    consoleSpy.mockRestore();
  });

  test("re-throws other errors", async () => {
    const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const unavailable = new ConnectError("backend unavailable", Code.Unavailable);
    vi.mocked(zitadelModule.getSession).mockRejectedValue(unavailable);

    await expect(loadSessionById(serviceConfig, "session-id")).rejects.toBe(unavailable);
    expect(consoleSpy).not.toHaveBeenCalled();
    consoleSpy.mockRestore();
  });
});
