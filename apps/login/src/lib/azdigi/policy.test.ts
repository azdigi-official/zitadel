/**
 * Policy matrix: organisations {Customers (OTP-first, no forced MFA), Internal (forceMfa, TOTP/U2F), default
 * (forceMfa, TOTP/U2F, not OTP-first)} × session shapes. The same function gates isSessionValid and every token call.
 */
import { MultiFactorType, SecondFactorType } from "@zitadel/proto/zitadel/settings/v2/login_settings_pb";
import { describe, expect, test } from "vitest";
import { AuthenticationMethodType as M } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { assertSessionSatisfiesPolicy, hasVerifiedFirstFactor, verifiedFactors } from "./policy";

const future = { seconds: BigInt(Math.floor(Date.now() / 1000) + 3600), nanos: 0 } as any;
const past = { seconds: BigInt(Math.floor(Date.now() / 1000) - 3600), nanos: 0 } as any;
const at = { seconds: BigInt(Math.floor(Date.now() / 1000) - 60), nanos: 0 } as any;

const customers = {
  forceMfa: false,
  forceMfaLocalOnly: false,
  secondFactors: [SecondFactorType.OTP_EMAIL, SecondFactorType.OTP_SMS],
  multiFactors: [],
} as any;
const internal = {
  forceMfa: true,
  forceMfaLocalOnly: true,
  secondFactors: [SecondFactorType.OTP, SecondFactorType.U2F],
  multiFactors: [MultiFactorType.U2F_WITH_VERIFICATION],
} as any;
const defaultOrg = { ...internal };

type Shape = "none" | "user" | "user+otpEmail" | "user+totp" | "user+password" | "user+password+otpEmail" | "user+password+totp" | "user+passkey";

function session(shape: Shape, expirationDate: any = future): any {
  if (shape === "none") {
    return { id: "s", expirationDate, factors: {} };
  }
  const factors: any = { user: { id: "u1", organizationId: "o1", loginName: "a@b.c", verifiedAt: at } };
  if (shape.includes("password")) factors.password = { verifiedAt: at };
  if (shape.includes("otpEmail")) factors.otpEmail = { verifiedAt: at };
  if (shape.includes("totp")) factors.totp = { verifiedAt: at };
  if (shape.includes("passkey")) factors.webAuthN = { verifiedAt: at, userVerified: true };
  return { id: "s", expirationDate, factors };
}

const shapes: Shape[] = [
  "none",
  "user",
  "user+otpEmail",
  "user+totp",
  "user+password",
  "user+password+otpEmail",
  "user+password+totp",
  "user+passkey",
];

const expected: Record<string, Record<Shape, boolean>> = {
  customers: {
    none: false,
    user: false,
    "user+otpEmail": true,
    "user+totp": false,
    "user+password": true,
    "user+password+otpEmail": true,
    "user+password+totp": true,
    "user+passkey": true,
  },
  internal: {
    none: false,
    user: false,
    "user+otpEmail": false,
    "user+totp": false,
    "user+password": false,
    "user+password+otpEmail": false,
    "user+password+totp": true,
    "user+passkey": true,
  },
  default: {
    none: false,
    user: false,
    "user+otpEmail": false,
    "user+totp": false,
    "user+password": false,
    "user+password+otpEmail": false,
    "user+password+totp": true,
    "user+passkey": true,
  },
};

describe("assertSessionSatisfiesPolicy matrix (3 orgs × 8 session shapes)", () => {
  const orgs = [
    { key: "customers", settings: customers, otpFirstOrg: true },
    { key: "internal", settings: internal, otpFirstOrg: false },
    { key: "default", settings: defaultOrg, otpFirstOrg: false },
  ];
  for (const org of orgs) {
    for (const shape of shapes) {
      test(`${org.key} × ${shape} → ${expected[org.key][shape] ? "ok" : "refused"}`, () => {
        const verdict = assertSessionSatisfiesPolicy({
          session: session(shape),
          loginSettings: org.settings,
          otpFirstOrg: org.otpFirstOrg,
          registeredMethods: [],
        });
        expect(verdict.ok).toBe(expected[org.key][shape]);
      });
    }
  }
});

describe("assertSessionSatisfiesPolicy details", () => {
  test("user-only session is refused everywhere with the right next step", () => {
    expect(assertSessionSatisfiesPolicy({ session: session("user"), loginSettings: customers, otpFirstOrg: true, registeredMethods: [] })).toEqual({
      ok: false,
      reason: "no-first-factor",
      next: "otpEmail",
    });
    expect(assertSessionSatisfiesPolicy({ session: session("user"), loginSettings: internal, otpFirstOrg: false, registeredMethods: [] })).toEqual({
      ok: false,
      reason: "no-first-factor",
      next: "password",
    });
  });

  test("password without a second factor in a forceMfa org points to /mfa", () => {
    expect(assertSessionSatisfiesPolicy({ session: session("user+password"), loginSettings: internal, otpFirstOrg: false, registeredMethods: [] })).toEqual({
      ok: false,
      reason: "second-factor-missing",
      next: "mfa",
    });
  });

  test("an allow-listed org still refuses otpEmail when its own policy does not list OTP_EMAIL", () => {
    const settings = { ...customers, secondFactors: [SecondFactorType.OTP] };
    expect(assertSessionSatisfiesPolicy({ session: session("user+otpEmail"), loginSettings: settings, otpFirstOrg: true, registeredMethods: [] }).ok).toBe(false);
  });

  test("otpEmail alone is refused for an allow-listed org once forceMfa is switched on (fresh settings win)", () => {
    const settings = { ...customers, forceMfa: true };
    expect(assertSessionSatisfiesPolicy({ session: session("user+otpEmail"), loginSettings: settings, otpFirstOrg: true, registeredMethods: [] })).toEqual({
      ok: false,
      reason: "no-first-factor",
      next: "password",
    });
  });

  test("expired, missing settings and missing user verification are refused", () => {
    expect(assertSessionSatisfiesPolicy({ session: session("user+password", past), loginSettings: customers, otpFirstOrg: true, registeredMethods: [] })).toEqual({
      ok: false,
      reason: "expired",
      next: "loginname",
    });
    expect(assertSessionSatisfiesPolicy({ session: session("user+password"), loginSettings: undefined, otpFirstOrg: true, registeredMethods: [] })).toEqual({
      ok: false,
      reason: "no-settings",
      next: "loginname",
    });
    const noVerifiedAt = session("user+password");
    delete noVerifiedAt.factors.user.verifiedAt;
    expect(assertSessionSatisfiesPolicy({ session: noVerifiedAt, loginSettings: customers, otpFirstOrg: true, registeredMethods: [] }).ok).toBe(false);
    expect(assertSessionSatisfiesPolicy({ session: undefined, loginSettings: customers, otpFirstOrg: true, registeredMethods: [] }).ok).toBe(false);
  });

  test("forceMfaLocalOnly: password needs a second factor, IDP does not", () => {
    const settings = { ...customers, forceMfaLocalOnly: true, secondFactors: [SecondFactorType.OTP] };
    expect(assertSessionSatisfiesPolicy({ session: session("user+password"), loginSettings: settings, otpFirstOrg: false, registeredMethods: [] }).ok).toBe(false);
    expect(assertSessionSatisfiesPolicy({ session: session("user+password+totp"), loginSettings: settings, otpFirstOrg: false, registeredMethods: [] }).ok).toBe(true);
    const idp = session("user");
    idp.factors.intent = { verifiedAt: at };
    expect(assertSessionSatisfiesPolicy({ session: idp, loginSettings: settings, otpFirstOrg: false, registeredMethods: [] }).ok).toBe(true);
  });

  test("U2F (webAuthN without user verification) is a second factor, not a first one", () => {
    const u2fOnly = session("user");
    u2fOnly.factors.webAuthN = { verifiedAt: at, userVerified: false };
    expect(assertSessionSatisfiesPolicy({ session: u2fOnly, loginSettings: internal, otpFirstOrg: false, registeredMethods: [] }).ok).toBe(false);
    u2fOnly.factors.password = { verifiedAt: at };
    expect(assertSessionSatisfiesPolicy({ session: u2fOnly, loginSettings: internal, otpFirstOrg: false, registeredMethods: [] }).ok).toBe(true);
  });
});

describe("factor helpers", () => {
  test("verifiedFactors and hasVerifiedFirstFactor", () => {
    expect([...verifiedFactors(session("user+password+totp"))].sort()).toEqual(["password", "totp"]);
    expect(hasVerifiedFirstFactor(session("user"))).toBe(false);
    expect(hasVerifiedFirstFactor(session("user+otpEmail"))).toBe(false);
    expect(hasVerifiedFirstFactor(session("user+password"))).toBe(true);
    expect(hasVerifiedFirstFactor(session("user+passkey"))).toBe(true);
    expect(hasVerifiedFirstFactor(undefined)).toBe(false);
  });
});

describe("registered factors are not bypassed by a weaker sign-in (OTP-first and password)", () => {
  const check = (shape: Shape, registeredMethods: M[] | undefined, settings = customers) =>
    assertSessionSatisfiesPolicy({ session: session(shape), loginSettings: settings, otpFirstOrg: true, registeredMethods });

  test("email code alone is enough only for users without TOTP / security key / passkey", () => {
    expect(check("user+otpEmail", [M.OTP_EMAIL]).ok).toBe(true);
    expect(check("user+otpEmail", [M.OTP_EMAIL, M.PASSWORD]).ok).toBe(true);
    expect(check("user+otpEmail", [M.OTP_EMAIL, M.TOTP])).toEqual({ ok: false, reason: "second-factor-missing", next: "mfa" });
    expect(check("user+otpEmail", [M.OTP_EMAIL, M.U2F])).toEqual({ ok: false, reason: "second-factor-missing", next: "mfa" });
    expect(check("user+otpEmail", [M.OTP_EMAIL, M.PASSKEY])).toEqual({ ok: false, reason: "second-factor-missing", next: "passkey" });
  });

  test("the email code plus the registered factor passes", () => {
    const s = session("user+otpEmail");
    s.factors.totp = { verifiedAt: at };
    expect(assertSessionSatisfiesPolicy({ session: s, loginSettings: customers, otpFirstOrg: true, registeredMethods: [M.OTP_EMAIL, M.TOTP] }).ok).toBe(true);
  });

  test("password alone does not bypass TOTP / U2F, but a passkey user may still use a password", () => {
    expect(check("user+password", [M.PASSWORD, M.TOTP])).toEqual({ ok: false, reason: "second-factor-missing", next: "mfa" });
    expect(check("user+password+totp", [M.PASSWORD, M.TOTP]).ok).toBe(true);
    expect(check("user+password", [M.PASSWORD, M.PASSKEY]).ok).toBe(true);
    expect(check("user+passkey", [M.PASSKEY, M.TOTP]).ok).toBe(true);
  });

  test("registered methods unknown → fail closed for OTP-only and password-only sessions", () => {
    expect(check("user+otpEmail", undefined)).toEqual({ ok: false, reason: "no-settings", next: "loginname" });
    expect(check("user+password", undefined)).toEqual({ ok: false, reason: "no-settings", next: "loginname" });
    expect(check("user+passkey", undefined).ok).toBe(true);
  });
});
