import * as upstreamGuard from "@/lib/server/enrollment-guard";
import * as sessionLib from "@/lib/server/session";
import * as verifyHelper from "@/lib/server/verify-helper";
import * as zitadel from "@/lib/server/zitadel";
import { PasskeysType, SecondFactorType } from "@zitadel/proto/zitadel/settings/v2/login_settings_pb";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { beforeEach, describe, expect, test, vi } from "vitest";
import { ENROLMENT_REFUSED, enrolmentAuthorizationError, mayEnrolSignInMethod } from "./enrolment-guard";
import * as issue from "./issue";

vi.mock("@/lib/server/session", async (importOriginal) => ({
  // upstream's second-factor helpers stay real
  ...(await importOriginal<typeof import("@/lib/server/session")>()),
  checkSessionPolicy: vi.fn(),
}));
vi.mock("@/lib/server/zitadel", () => ({ getLoginSettings: vi.fn() }));
vi.mock("./issue", () => ({ registeredMethodsOf: vi.fn() }));
vi.mock("@/lib/server/enrollment-guard", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/server/enrollment-guard")>()),
  getSetupAuthorizationError: vi.fn(),
}));
vi.mock("@/lib/server/verify-helper", () => ({ checkUserVerification: vi.fn() }));

const cfg = { baseUrl: "http://api" };
const at = { seconds: BigInt(1), nanos: 0 };
const session = (factors: Record<string, unknown>) =>
  ({ id: "s", factors: { user: { id: "u1", organizationId: "o1", verifiedAt: at }, ...factors } }) as any;
const rejected = { ok: false, reason: "second-factor-missing", next: "mfa" } as any;

beforeEach(() => {
  vi.clearAllMocks();
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

describe("who may add a sign-in method", () => {
  test("a session the login policy accepts", async () => {
    vi.mocked(sessionLib.checkSessionPolicy).mockResolvedValue({ ok: true });
    expect(await mayEnrolSignInMethod({ serviceConfig: cfg, session: session({ password: { verifiedAt: at } }) })).toBe(
      true,
    );
    expect(issue.registeredMethodsOf).not.toHaveBeenCalled();
  });

  test("a known password does not add a passkey or authenticator past the second factor the account already has", async () => {
    vi.mocked(sessionLib.checkSessionPolicy).mockResolvedValue(rejected);
    for (const strong of [AuthenticationMethodType.TOTP, AuthenticationMethodType.U2F, AuthenticationMethodType.PASSKEY]) {
      vi.mocked(issue.registeredMethodsOf).mockResolvedValue([AuthenticationMethodType.PASSWORD, strong]);
      expect(await mayEnrolSignInMethod({ serviceConfig: cfg, session: session({ password: { verifiedAt: at } }) })).toBe(
        false,
      );
    }
  });

  test("the first set-up: a proven first factor and no strong factor on the account yet", async () => {
    vi.mocked(sessionLib.checkSessionPolicy).mockResolvedValue({ ...rejected, next: "mfaSetup" });
    vi.mocked(issue.registeredMethodsOf).mockResolvedValue([
      AuthenticationMethodType.PASSWORD,
      AuthenticationMethodType.OTP_EMAIL,
    ]);
    expect(await mayEnrolSignInMethod({ serviceConfig: cfg, session: session({ password: { verifiedAt: at } }) })).toBe(
      true,
    );
  });

  test("a session that only names the user, or only has an emailed code the policy does not accept", async () => {
    vi.mocked(sessionLib.checkSessionPolicy).mockResolvedValue({
      ok: false,
      reason: "no-first-factor",
      next: "password",
    } as any);
    vi.mocked(issue.registeredMethodsOf).mockResolvedValue([]);
    expect(await mayEnrolSignInMethod({ serviceConfig: cfg, session: session({}) })).toBe(false);
    expect(await mayEnrolSignInMethod({ serviceConfig: cfg, session: session({ otpEmail: { verifiedAt: at } }) })).toBe(
      false,
    );
  });

  test("an expired session with a password gets no first set-up", async () => {
    vi.mocked(sessionLib.checkSessionPolicy).mockResolvedValue({ ok: false, reason: "expired", next: "loginname" } as any);
    vi.mocked(issue.registeredMethodsOf).mockResolvedValue([AuthenticationMethodType.PASSWORD]);
    expect(await mayEnrolSignInMethod({ serviceConfig: cfg, session: session({ password: { verifiedAt: at } }) })).toBe(
      false,
    );
  });

  test("methods that cannot be read fail closed", async () => {
    vi.mocked(sessionLib.checkSessionPolicy).mockResolvedValue(rejected);
    vi.mocked(issue.registeredMethodsOf).mockResolvedValue(undefined);
    expect(await mayEnrolSignInMethod({ serviceConfig: cfg, session: session({ password: { verifiedAt: at } }) })).toBe(
      false,
    );
  });

  test("no session, no user", async () => {
    expect(await mayEnrolSignInMethod({ serviceConfig: cfg, session: undefined })).toBe(false);
    expect(await mayEnrolSignInMethod({ serviceConfig: cfg, session: { id: "s", factors: {} } as any })).toBe(false);
    expect(sessionLib.checkSessionPolicy).not.toHaveBeenCalled();
  });
});

describe("the gate every enrolment entry point calls", () => {
  const M = AuthenticationMethodType;
  const password = session({ password: { verifiedAt: at } });
  const allowAll = {
    passkeysType: PasskeysType.ALLOWED,
    secondFactors: [SecondFactorType.TOTP, SecondFactorType.U2F],
  } as any;
  const gate = (s: any, method: any, userId = "u1") =>
    enrolmentAuthorizationError({ serviceConfig: cfg, session: s, userId, method });

  beforeEach(() => {
    vi.mocked(zitadel.getLoginSettings).mockResolvedValue(allowAll);
  });

  test("a known password alone is not enough when the account already has a second factor (our policy refuses first)", async () => {
    vi.mocked(sessionLib.checkSessionPolicy).mockResolvedValue(rejected);
    vi.mocked(issue.registeredMethodsOf).mockResolvedValue([M.PASSWORD, M.TOTP]);
    for (const method of ["passkey", "totp", "u2f", "idp"]) {
      expect(await gate(password, method)).toBe(ENROLMENT_REFUSED);
    }
    expect(upstreamGuard.getSetupAuthorizationError).not.toHaveBeenCalled();
  });

  test("upstream's rule on top: a policy-valid session must also have verified a configured second factor", async () => {
    // e.g. a customer who signed in with a password: the policy accepts it, the configured email code was not verified
    vi.mocked(sessionLib.checkSessionPolicy).mockResolvedValue({ ok: true });
    vi.mocked(issue.registeredMethodsOf).mockResolvedValue([M.PASSWORD, M.OTP_EMAIL]);
    expect(await gate(password, "passkey")).toBe(upstreamGuard.SECOND_FACTOR_REQUIRED_ERROR);
    expect(await gate(session({ password: { verifiedAt: at }, otpEmail: { verifiedAt: at } }), "passkey")).toBeNull();
    // a user-verified passkey sign-in is multi-factor on its own
    expect(await gate(session({ webAuthN: { verifiedAt: at, userVerified: true } }), "totp")).toBeNull();
  });

  test("an OTP-first customer signed in with the emailed code alone may add a passkey", async () => {
    vi.mocked(sessionLib.checkSessionPolicy).mockResolvedValue({ ok: true });
    vi.mocked(issue.registeredMethodsOf).mockResolvedValue([M.OTP_EMAIL]);
    expect(await gate(session({ otpEmail: { verifiedAt: at } }), "passkey")).toBeNull();
  });

  test("forced first set-up: staff with a password and no second factor may set one up", async () => {
    vi.mocked(sessionLib.checkSessionPolicy).mockResolvedValue({ ...rejected, next: "mfaSetup" });
    vi.mocked(issue.registeredMethodsOf).mockResolvedValue([M.PASSWORD]);
    expect(await gate(password, "totp")).toBeNull();
    expect(await gate(password, "u2f")).toBeNull();
  });

  test("the organisation's settings must allow the authenticator (IdP links are checked by the IdP flow)", async () => {
    vi.mocked(sessionLib.checkSessionPolicy).mockResolvedValue({ ok: true });
    vi.mocked(issue.registeredMethodsOf).mockResolvedValue([M.PASSWORD]);
    vi.mocked(zitadel.getLoginSettings).mockResolvedValue({
      passkeysType: PasskeysType.NOT_ALLOWED,
      secondFactors: [SecondFactorType.U2F],
    } as any);
    expect(await gate(password, "passkey")).toBe(upstreamGuard.PASSKEYS_NOT_ALLOWED_ERROR);
    expect(await gate(password, "totp")).toBe(upstreamGuard.SECOND_FACTOR_NOT_ALLOWED_ERROR);
    expect(await gate(password, "u2f")).toBeNull();
    expect(await gate(password, "idp")).toBeNull();
    expect(zitadel.getLoginSettings).toHaveBeenCalledWith(expect.objectContaining({ organization: "o1", fresh: true }));
  });

  test("upstream's onboarding path: an account with no method that was verified in this browser", async () => {
    vi.mocked(sessionLib.checkSessionPolicy).mockResolvedValue({
      ok: false,
      reason: "no-first-factor",
      next: "password",
    } as any);
    vi.mocked(issue.registeredMethodsOf).mockResolvedValue([]);
    vi.mocked(verifyHelper.checkUserVerification).mockResolvedValue(true);
    expect(await gate(session({}), "passkey")).toBeNull();
    expect(verifyHelper.checkUserVerification).toHaveBeenCalledWith("u1");

    vi.mocked(verifyHelper.checkUserVerification).mockResolvedValue(false);
    expect(await gate(session({}), "passkey")).toBe(ENROLMENT_REFUSED);

    // any existing method closes the onboarding path, and unreadable methods fail closed
    vi.mocked(verifyHelper.checkUserVerification).mockResolvedValue(true);
    vi.mocked(issue.registeredMethodsOf).mockResolvedValue([M.OTP_EMAIL]);
    expect(await gate(session({}), "passkey")).toBe(ENROLMENT_REFUSED);
    vi.mocked(issue.registeredMethodsOf).mockResolvedValue(undefined);
    expect(await gate(session({}), "passkey")).toBe(ENROLMENT_REFUSED);
  });

  test("codes keep upstream's rule (including its v4.20.5 second-factor and settings checks)", async () => {
    vi.mocked(upstreamGuard.getSetupAuthorizationError).mockResolvedValue("upstream says no");
    expect(await gate(password, "otp_email")).toBe("upstream says no");
    expect(upstreamGuard.getSetupAuthorizationError).toHaveBeenCalledWith(
      expect.objectContaining({ method: "otp_email", userId: "u1" }),
    );
    vi.mocked(upstreamGuard.getSetupAuthorizationError).mockResolvedValue(null);
    expect(await gate(password, "otp_sms")).toBeNull();
  });

  test("a session of another user, or none, is refused before anything is read", async () => {
    expect(await gate(password, "otp_email", "someone-else")).toBe(ENROLMENT_REFUSED);
    expect(await gate(undefined, "passkey")).toBe(ENROLMENT_REFUSED);
    expect(upstreamGuard.getSetupAuthorizationError).not.toHaveBeenCalled();
    expect(sessionLib.checkSessionPolicy).not.toHaveBeenCalled();
  });
});
