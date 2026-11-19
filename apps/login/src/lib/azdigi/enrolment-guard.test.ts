import * as upstreamGuard from "@/lib/server/enrollment-guard";
import * as sessionLib from "@/lib/server/session";
import * as verifyHelper from "@/lib/server/verify-helper";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { beforeEach, describe, expect, test, vi } from "vitest";
import { ENROLMENT_REFUSED, enrolmentAuthorizationError, mayEnrolSignInMethod } from "./enrolment-guard";
import * as issue from "./issue";

vi.mock("@/lib/server/session", () => ({ checkSessionPolicy: vi.fn() }));
vi.mock("./issue", () => ({ registeredMethodsOf: vi.fn() }));
vi.mock("@/lib/server/enrollment-guard", () => ({ getEnrollmentAuthorizationError: vi.fn() }));
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
  const password = session({ password: { verifiedAt: at } });

  test("strong methods: a password alone is not enough when the account already has a second factor", async () => {
    vi.mocked(sessionLib.checkSessionPolicy).mockResolvedValue(rejected);
    vi.mocked(issue.registeredMethodsOf).mockResolvedValue([
      AuthenticationMethodType.PASSWORD,
      AuthenticationMethodType.TOTP,
    ]);
    expect(await enrolmentAuthorizationError({ serviceConfig: cfg, session: password, userId: "u1", kind: "strong" })).toBe(
      ENROLMENT_REFUSED,
    );
    // upstream's rule would have allowed it (verified primary factor); it is not consulted for strong methods
    expect(upstreamGuard.getEnrollmentAuthorizationError).not.toHaveBeenCalled();
  });

  test("strong methods: a session the policy accepts", async () => {
    vi.mocked(sessionLib.checkSessionPolicy).mockResolvedValue({ ok: true });
    expect(
      await enrolmentAuthorizationError({ serviceConfig: cfg, session: password, userId: "u1", kind: "strong" }),
    ).toBeNull();
  });

  test("strong methods: upstream's onboarding path, an account with no method that was verified in this browser", async () => {
    vi.mocked(sessionLib.checkSessionPolicy).mockResolvedValue({
      ok: false,
      reason: "no-first-factor",
      next: "password",
    } as any);
    vi.mocked(issue.registeredMethodsOf).mockResolvedValue([]);
    vi.mocked(verifyHelper.checkUserVerification).mockResolvedValue(true);
    expect(
      await enrolmentAuthorizationError({ serviceConfig: cfg, session: session({}), userId: "u1", kind: "strong" }),
    ).toBeNull();
    expect(verifyHelper.checkUserVerification).toHaveBeenCalledWith("u1");

    vi.mocked(verifyHelper.checkUserVerification).mockResolvedValue(false);
    expect(
      await enrolmentAuthorizationError({ serviceConfig: cfg, session: session({}), userId: "u1", kind: "strong" }),
    ).toBe(ENROLMENT_REFUSED);

    // any existing method closes the onboarding path, and unreadable methods fail closed
    vi.mocked(verifyHelper.checkUserVerification).mockResolvedValue(true);
    vi.mocked(issue.registeredMethodsOf).mockResolvedValue([AuthenticationMethodType.OTP_EMAIL]);
    expect(
      await enrolmentAuthorizationError({ serviceConfig: cfg, session: session({}), userId: "u1", kind: "strong" }),
    ).toBe(ENROLMENT_REFUSED);
    vi.mocked(issue.registeredMethodsOf).mockResolvedValue(undefined);
    expect(
      await enrolmentAuthorizationError({ serviceConfig: cfg, session: session({}), userId: "u1", kind: "strong" }),
    ).toBe(ENROLMENT_REFUSED);
  });

  test("codes keep upstream's rule", async () => {
    vi.mocked(upstreamGuard.getEnrollmentAuthorizationError).mockResolvedValue("upstream says no");
    expect(await enrolmentAuthorizationError({ serviceConfig: cfg, session: password, userId: "u1", kind: "code" })).toBe(
      "upstream says no",
    );
    vi.mocked(upstreamGuard.getEnrollmentAuthorizationError).mockResolvedValue(null);
    expect(
      await enrolmentAuthorizationError({ serviceConfig: cfg, session: password, userId: "u1", kind: "code" }),
    ).toBeNull();
  });

  test("a session of another user, or none, is refused before anything is read", async () => {
    expect(
      await enrolmentAuthorizationError({ serviceConfig: cfg, session: password, userId: "someone-else", kind: "code" }),
    ).toBe(ENROLMENT_REFUSED);
    expect(await enrolmentAuthorizationError({ serviceConfig: cfg, session: undefined, userId: "u1", kind: "strong" })).toBe(
      ENROLMENT_REFUSED,
    );
    expect(upstreamGuard.getEnrollmentAuthorizationError).not.toHaveBeenCalled();
    expect(sessionLib.checkSessionPolicy).not.toHaveBeenCalled();
  });
});
