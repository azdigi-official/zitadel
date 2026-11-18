import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { beforeEach, describe, expect, test, vi } from "vitest";
import * as sessionLib from "../session";
import { mayEnrolSignInMethod } from "./enrolment-guard";
import * as issue from "./issue";

vi.mock("../session", () => ({ checkSessionPolicy: vi.fn() }));
vi.mock("./issue", () => ({ registeredMethodsOf: vi.fn() }));

const cfg = { baseUrl: "http://api" };
const at = { seconds: BigInt(1), nanos: 0 };
const session = (factors: Record<string, unknown>) => ({ id: "s", factors: { user: { id: "u1", organizationId: "o1", verifiedAt: at }, ...factors } }) as any;
const rejected = { ok: false, reason: "second-factor-missing", next: "mfa" } as any;

beforeEach(() => {
  vi.clearAllMocks();
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

describe("who may add a sign-in method", () => {
  test("a session the login policy accepts", async () => {
    vi.mocked(sessionLib.checkSessionPolicy).mockResolvedValue({ ok: true });
    expect(await mayEnrolSignInMethod({ serviceConfig: cfg, session: session({ password: { verifiedAt: at } }) })).toBe(true);
    expect(issue.registeredMethodsOf).not.toHaveBeenCalled();
  });

  test("a known password does not add a passkey or authenticator past the second factor the account already has", async () => {
    vi.mocked(sessionLib.checkSessionPolicy).mockResolvedValue(rejected);
    for (const strong of [AuthenticationMethodType.TOTP, AuthenticationMethodType.U2F, AuthenticationMethodType.PASSKEY]) {
      vi.mocked(issue.registeredMethodsOf).mockResolvedValue([AuthenticationMethodType.PASSWORD, strong]);
      expect(await mayEnrolSignInMethod({ serviceConfig: cfg, session: session({ password: { verifiedAt: at } }) })).toBe(false);
    }
  });

  test("the first set-up: a proven first factor and no strong factor on the account yet", async () => {
    vi.mocked(sessionLib.checkSessionPolicy).mockResolvedValue({ ...rejected, next: "mfaSetup" });
    vi.mocked(issue.registeredMethodsOf).mockResolvedValue([AuthenticationMethodType.PASSWORD, AuthenticationMethodType.OTP_EMAIL]);
    expect(await mayEnrolSignInMethod({ serviceConfig: cfg, session: session({ password: { verifiedAt: at } }) })).toBe(true);
  });

  test("a session that only names the user, or only has an emailed code the policy does not accept", async () => {
    vi.mocked(sessionLib.checkSessionPolicy).mockResolvedValue({ ok: false, reason: "no-first-factor", next: "password" } as any);
    vi.mocked(issue.registeredMethodsOf).mockResolvedValue([]);
    expect(await mayEnrolSignInMethod({ serviceConfig: cfg, session: session({}) })).toBe(false);
    expect(await mayEnrolSignInMethod({ serviceConfig: cfg, session: session({ otpEmail: { verifiedAt: at } }) })).toBe(false);
  });

  test("an expired session with a password gets no first set-up", async () => {
    vi.mocked(sessionLib.checkSessionPolicy).mockResolvedValue({ ok: false, reason: "expired", next: "loginname" } as any);
    vi.mocked(issue.registeredMethodsOf).mockResolvedValue([AuthenticationMethodType.PASSWORD]);
    expect(await mayEnrolSignInMethod({ serviceConfig: cfg, session: session({ password: { verifiedAt: at } }) })).toBe(false);
  });

  test("methods that cannot be read fail closed", async () => {
    vi.mocked(sessionLib.checkSessionPolicy).mockResolvedValue(rejected);
    vi.mocked(issue.registeredMethodsOf).mockResolvedValue(undefined);
    expect(await mayEnrolSignInMethod({ serviceConfig: cfg, session: session({ password: { verifiedAt: at } }) })).toBe(false);
  });

  test("no session, no user", async () => {
    expect(await mayEnrolSignInMethod({ serviceConfig: cfg, session: undefined })).toBe(false);
    expect(await mayEnrolSignInMethod({ serviceConfig: cfg, session: { id: "s", factors: {} } as any })).toBe(false);
    expect(sessionLib.checkSessionPolicy).not.toHaveBeenCalled();
  });
});
