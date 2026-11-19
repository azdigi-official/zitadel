// AZDIGI: the action calls lib/azdigi/enrolment-guard.ts (upstream's guard plus the policy rule for strong methods);
// the gate itself is tested in lib/azdigi/enrolment-guard.test.ts.
import { addU2F, verifyU2F } from "@/lib/actions/u2f";
import { beforeEach, describe, expect, test, vi } from "vitest";

vi.mock("@zitadel/client", () => ({
  // `create(schema, data)` is only used to build the verify request — return the data.
  create: vi.fn((_schema: unknown, data: unknown) => data),
}));

vi.mock("@/lib/server/zitadel", () => ({
  getSession: vi.fn(),
  registerU2F: vi.fn(),
  verifyU2FRegistration: vi.fn(),
}));

vi.mock("@/lib/server/service-url", () => ({
  getServiceConfig: vi.fn(() => ({ serviceConfig: { baseUrl: "https://example.com" } })),
}));

vi.mock("@/lib/server/host", () => ({
  getPublicHost: vi.fn(() => "test.com"),
}));

vi.mock("@/lib/server/cookies", () => ({
  getSessionCookieById: vi.fn(),
}));

vi.mock("@/lib/azdigi/enrolment-guard", () => ({
  enrolmentAuthorizationError: vi.fn(),
}));

vi.mock("next/headers", () => ({
  headers: vi.fn(() => new Headers()),
}));

vi.mock("next/server", () => ({
  userAgent: vi.fn(() => ({ browser: {}, device: {}, os: {} })),
}));

const userOnlySession = {
  session: { id: "session-1", factors: { user: { id: "victim-1", loginName: "victim@example.com" } } },
};

describe("addU2F", () => {
  let getSessionCookieById: any;
  let getSession: any;
  let registerU2F: any;
  let enrolmentAuthorizationError: any;

  beforeEach(async () => {
    vi.clearAllMocks();
    getSessionCookieById = vi.mocked((await import("@/lib/server/cookies")).getSessionCookieById);
    getSession = vi.mocked((await import("@/lib/server/zitadel")).getSession);
    registerU2F = vi.mocked((await import("@/lib/server/zitadel")).registerU2F);
    enrolmentAuthorizationError = vi.mocked((await import("@/lib/azdigi/enrolment-guard")).enrolmentAuthorizationError);

    getSessionCookieById.mockResolvedValue({ id: "session-1", token: "token-1" });
    getSession.mockResolvedValue(userOnlySession);
  });

  test("rejects enrollment on an unauthenticated (identify-only) session without registering", async () => {
    enrolmentAuthorizationError.mockResolvedValue("You have to authenticate or have a valid User Verification Check");

    const result = await addU2F({ sessionId: "session-1" });

    expect(result).toEqual({ error: "You have to authenticate or have a valid User Verification Check" });
    expect(enrolmentAuthorizationError).toHaveBeenCalledWith({
      serviceConfig: { baseUrl: "https://example.com" },
      session: userOnlySession.session,
      userId: "victim-1",
      kind: "strong",
    });
    expect(registerU2F).not.toHaveBeenCalled();
  });

  test("registers the credential when the session is authorized", async () => {
    enrolmentAuthorizationError.mockResolvedValue(null);
    registerU2F.mockResolvedValue({ u2fId: "u2f-1" });

    const result = await addU2F({ sessionId: "session-1" });

    expect(registerU2F).toHaveBeenCalledWith({
      serviceConfig: { baseUrl: "https://example.com" },
      userId: "victim-1",
      domain: "test.com",
    });
    expect(result).toEqual({ u2fId: "u2f-1" });
  });

  test("returns error and never calls the guard when no session cookie exists", async () => {
    getSessionCookieById.mockResolvedValue(undefined);

    const result = await addU2F({ sessionId: "missing" });

    expect(result).toEqual({ error: "Could not get session" });
    expect(enrolmentAuthorizationError).not.toHaveBeenCalled();
    expect(registerU2F).not.toHaveBeenCalled();
  });
});

describe("verifyU2F", () => {
  let getSessionCookieById: any;
  let getSession: any;
  let verifyU2FRegistration: any;
  let enrolmentAuthorizationError: any;

  beforeEach(async () => {
    vi.clearAllMocks();
    getSessionCookieById = vi.mocked((await import("@/lib/server/cookies")).getSessionCookieById);
    getSession = vi.mocked((await import("@/lib/server/zitadel")).getSession);
    verifyU2FRegistration = vi.mocked((await import("@/lib/server/zitadel")).verifyU2FRegistration);
    enrolmentAuthorizationError = vi.mocked((await import("@/lib/azdigi/enrolment-guard")).enrolmentAuthorizationError);

    getSessionCookieById.mockResolvedValue({ id: "session-1", token: "token-1" });
    getSession.mockResolvedValue(userOnlySession);
  });

  test("rejects verification on an unauthenticated session without persisting the credential", async () => {
    enrolmentAuthorizationError.mockResolvedValue("User Verification Check has to be done");

    const result = await verifyU2F({
      u2fId: "u2f-1",
      passkeyName: "my key",
      publicKeyCredential: {},
      sessionId: "session-1",
    });

    expect(result).toEqual({ error: "User Verification Check has to be done" });
    expect(verifyU2FRegistration).not.toHaveBeenCalled();
  });

  test("verifies the registration when the session is authorized", async () => {
    enrolmentAuthorizationError.mockResolvedValue(null);
    verifyU2FRegistration.mockResolvedValue({ done: true });

    const result = await verifyU2F({
      u2fId: "u2f-1",
      passkeyName: "my key",
      publicKeyCredential: {},
      sessionId: "session-1",
    });

    expect(verifyU2FRegistration).toHaveBeenCalledTimes(1);
    expect(result).toEqual({ done: true });
  });
});
