import { SecondFactorFirst } from "@/components/azdigi/second-factor-first";
import { OTPAddForm } from "@/components/otp-add-form";
import { Translated } from "@/components/translated";
import { isValidElement, ReactElement, ReactNode } from "react";
import { beforeEach, describe, expect, test, vi } from "vitest";
import Page from "./page";

// AZDIGI: the page asks lib/azdigi/enrolment-guard.ts; here it passes every method to upstream's mocked rule (the gate
// itself is tested in lib/azdigi/enrolment-guard.test.ts)
vi.mock("@/lib/azdigi/enrolment-guard", () => ({
  enrolmentAuthorizationError: vi.fn(async (args: any) =>
    (await import("@/lib/server/enrollment-guard")).getSetupAuthorizationError(args),
  ),
}));
vi.mock("@/lib/azdigi/second-factor-step", () => ({ secondFactorStep: vi.fn() }));
vi.mock("@/lib/server/zitadel", () => ({
  getBrandingSettings: vi.fn(),
  getLoginSettings: vi.fn(),
  registerTOTP: vi.fn(),
  addOTPEmail: vi.fn(),
  addOTPSMS: vi.fn(),
}));

vi.mock("@/lib/server/enrollment-guard", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/server/enrollment-guard")>()),
  getSetupAuthorizationError: vi.fn(),
}));

vi.mock("@/lib/actions/otp", () => ({
  addOTP: vi.fn(),
}));

vi.mock("@/lib/server/session", () => ({
  loadMostRecentSession: vi.fn(),
  loadSessionById: vi.fn(),
}));

vi.mock("@/lib/server/service-url", () => ({
  getServiceConfig: vi.fn(() => ({ serviceConfig: { baseUrl: "https://example.com" } })),
}));

vi.mock("next-intl", () => ({
  useTranslations: () => (key: string) => key,
}));

vi.mock("next/headers", () => ({
  headers: vi.fn(() => new Headers()),
}));

// AZDIGI: the page sends a refused session back to the sign-in
vi.mock("next/navigation", () => ({
  redirect: vi.fn((url: string) => {
    throw new Error(`NEXT_REDIRECT ${url}`);
  }),
}));

const session = {
  id: "session-1",
  factors: { user: { id: "user-1", loginName: "user@example.com", displayName: "User", organizationId: "org-1" } },
};

// collects all elements of the given type from the (unrendered) element tree returned by the page
function findElements(node: ReactNode, type: unknown): ReactElement<any>[] {
  if (Array.isArray(node)) {
    return node.flatMap((child) => findElements(child, type));
  }
  if (!isValidElement(node)) {
    return [];
  }
  const element = node as ReactElement<any>;
  return [...(element.type === type ? [element] : []), ...findElements(element.props?.children, type)];
}

describe("otp set page", () => {
  let zitadel: any;
  let sessionLib: any;
  let guard: any;
  let addOTP: any;

  beforeEach(async () => {
    vi.clearAllMocks();
    zitadel = await import("@/lib/server/zitadel");
    sessionLib = await import("@/lib/server/session");
    guard = await import("@/lib/server/enrollment-guard");
    addOTP = vi.mocked((await import("@/lib/actions/otp")).addOTP);

    vi.mocked(zitadel.getBrandingSettings).mockResolvedValue({} as any);
    vi.mocked(zitadel.getLoginSettings).mockResolvedValue({} as any);
    vi.mocked(sessionLib.loadMostRecentSession).mockResolvedValue(session as any);
    vi.mocked(sessionLib.loadSessionById).mockResolvedValue(session as any);
    vi.mocked(guard.getSetupAuthorizationError).mockResolvedValue(null);
  });

  // Rendering the page (e.g. by following a link) must never add a second factor to the
  // signed-in user; OTP via email or SMS is only added on explicit confirmation.
  test.each(["email", "sms"])("does not add OTP via %s while rendering but asks for confirmation", async (method) => {
    const result = await Page({
      params: Promise.resolve({ method }),
      searchParams: Promise.resolve({}),
    });

    expect(zitadel.addOTPEmail).not.toHaveBeenCalled();
    expect(zitadel.addOTPSMS).not.toHaveBeenCalled();
    expect(addOTP).not.toHaveBeenCalled();

    const forms = findElements(result, OTPAddForm);
    expect(forms).toHaveLength(1);
    expect(forms[0].props).toMatchObject({ method, sessionId: "session-1", urlToContinue: "/accounts", checkAfter: false });
  });

  test.each(["email", "sms"])("does not redirect for %s with checkAfter while rendering", async (method) => {
    const result = await Page({
      params: Promise.resolve({ method }),
      searchParams: Promise.resolve({ checkAfter: "true", loginName: "user@example.com" }),
    });

    expect(addOTP).not.toHaveBeenCalled();
    const forms = findElements(result, OTPAddForm);
    expect(forms).toHaveLength(1);
    expect(forms[0].props.checkAfter).toBe(true);
    expect(forms[0].props.urlToContinue).toBe(`/otp/${method}?loginName=user%40example.com`);
  });

  // AZDIGI: any other refusal (no or an expired authentication) goes back to the sign-in, see the test below
  test.each([["This second factor is not allowed", "authenticatorNotAllowed"]])(
    "hides the confirmation and shows a translated error for %s",
    async (enrollmentError, i18nKey) => {
      vi.mocked(guard.getSetupAuthorizationError).mockResolvedValue(enrollmentError);

      const result = await Page({
        params: Promise.resolve({ method: "email" }),
        searchParams: Promise.resolve({}),
      });

      expect(findElements(result, OTPAddForm)).toHaveLength(0);
      expect(findElements(result, Translated).map((t) => t.props)).toContainEqual(
        expect.objectContaining({ i18nKey, namespace: "error" }),
      );
      expect(JSON.stringify(result)).not.toContain(enrollmentError);
    },
  );

  test.each([
    ["time-based", {}, "/otp/time-based/set"],
    ["time-based", { checkAfter: "true" }, "/otp/time-based/set?checkAfter=true"],
    // codes have no set-up page to come back to; the flow then ends where it normally does
    ["email", {}, ""],
  ])("AZDIGI: refused only for the second factor, %s offers that step (%j)", async (method, extra, returnTo) => {
    const stepLib = await import("@/lib/azdigi/second-factor-step");
    const step = { kind: "emailCode", href: "/otp/email?loginName=user%40example.com" } as const;
    vi.mocked(guard.getSetupAuthorizationError).mockResolvedValue("You have to verify your second factor first");
    vi.mocked(stepLib.secondFactorStep).mockResolvedValue(step);

    const result = await Page({ params: Promise.resolve({ method }), searchParams: Promise.resolve({ ...extra }) });

    expect(findElements(result, OTPAddForm)).toHaveLength(0);
    expect(zitadel.registerTOTP).not.toHaveBeenCalled();
    expect(stepLib.secondFactorStep).toHaveBeenCalledWith(expect.objectContaining({ returnTo }));
    expect(findElements(result, SecondFactorFirst).map((element) => element.props.step)).toEqual([step]);
  });

  test("AZDIGI: a session the enrolment gate refuses goes back to the sign-in; nothing is added or registered", async () => {
    vi.mocked(guard.getSetupAuthorizationError).mockResolvedValue("You have to authenticate");

    await expect(
      Page({
        params: Promise.resolve({ method: "email" }),
        searchParams: Promise.resolve({ loginName: "user@example.com", organization: "org-1", requestId: "oidc_1" }),
      }),
    ).rejects.toThrow("NEXT_REDIRECT /loginname?loginName=user%40example.com&organization=org-1&requestId=oidc_1");
    expect(addOTP).not.toHaveBeenCalled();
    expect(zitadel.registerTOTP).not.toHaveBeenCalled();
  });

  test("renders an alert instead of the confirmation without a session", async () => {
    vi.mocked(sessionLib.loadMostRecentSession).mockResolvedValue(undefined);

    const result = await Page({
      params: Promise.resolve({ method: "email" }),
      searchParams: Promise.resolve({}),
    });

    expect(findElements(result, OTPAddForm)).toHaveLength(0);
    expect(findElements(result, Translated).map((t) => t.props.i18nKey)).toContain("unknownContext");
  });

  test("acts on the session given by sessionId instead of the most recent one", async () => {
    vi.mocked(sessionLib.loadSessionById).mockResolvedValue({ ...session, id: "session-a" } as any);

    const result = await Page({
      params: Promise.resolve({ method: "email" }),
      searchParams: Promise.resolve({ sessionId: "session-a", organization: "org-1" }),
    });

    expect(sessionLib.loadSessionById).toHaveBeenCalledWith({ baseUrl: "https://example.com" }, "session-a", "org-1");
    expect(sessionLib.loadMostRecentSession).not.toHaveBeenCalled();
    expect(findElements(result, OTPAddForm)[0].props.sessionId).toBe("session-a");
  });

  test("renders the session expired alert when the session given by sessionId can't be loaded", async () => {
    vi.mocked(sessionLib.loadSessionById).mockResolvedValue(undefined);

    const result = await Page({
      params: Promise.resolve({ method: "email" }),
      searchParams: Promise.resolve({ sessionId: "session-a" }),
    });

    expect(sessionLib.loadMostRecentSession).not.toHaveBeenCalled();
    expect(findElements(result, OTPAddForm)).toHaveLength(0);
    expect(findElements(result, Translated).map((t) => t.props.i18nKey)).toContain("sessionExpired");
  });
});
