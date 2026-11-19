import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { absolutePathFor, navigateAfterAction } from "./navigate";

describe("the URL for a full page load", () => {
  test("an app-relative path gets the base path once", () => {
    expect(absolutePathFor("/otp/time-based?loginName=a", "/ui/v2/login")).toBe("/ui/v2/login/otp/time-based?loginName=a");
    expect(absolutePathFor("/ui/v2/login/account?x=1", "/ui/v2/login")).toBe("/ui/v2/login/account?x=1");
    expect(absolutePathFor("/account", undefined)).toBe("/account");
  });

  test("an application's own URL is left alone", () => {
    expect(absolutePathFor("https://billing.example/callback?code=1", "/ui/v2/login")).toBe(
      "https://billing.example/callback?code=1",
    );
    expect(absolutePathFor("//evil.example/x", "/ui/v2/login")).toBe("//evil.example/x");
  });
});

describe("going to the next page after a server action", () => {
  const assign = vi.fn();
  let href = "http://login.test/ui/v2/login/password?loginName=a";
  beforeEach(() => {
    vi.useFakeTimers();
    vi.stubEnv("NEXT_PUBLIC_BASE_PATH", "/ui/v2/login");
    href = "http://login.test/ui/v2/login/password?loginName=a";
    vi.stubGlobal("window", {
      location: {
        get href() {
          return href;
        },
        assign,
      },
    });
    vi.spyOn(console, "warn").mockImplementation(() => {});
    assign.mockClear();
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  test("the router is asked in a later task; when the page changes nothing else happens", () => {
    const router = {
      push: vi.fn(() => {
        href = "http://login.test/ui/v2/login/otp/time-based";
      }),
    };
    navigateAfterAction(router, "/otp/time-based");
    expect(router.push).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(router.push).toHaveBeenCalledWith("/otp/time-based");
    vi.advanceTimersByTime(10_000);
    expect(assign).not.toHaveBeenCalled();
  });

  test("when the page does not change, the browser loads the next page itself", () => {
    const router = { push: vi.fn() };
    navigateAfterAction(router, "/otp/time-based?loginName=a");
    vi.advanceTimersByTime(3_900);
    expect(assign).not.toHaveBeenCalled();
    vi.advanceTimersByTime(200);
    expect(assign).toHaveBeenCalledWith("/ui/v2/login/otp/time-based?loginName=a");
  });
});
