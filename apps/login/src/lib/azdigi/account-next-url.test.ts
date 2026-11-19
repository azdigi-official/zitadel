import { getNextUrl } from "@/lib/server/next-url";
import { describe, expect, test, vi } from "vitest";

vi.mock("next/headers", () => ({ headers: vi.fn(async () => new Headers()) }));

describe("where a flow without an application request ends", () => {
  test("at the account page of the session that signed in, not at the organisation's default redirect", async () => {
    expect(await getNextUrl({ loginName: "an@azdigi.com", organization: "7" }, "https://billing.example/admin/login")).toBe(
      "/account?loginName=an%40azdigi.com&organization=7",
    );
    expect(await getNextUrl({ loginName: "an@azdigi.com" })).toBe("/account?loginName=an%40azdigi.com");
  });

  test("a device authorization still goes to upstream's consent screen", async () => {
    expect(
      await getNextUrl(
        { sessionId: "s1", requestId: "device_abc", organization: "7" },
        "https://billing.example/admin/login",
      ),
    ).toBe("/device/consent?sessionId=s1&organization=7&requestId=device_abc");
  });

  test("an operator's DEFAULT_REDIRECT_URI still wins", async () => {
    vi.stubEnv("DEFAULT_REDIRECT_URI", "https://portal.example/after-login");
    expect(await getNextUrl({ loginName: "an@azdigi.com" })).toBe("https://portal.example/after-login");
    vi.unstubAllEnvs();
  });
});
