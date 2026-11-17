import { describe, expect, test, vi } from "vitest";
import { getNextUrl } from "../client";

vi.mock("../server/auth-flow", () => ({ completeAuthFlow: vi.fn() }));

describe("where a flow without an application request ends", () => {
  test("at the account page of the session that signed in, not at the organisation's default redirect", async () => {
    expect(await getNextUrl({ loginName: "an@azdigi.com", organization: "7" }, "https://billing.example/admin/login")).toBe(
      "/account?loginName=an%40azdigi.com&organization=7",
    );
    expect(await getNextUrl({ loginName: "an@azdigi.com" })).toBe("/account?loginName=an%40azdigi.com");
  });

  test("a device authorization still ends at the signed-in page", async () => {
    expect(await getNextUrl({ sessionId: "s1", requestId: "device_abc", organization: "7" }, "https://billing.example/admin/login")).toBe(
      "/signedin?sessionId=s1&organization=7&requestId=device_abc",
    );
  });
});
