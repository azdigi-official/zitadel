import crypto from "node:crypto";
import { describe, expect, test } from "vitest";
import { verificationCheckMatches, verificationCheckValue } from "./verification-check";

const env = { ZITADEL_SERVICE_USER_TOKEN: "server-only-secret" } as NodeJS.ProcessEnv;

describe("the verification-check cookie", () => {
  test("a value made by the server matches for that user and that browser only", () => {
    const value = verificationCheckValue("user-1", "fp-1", env);
    expect(verificationCheckMatches(value, "user-1", "fp-1", env)).toBe(true);
    expect(verificationCheckMatches(value, "user-2", "fp-1", env)).toBe(false);
    expect(verificationCheckMatches(value, "user-1", "fp-2", env)).toBe(false);
  });

  test("what a browser can compute by itself is refused: the old plain hash of user id and fingerprint", () => {
    const forged = crypto.createHash("sha256").update("user-1:fp-1").digest("hex");
    expect(verificationCheckMatches(forged, "user-1", "fp-1", env)).toBe(false);
  });

  test("another server secret does not validate it", () => {
    const value = verificationCheckValue("user-1", "fp-1", env);
    expect(verificationCheckMatches(value, "user-1", "fp-1", { ZITADEL_SERVICE_USER_TOKEN: "other" } as NodeJS.ProcessEnv)).toBe(false);
  });

  test.each([undefined, "", "short", "x".repeat(64)])("cookie %j is refused", (cookie) => {
    expect(verificationCheckMatches(cookie, "user-1", "fp-1", env)).toBe(false);
  });

  test("a missing fingerprint or user is refused", () => {
    const value = verificationCheckValue("user-1", "fp-1", env);
    expect(verificationCheckMatches(value, "user-1", undefined, env)).toBe(false);
    expect(verificationCheckMatches(value, "", "fp-1", env)).toBe(false);
  });

  test("without a server secret nothing is ever verified, and nothing can be issued", () => {
    const value = verificationCheckValue("user-1", "fp-1", env);
    expect(verificationCheckMatches(value, "user-1", "fp-1", {} as NodeJS.ProcessEnv)).toBe(false);
    expect(() => verificationCheckValue("user-1", "fp-1", {} as NodeJS.ProcessEnv)).toThrow();
  });
});
