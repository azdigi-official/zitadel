import { describe, expect, test } from "vitest";
import { enrolmentReturnTarget, enrolmentReturnUrl } from "./enrolment-return";

describe("the enrolment page to come back to after the second factor", () => {
  test.each([
    ["/passkey/set", "/passkey/set"],
    ["/passkey/set?prompt=true", "/passkey/set?prompt=true"],
    ["/otp/time-based/set", "/otp/time-based/set"],
    ["/otp/time-based/set?checkAfter=true", "/otp/time-based/set?checkAfter=true"],
    ["/u2f/set?checkAfter=true", "/u2f/set?checkAfter=true"],
  ])("accepts the known enrolment path %s", (value, expected) => {
    expect(enrolmentReturnTarget(value)).toBe(expected);
  });

  test.each([
    "https://evil.example/passkey/set",
    "//evil.example/passkey/set",
    "/\\evil.example",
    "passkey/set",
    "/account",
    "/loginname",
    "/passkey/set/../../account",
    "/passkey/set?prompt=false",
    "/passkey/set?checkAfter=true",
    "/passkey/set?prompt=true&prompt=true",
    "/passkey/set?prompt=true&loginName=victim",
    "/passkey/set?prompt=true=true",
    "/passkey/set?a?b",
    "/otp/email",
    "/PASSKEY/set",
    "/passkey/set%3Fprompt=true",
    "/passkey/set#x",
    "",
    undefined,
    ["/passkey/set"],
    "/passkey/set?" + "prompt=true&".repeat(20),
  ])("rejects anything else: %j", (value) => {
    expect(enrolmentReturnTarget(value)).toBeUndefined();
  });

  test("the return URL is rebuilt from the known path and the flow's own context", () => {
    expect(
      enrolmentReturnUrl("/passkey/set?prompt=true", { loginName: "a@b.vn", organization: "o1", requestId: "oidc_1" }),
    ).toBe("/passkey/set?prompt=true&loginName=a%40b.vn&organization=o1&requestId=oidc_1");
    expect(enrolmentReturnUrl("/otp/time-based/set", { loginName: "a@b.vn" })).toBe(
      "/otp/time-based/set?loginName=a%40b.vn",
    );
    expect(enrolmentReturnUrl("https://evil.example", { loginName: "a@b.vn" })).toBeUndefined();
  });
});
