import { createSignedProof } from "@/lib/server/signed-proof";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import {
  isPasskeyRegistrationProofValid,
  PASSKEY_REGISTRATION_TTL_SECONDS,
  passkeyRegistrationProof,
} from "./passkey-registration-proof";

vi.mock("@/lib/server/fingerprint", () => ({ setBrowserCookie: vi.fn() }));

const SECRET = "a-test-secret-that-is-at-least-32-characters-long";
const NOW = 1_700_000_000_000;

describe("code-started passkey registration proof", () => {
  beforeEach(() => vi.stubEnv("ZITADEL_SESSION_COOKIE_SECRET", SECRET));
  afterEach(() => vi.unstubAllEnvs());

  test("is valid for the user and registration it was made for, until it expires", () => {
    const proof = passkeyRegistrationProof("u1", "p1", NOW);
    expect(isPasskeyRegistrationProofValid(proof, "u1", "p1", NOW)).toBe(true);
    expect(isPasskeyRegistrationProofValid(proof, "u1", "p1", NOW + (PASSKEY_REGISTRATION_TTL_SECONDS - 1) * 1000)).toBe(
      true,
    );
    expect(isPasskeyRegistrationProofValid(proof, "u1", "p1", NOW + PASSKEY_REGISTRATION_TTL_SECONDS * 1000)).toBe(false);
  });

  test("does not finish another user's or another registration", () => {
    const proof = passkeyRegistrationProof("u1", "p1", NOW);
    expect(isPasskeyRegistrationProofValid(proof, "u2", "p1", NOW)).toBe(false);
    expect(isPasskeyRegistrationProofValid(proof, "u1", "p2", NOW)).toBe(false);
    expect(isPasskeyRegistrationProofValid(undefined, "u1", "p1", NOW)).toBe(false);
    expect(isPasskeyRegistrationProofValid(proof, undefined, "p1", NOW)).toBe(false);
  });

  test("a proof made for another purpose (the verification check) is not accepted, nor a forged value", () => {
    const other = createSignedProof("verification-check", ["u1", "p1"], PASSKEY_REGISTRATION_TTL_SECONDS, NOW);
    expect(isPasskeyRegistrationProofValid(other, "u1", "p1", NOW)).toBe(false);
    const [version, expiresAt] = passkeyRegistrationProof("u1", "p1", NOW).split(".");
    expect(isPasskeyRegistrationProofValid(`${version}.${expiresAt}.forged`, "u1", "p1", NOW)).toBe(false);
  });
});
