import { timestampDate } from "@zitadel/client";
import { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { LoginSettings, MultiFactorType, SecondFactorType } from "@zitadel/proto/zitadel/settings/v2/login_settings_pb";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";

/**
 * The single rule set that decides whether a Zitadel session may receive tokens. Zitadel itself issues tokens for any
 * session with a user check (M0 PoC), so this is enforced in the login app before every createCallback /
 * createResponse / device authorisation and inside isSessionValid. Everything here is pure and fail-closed.
 */

export type FactorKind = "password" | "passkey" | "u2f" | "idp" | "totp" | "otpEmail" | "otpSms";

export type RejectReason =
  | "no-user"
  | "expired"
  | "no-settings"
  | "no-first-factor"
  | "second-factor-missing"
  | "org-mismatch";

/** Where to send the user when a verdict rejects the session. */
export type NextStep = "loginname" | "password" | "otpEmail" | "mfa" | "mfaSetup" | "passkey";

/** `organization`: where to sign in instead (org-mismatch: the organisation the application asked for). */
export type PolicyVerdict = { ok: true } | { ok: false; reason: RejectReason; next: NextStep; organization?: string };

export type PolicyInput = {
  session: Session | undefined;
  loginSettings: LoginSettings | undefined;
  /** the user's organisation is allow-listed for OTP-first (see org-lookup.ts) */
  otpFirstOrg: boolean;
  /**
   * Authentication methods the user has registered (ListAuthenticationMethodTypes). A user who set up TOTP, a security
   * key or a passkey has asked for more than a mailbox: a code sent to the mailbox (or a password) alone must not be
   * enough for them. `undefined` = could not be read → fail closed.
   */
  registeredMethods: AuthenticationMethodType[] | undefined;
  now?: Date;
};

export function verifiedFactors(session: Session | undefined): Set<FactorKind> {
  const f = session?.factors;
  const out = new Set<FactorKind>();
  if (!f) {
    return out;
  }
  if (f.password?.verifiedAt) out.add("password");
  if (f.webAuthN?.verifiedAt) {
    out.add(f.webAuthN.userVerified ? "passkey" : "u2f");
  }
  if (f.intent?.verifiedAt) out.add("idp");
  if (f.totp?.verifiedAt) out.add("totp");
  if (f.otpEmail?.verifiedAt) out.add("otpEmail");
  if (f.otpSms?.verifiedAt) out.add("otpSms");
  return out;
}

/** A factor that proves the user on its own: password, user-verified passkey or an external IDP. */
export function hasVerifiedFirstFactor(session: Session | undefined): boolean {
  const f = verifiedFactors(session);
  return f.has("password") || f.has("passkey") || f.has("idp");
}

export function isSessionExpired(session: Session, now = new Date()): boolean {
  if (!session.expirationDate) {
    return false;
  }
  const expires = timestampDate(session.expirationDate).getTime();
  return Number.isNaN(expires) ? true : expires <= now.getTime();
}

function mfaRequired(factors: Set<FactorKind>, settings: LoginSettings): boolean {
  if (factors.has("passkey")) {
    // a user-verified passkey is possession + user verification; Zitadel treats it as multi-factor
    return false;
  }
  if (settings.forceMfa) {
    return true;
  }
  if (settings.forceMfaLocalOnly) {
    return factors.has("password") && !factors.has("idp");
  }
  return false;
}

function secondFactorSatisfied(factors: Set<FactorKind>, settings: LoginSettings): boolean {
  const second = settings.secondFactors ?? [];
  const multi = settings.multiFactors ?? [];
  return (
    (second.includes(SecondFactorType.OTP) && factors.has("totp")) ||
    (second.includes(SecondFactorType.U2F) && (factors.has("u2f") || factors.has("passkey"))) ||
    (second.includes(SecondFactorType.OTP_EMAIL) && factors.has("otpEmail")) ||
    (second.includes(SecondFactorType.OTP_SMS) && factors.has("otpSms")) ||
    (multi.includes(MultiFactorType.U2F_WITH_VERIFICATION) && factors.has("passkey"))
  );
}

/** The user's own strong factors that a weaker sign-in must not bypass. */
function strongRegistered(methods: AuthenticationMethodType[]): { mfa: boolean; passkey: boolean } {
  return {
    mfa: methods.includes(AuthenticationMethodType.TOTP) || methods.includes(AuthenticationMethodType.U2F),
    passkey: methods.includes(AuthenticationMethodType.PASSKEY),
  };
}

/** Second factors the /mfa chooser can offer (the same set checkMFAFactors considers). */
function hasSecondFactorRegistered(methods: AuthenticationMethodType[]): boolean {
  return [AuthenticationMethodType.TOTP, AuthenticationMethodType.U2F, AuthenticationMethodType.OTP_EMAIL, AuthenticationMethodType.OTP_SMS].some(
    (m) => methods.includes(m),
  );
}

function hasStrongVerified(factors: Set<FactorKind>): boolean {
  return factors.has("totp") || factors.has("u2f") || factors.has("passkey");
}

export function assertSessionSatisfiesPolicy({ session, loginSettings, otpFirstOrg, registeredMethods, now }: PolicyInput): PolicyVerdict {
  if (!session?.factors?.user?.id || !session.factors.user.verifiedAt) {
    return { ok: false, reason: "no-user", next: "loginname" };
  }
  if (isSessionExpired(session, now)) {
    return { ok: false, reason: "expired", next: "loginname" };
  }
  if (!loginSettings) {
    return { ok: false, reason: "no-settings", next: "loginname" };
  }

  const factors = verifiedFactors(session);
  const firstFactor = factors.has("password") || factors.has("passkey") || factors.has("idp");

  if (mfaRequired(factors, loginSettings)) {
    if (!firstFactor) {
      // OTP-first never applies where MFA is forced
      return { ok: false, reason: "no-first-factor", next: "password" };
    }
    if (!secondFactorSatisfied(factors, loginSettings)) {
      // nothing registered (never set up, or removed by an administrator): set one up instead of an empty chooser
      const next = registeredMethods && !hasSecondFactorRegistered(registeredMethods) ? "mfaSetup" : "mfa";
      return { ok: false, reason: "second-factor-missing", next };
    }
    return { ok: true };
  }

  if (firstFactor) {
    // a password (not a passkey or an IDP) does not override the TOTP / security key the user set up
    if (factors.has("password") && !factors.has("passkey") && !factors.has("idp")) {
      if (!registeredMethods) return { ok: false, reason: "no-settings", next: "loginname" };
      if (strongRegistered(registeredMethods).mfa && !hasStrongVerified(factors)) {
        return { ok: false, reason: "second-factor-missing", next: "mfa" };
      }
    }
    return { ok: true };
  }

  // no password/passkey/idp: only an allow-listed organisation may accept an OTP as the sole factor, and only the
  // OTP kinds its own policy lists as second factors
  if (otpFirstOrg) {
    const second = loginSettings.secondFactors ?? [];
    const otpEmailOk = second.includes(SecondFactorType.OTP_EMAIL) && factors.has("otpEmail");
    const otpSmsOk = second.includes(SecondFactorType.OTP_SMS) && factors.has("otpSms");
    if (otpEmailOk || otpSmsOk) {
      // whoever reads the mailbox / receives the SMS must not get past a TOTP, security key or passkey the user set up
      if (!registeredMethods) return { ok: false, reason: "no-settings", next: "loginname" };
      const strong = strongRegistered(registeredMethods);
      if ((strong.mfa || strong.passkey) && !hasStrongVerified(factors)) {
        return { ok: false, reason: "second-factor-missing", next: strong.mfa ? "mfa" : "passkey" };
      }
      return { ok: true };
    }
    return { ok: false, reason: "no-first-factor", next: "otpEmail" };
  }

  return { ok: false, reason: "no-first-factor", next: "password" };
}
