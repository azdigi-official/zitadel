// AZDIGI account page (/account): what the signed-in user can sign in with. The account shown is always the user of a
// session this browser holds a cookie for and that satisfies the organisation's login policy; URL parameters only pick
// WHICH of the browser's own sessions, never which user. Read-only: nothing here changes a credential.
import { Client } from "@zitadel/client";
import { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { AuthFactorState } from "@zitadel/proto/zitadel/user/v2/user_pb";
import { AuthenticationMethodType, UserService } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { getAllSessions, getSessionCookieById } from "../cookies";
import { createServiceForHost } from "../service";
import { checkSessionPolicy, isSessionValid, loadMostRecentSession } from "../session";
import { getSession, listAuthenticationMethodTypes, ServiceConfig } from "../zitadel";
import { redirectForVerdict } from "./issue";

export type SecondFactor = "totp" | "u2f" | "otpEmail" | "otpSms";

export type AccountView = {
  userId: string;
  loginName: string;
  displayName: string;
  organizationId: string;
  /** names of the registered, usable passkeys; null when the list could not be read (shown as unknown, never as none) */
  passkeys: string[] | null;
  hasPassword: boolean;
  secondFactors: SecondFactor[];
};

export type AccountResult =
  | { kind: "ok"; account: AccountView }
  /** nobody is signed in in this browser (for the organisation asked for): start at the sign-in */
  | { kind: "signin" }
  /** someone is signed in but not far enough for the organisation's policy: continue at the missing step */
  | { kind: "continue"; url: string };

import type { AccountParams } from "./account-url";

export type { AccountParams } from "./account-url";

/** how many of the browser's sessions are looked at when the URL names none (a stuffed cookie must not fan out) */
const MAX_CANDIDATES = 5;

const SECOND_FACTORS: [AuthenticationMethodType, SecondFactor][] = [
  [AuthenticationMethodType.TOTP, "totp"],
  [AuthenticationMethodType.U2F, "u2f"],
  [AuthenticationMethodType.OTP_EMAIL, "otpEmail"],
  [AuthenticationMethodType.OTP_SMS, "otpSms"],
];

async function readSession(serviceConfig: ServiceConfig, cookie: { id: string; token: string }): Promise<Session | undefined> {
  // the wrapper refuses a missing token and Zitadel a wrong one (lib/azdigi/session-token.ts): a cookie that merely
  // names a session id yields nothing
  return getSession({ serviceConfig, sessionId: cookie.id, sessionToken: cookie.token }).then(
    (response) => response?.session,
    () => undefined,
  );
}

/**
 * The sessions the page may be about, best first: each is one of this browser's cookies, read back from Zitadel with
 * its own token. A session id or a login name narrows the choice; without either, every session of the browser is a
 * candidate (newest first), so a sign-in that was started and abandoned does not hide an older, complete one.
 */
async function sessionsOfThisBrowser(serviceConfig: ServiceConfig, params: AccountParams): Promise<Session[]> {
  if (params.sessionId) {
    const cookie = await getSessionCookieById({ sessionId: params.sessionId, organization: params.organization });
    const session = cookie ? await readSession(serviceConfig, cookie) : undefined;
    return session ? [session] : [];
  }
  if (params.loginName) {
    const session = await loadMostRecentSession({ serviceConfig, sessionParams: { loginName: params.loginName, organization: params.organization } });
    return session ? [session] : [];
  }
  const cookies = (await getAllSessions(true))
    .filter((cookie) => !params.organization || cookie.organization === params.organization)
    .sort((a, b) => Number(b.changeTs ?? 0) - Number(a.changeTs ?? 0))
    .slice(0, MAX_CANDIDATES);
  const sessions = await Promise.all(cookies.map((cookie) => readSession(serviceConfig, cookie)));
  return sessions.filter((session): session is Session => session !== undefined);
}

/** Registered passkeys by name. A registration that was started but never finished is not usable and not listed. */
async function passkeyNames(serviceConfig: ServiceConfig, userId: string): Promise<string[] | null> {
  try {
    const userService: Client<typeof UserService> = await createServiceForHost(UserService, serviceConfig);
    const response = await userService.listPasskeys({ userId });
    return (response.result ?? []).filter((passkey) => passkey.state === AuthFactorState.READY).map((passkey) => passkey.name);
  } catch (error) {
    console.warn("[azdigi] account: passkey list unavailable", { userId, code: (error as { code?: unknown })?.code });
    return null;
  }
}

export async function loadAccount({ serviceConfig, params }: { serviceConfig: ServiceConfig; params: AccountParams }): Promise<AccountResult> {
  const candidates = (await sessionsOfThisBrowser(serviceConfig, params)).filter((session) => {
    const user = session.factors?.user;
    // an application that names its organisation never sees another organisation's account (#46)
    return !!user?.id && (!params.organization || user.organizationId === params.organization);
  });

  // the same rule that decides whether a session may receive tokens: a half-authenticated session shows nothing
  let session: Session | undefined;
  for (const candidate of candidates) {
    if (await isSessionValid({ serviceConfig, session: candidate })) {
      session = candidate;
      break;
    }
  }
  if (!session) {
    // signed in, but not far enough (a first factor where the policy asks for more, an email code where the account
    // has a passkey): send the user to the step that is missing instead of back to the start, which would loop
    const pending = candidates[0];
    if (pending) {
      const verdict = await checkSessionPolicy({ serviceConfig, session: pending });
      if (!verdict.ok) {
        return { kind: "continue", url: redirectForVerdict(verdict, pending) };
      }
    }
    return { kind: "signin" };
  }
  const user = session.factors!.user!;

  const [methods, passkeys] = await Promise.all([
    listAuthenticationMethodTypes({ serviceConfig, userId: user.id }).then((response) => response.authMethodTypes ?? []),
    passkeyNames(serviceConfig, user.id),
  ]);

  return {
    kind: "ok",
    account: {
      userId: user.id,
      loginName: user.loginName,
      displayName: user.displayName || user.loginName,
      organizationId: user.organizationId,
      passkeys,
      hasPassword: methods.includes(AuthenticationMethodType.PASSWORD),
      secondFactors: SECOND_FACTORS.filter(([type]) => methods.includes(type)).map(([, name]) => name),
    },
  };
}
