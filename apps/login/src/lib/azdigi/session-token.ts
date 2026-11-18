// AZDIGI: a session may only be read, changed, ended or listed with ITS OWN token.
//
// The login creates every session with its service token, and Zitadel v4.11 treats the creator of a session as
// authorised for it (measured on the local stack, 15/11/2026):
//   - GetSession without a session token returns the session (a wrong token is refused);
//   - SetSession and DeleteSession are accepted with a wrong or missing session token, and SetSession hands back a
//     NEW, valid session token;
//   - ListSessions by id returns any session.
// The session id and token the login uses come from the browser's `sessions` cookie, which the browser's owner can
// write freely. Without the checks below, a cookie naming someone else's session id (ids are time-based and appear in
// URLs) would let that browser read the session, and through an update obtain a working token for it.
//
// So every session call first requires a non-empty token, and every call Zitadel does not verify itself is preceded by
// a GetSession WITH the token, which Zitadel does verify. Rejections carry gRPC code 7 (permission denied), the code
// callers already treat as "not signed in".

/** gRPC PERMISSION_DENIED: what Zitadel answers to a wrong session token. */
export const SESSION_TOKEN_REJECTED = 7;

export class SessionTokenRequiredError extends Error {
  readonly code = SESSION_TOKEN_REJECTED;
  constructor() {
    super("session token required");
    this.name = "SessionTokenRequiredError";
  }
}

export function isSessionToken(token: unknown): token is string {
  return typeof token === "string" && token.length > 0 && token.length <= 200;
}

/** Throws unless a usable token came with the session id. */
export function requireSessionToken(token: unknown): asserts token is string {
  if (!isSessionToken(token)) {
    throw new SessionTokenRequiredError();
  }
}

type SessionReader<S> = (request: { sessionId: string; sessionToken: string }, options: object) => Promise<{ session?: S }>;

/**
 * Proves that `sessionToken` is the current token of `sessionId`: Zitadel refuses GetSession with a wrong token.
 * Call before any request Zitadel accepts from the session's creator without checking the token.
 */
export async function verifySessionToken<S>(getSession: SessionReader<S>, sessionId: string, sessionToken: unknown): Promise<S | undefined> {
  requireSessionToken(sessionToken);
  const response = await getSession({ sessionId, sessionToken }, {});
  return response.session;
}

/** how many of a browser's sessions are read back per request; the cookie puts the newest first */
export const MAX_SESSIONS_READ = 20;

/**
 * The sessions among `ids` that this browser really holds: each needs a cookie with a token Zitadel accepts for it.
 * Replaces listing by id, which would return anyone's session. A session that is gone or whose token is rejected is
 * left out; any other failure is thrown.
 */
export async function listSessionsByToken<S>(
  getSession: SessionReader<S>,
  ids: string[],
  cookies: { id?: unknown; token?: unknown }[],
): Promise<S[]> {
  const NOT_FOUND = 5;
  const tokens = new Map<string, unknown>();
  for (const cookie of cookies) {
    if (typeof cookie?.id === "string") tokens.set(cookie.id, cookie.token);
  }
  // the cookie is written by the browser: a stuffed one must not turn one request into hundreds of reads
  const found = await Promise.all(
    Array.from(new Set(ids)).slice(0, MAX_SESSIONS_READ).map(async (id) => {
      const token = tokens.get(id);
      if (!isSessionToken(token)) return undefined;
      try {
        return (await getSession({ sessionId: id, sessionToken: token }, {})).session;
      } catch (error) {
        const code = (error as { code?: unknown })?.code;
        if (code === NOT_FOUND || code === SESSION_TOKEN_REJECTED) return undefined;
        throw error;
      }
    }),
  );
  return found.filter((session): session is Awaited<S> => session !== undefined) as S[];
}
