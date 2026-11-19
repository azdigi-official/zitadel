// AZDIGI: where to come back to after verifying the second factor that an enrolment page asked for.
//
// Adding a sign-in method needs the configured second factor verified in the session (upstream v4.20.5). The enrolment
// pages send the user to that factor's screen with `returnTo`; once the factor is verified, the code screen returns to
// the enrolment page. The value comes from the request, so it is never used as given: only one of the known enrolment
// paths, with only the flags those pages understand, is accepted, and the URL is rebuilt from those parts.
// No server-only import: the code screen (a client component) rebuilds the URL too.

const ENROLMENT_PATHS: Record<string, readonly string[]> = {
  "/passkey/set": ["prompt"],
  "/otp/time-based/set": ["checkAfter"],
  "/u2f/set": ["checkAfter"],
};

/**
 * The canonical return target for `value`, or undefined when it is not one of the known enrolment paths. Accepted:
 * a known path, optionally with its flags set to "true" (`/passkey/set?prompt=true`). Anything else (absolute URLs,
 * other paths, other parameters, encoded tricks) is rejected as a whole.
 */
export function enrolmentReturnTarget(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length > 64 || !value.startsWith("/") || value.startsWith("//")) {
    return undefined;
  }
  const [path, query = "", ...rest] = value.split("?");
  if (rest.length > 0 || !Object.prototype.hasOwnProperty.call(ENROLMENT_PATHS, path)) {
    return undefined;
  }
  const allowedFlags = ENROLMENT_PATHS[path];
  const flags: string[] = [];
  for (const part of query ? query.split("&") : []) {
    const [key, flagValue, ...extra] = part.split("=");
    if (extra.length > 0 || flagValue !== "true" || !allowedFlags.includes(key) || flags.includes(key)) {
      return undefined;
    }
    flags.push(key);
  }
  return flags.length
    ? `${path}?${flags
        .sort()
        .map((key) => `${key}=true`)
        .join("&")}`
    : path;
}

/** The enrolment page URL to go back to, with the flow's context (login name, organisation, application request). */
export function enrolmentReturnUrl(
  returnTo: string,
  context: { loginName?: string; organization?: string; requestId?: string },
): string | undefined {
  const target = enrolmentReturnTarget(returnTo);
  if (!target) {
    return undefined;
  }
  const [path, flags] = target.split("?");
  const params = new URLSearchParams(flags ?? "");
  if (context.loginName) params.set("loginName", context.loginName);
  if (context.organization) params.set("organization", context.organization);
  if (context.requestId) params.set("requestId", context.requestId);
  return `${path}?${params}`;
}
