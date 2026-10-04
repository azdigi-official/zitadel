import { create } from "@zitadel/client";
import { CreateCallbackRequestSchema, SessionSchema } from "@zitadel/proto/zitadel/oidc/v2/oidc_service_pb";
import { CreateResponseRequestSchema } from "@zitadel/proto/zitadel/saml/v2/saml_service_pb";
import { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import {
  authorizeOrDenyDeviceAuthorization,
  createCallback,
  createResponse,
  getLoginSettings,
  getSession,
  ServiceConfig,
} from "../zitadel";
import { isOtpFirstOrg } from "./org-lookup";
import { assertSessionSatisfiesPolicy, PolicyVerdict } from "./policy";

/**
 * The only place that asks Zitadel for tokens (OIDC callback, SAML response, device authorisation). Fork policy and
 * scripts/azdigi/check-guarded-callbacks.sh forbid calling the raw functions anywhere else. Each call re-reads the
 * session with its token and the organisation's login policy (uncached) and refuses with PolicyRejectedError.
 */

export type SessionRef = { sessionId: string; sessionToken: string };

export class PolicyRejectedError extends Error {
  constructor(
    readonly verdict: Exclude<PolicyVerdict, { ok: true }>,
    readonly session: Session | undefined,
  ) {
    super(`token issuance refused: ${verdict.reason}`);
    this.name = "PolicyRejectedError";
  }
}

export function isPolicyRejected(error: unknown): error is PolicyRejectedError {
  return error instanceof PolicyRejectedError || (!!error && typeof error === "object" && (error as any).name === "PolicyRejectedError");
}

export async function assertSessionMayReceiveTokens({
  serviceConfig,
  session,
}: {
  serviceConfig: ServiceConfig;
  session: SessionRef;
}): Promise<Session> {
  const loaded = await getSession({ serviceConfig, sessionId: session.sessionId, sessionToken: session.sessionToken })
    .then((r) => r?.session)
    .catch(() => undefined);
  const orgId = loaded?.factors?.user?.organizationId;
  const [loginSettings, otpFirstOrg] = await Promise.all([
    orgId ? getLoginSettings({ serviceConfig, organization: orgId, fresh: true }) : Promise.resolve(undefined),
    isOtpFirstOrg(serviceConfig, orgId),
  ]);
  const verdict = assertSessionSatisfiesPolicy({ session: loaded, loginSettings, otpFirstOrg });
  if (!verdict.ok) {
    console.warn("[azdigi] token issuance refused", {
      sessionId: session.sessionId,
      userId: loaded?.factors?.user?.id,
      organizationId: orgId,
      reason: verdict.reason,
    });
    throw new PolicyRejectedError(verdict, loaded);
  }
  return loaded as Session;
}

export async function guardedCreateCallback({
  serviceConfig,
  authRequestId,
  session,
}: {
  serviceConfig: ServiceConfig;
  authRequestId: string;
  session: SessionRef;
}) {
  await assertSessionMayReceiveTokens({ serviceConfig, session });
  return createCallback({
    serviceConfig,
    req: create(CreateCallbackRequestSchema, {
      authRequestId,
      callbackKind: { case: "session", value: create(SessionSchema, session) },
    }),
  });
}

export async function guardedCreateResponse({
  serviceConfig,
  samlRequestId,
  session,
}: {
  serviceConfig: ServiceConfig;
  samlRequestId: string;
  session: SessionRef;
}) {
  await assertSessionMayReceiveTokens({ serviceConfig, session });
  return createResponse({
    serviceConfig,
    req: create(CreateResponseRequestSchema, {
      samlRequestId,
      responseKind: { case: "session", value: session },
    }),
  });
}

export async function guardedDeviceAuthorization({
  serviceConfig,
  deviceAuthorizationId,
  session,
}: {
  serviceConfig: ServiceConfig;
  deviceAuthorizationId: string;
  session?: SessionRef;
}) {
  if (session) {
    await assertSessionMayReceiveTokens({ serviceConfig, session });
  }
  // without a session the request is denied by Zitadel
  return authorizeOrDenyDeviceAuthorization({ serviceConfig, deviceAuthorizationId, session });
}

/** Login-app path to continue at after a refusal, so callers never fall back to a blind sendLoginname. */
export function redirectForVerdict(
  verdict: Exclude<PolicyVerdict, { ok: true }>,
  session: Session | undefined,
  requestId?: string,
): string {
  const params = new URLSearchParams();
  const loginName = session?.factors?.user?.loginName;
  const organization = session?.factors?.user?.organizationId;
  if (loginName) params.append("loginName", loginName);
  if (organization) params.append("organization", organization);
  if (requestId) params.append("requestId", requestId);
  switch (verdict.next) {
    case "password":
      return loginName ? `/password?${params}` : `/loginname?${params}`;
    case "otpEmail":
      return loginName ? `/otp/email?${params}` : `/loginname?${params}`;
    case "mfa":
      return loginName ? `/mfa?${params}` : `/loginname?${params}`;
    default:
      return `/loginname?${params}`;
  }
}
