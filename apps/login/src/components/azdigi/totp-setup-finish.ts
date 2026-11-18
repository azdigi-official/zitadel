"use client";

// AZDIGI: the code that just proved the new authenticator also proves the second factor of the sign-in in progress.
// Upstream sent the user to the code screen to type a second code right after the first, with nothing saying why.
import { completeFlowOrGetUrl, handleServerActionResponse } from "@/lib/client";
import { updateOrCreateSession } from "@/lib/server/session";
import { create } from "@zitadel/client";
import { ChecksSchema } from "@zitadel/proto/zitadel/session/v2/session_service_pb";
import { LoginSettings } from "@zitadel/proto/zitadel/settings/v2/login_settings_pb";

type Router = Parameters<typeof handleServerActionResponse>[1];
type SetSamlData = Parameters<typeof handleServerActionResponse>[2];
type SetError = Parameters<typeof handleServerActionResponse>[3];

/**
 * Checks the session with the set-up code and continues the sign-in. Returns false when that did not work (the code
 * expired meanwhile, the session is gone): the caller then shows the code screen, which explains what to do.
 */
export async function finishSignInWithSetupCode({
  code,
  loginName,
  sessionId,
  organization,
  requestId,
  loginSettings,
  router,
  setSamlData,
  setError,
}: {
  code: string;
  loginName?: string;
  sessionId?: string;
  organization?: string;
  requestId?: string;
  loginSettings?: LoginSettings;
  router: Router;
  setSamlData: SetSamlData;
  setError: SetError;
}): Promise<boolean> {
  const response = await updateOrCreateSession({
    loginName,
    sessionId,
    organization,
    checks: create(ChecksSchema, { totp: { code } }),
    requestId,
  }).catch(() => undefined);

  if (!response || !("sessionId" in response) || !response.factors?.user) {
    return false;
  }

  // the same pause the code screen takes: the check must be visible to the /login endpoint
  await new Promise((resolve) => setTimeout(resolve, 2000));

  const callbackResponse = await completeFlowOrGetUrl(
    requestId && response.sessionId
      ? { sessionId: response.sessionId, requestId, organization: response.factors.user.organizationId }
      : { loginName: response.factors.user.loginName, organization: response.factors.user.organizationId },
    loginSettings?.defaultRedirectUri,
  ).catch(() => undefined);
  if (!callbackResponse) {
    return false;
  }
  handleServerActionResponse(callbackResponse, router, setSamlData, setError);
  return true;
}
