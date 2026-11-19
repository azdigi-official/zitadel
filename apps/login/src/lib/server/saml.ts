import "server-only";

import { guardedCreateResponse, isPolicyRejected, redirectForVerdict } from "@/lib/azdigi/issue";
import { isSafeRedirectUri } from "@/lib/client-utils";
import { Cookie } from "@/lib/server/cookies";
import { isClassifiedError } from "@/lib/server/grpc/interceptors/error-classification";
import { checkSessionPolicy } from "@/lib/server/session";
import { getLoginSettings, ServiceConfig } from "@/lib/server/zitadel";
import { Code } from "@zitadel/client";
import { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";

type LoginWithSAMLAndSession = {
  serviceConfig: ServiceConfig;
  samlRequest: string;
  sessionId: string;
  sessions: Session[];
  sessionCookies: Cookie[];
};

export async function loginWithSAMLAndSession({
  serviceConfig,
  samlRequest,
  sessionId,
  sessions,
  sessionCookies,
}: LoginWithSAMLAndSession): Promise<
  { error: string } | { redirect: string } | { samlData: { url: string; fields: Record<string, string> } }
> {
  console.log(`Login with session: ${sessionId} and samlRequest: ${samlRequest}`);

  const selectedSession = sessions.find((s) => s.id === sessionId);

  if (selectedSession && selectedSession.id) {
    // AZDIGI: an invalid session is never linked to the SAML request; refuse with the precise next step of the
    // organisation's policy. The token wrapper below re-checks with the session token anyway.
    const verdict = await checkSessionPolicy({ serviceConfig, session: selectedSession });

    if (!verdict.ok) {
      return { redirect: redirectForVerdict(verdict, selectedSession, `saml_${samlRequest}`) };
    }

    const cookie = sessionCookies.find((cookie) => cookie.id === selectedSession?.id);

    if (cookie && cookie.id && cookie.token) {
      const session = {
        sessionId: cookie?.id,
        sessionToken: cookie?.token,
      };

      // works not with _rsc request
      try {
        const { url, binding } = await guardedCreateResponse({ serviceConfig, samlRequestId: samlRequest, session });
        if (url && binding.case === "redirect") {
          if (!isSafeRedirectUri(url)) {
            console.warn("loginWithSAMLAndSession: Blocked unsafe SAML redirect URL:", url);
            return { error: "Unsafe redirect URI was blocked" };
          }
          return { redirect: url };
        } else if (url && binding.case === "post") {
          if (!isSafeRedirectUri(url)) {
            console.warn("loginWithSAMLAndSession: Blocked unsafe SAML post URL:", url);
            return { error: "Unsafe redirect URI was blocked" };
          }
          return {
            samlData: {
              url,
              fields: {
                RelayState: binding.value.relayState,
                SAMLResponse: binding.value.samlResponse,
              },
            },
          };
        } else {
          return { error: "An error occurred!" };
        }
      } catch (error: unknown) {
        if (isPolicyRejected(error)) {
          return { redirect: redirectForVerdict(error.verdict, error.session ?? selectedSession, `saml_${samlRequest}`) };
        }
        // handle already handled gracefully as these could come up if old emails with requestId are used (reset password, register emails etc.)
        console.error(error);

        if (isClassifiedError(error) && error.code === Code.FailedPrecondition) {
          const loginSettings = await getLoginSettings({
            serviceConfig,
            organization: selectedSession.factors?.user?.organizationId,
          });

          if (loginSettings?.defaultRedirectUri && isSafeRedirectUri(loginSettings.defaultRedirectUri)) {
            return { redirect: loginSettings.defaultRedirectUri };
          } else if (loginSettings?.defaultRedirectUri) {
            console.warn("loginWithSAMLAndSession: Unsafe defaultRedirectUri prevented:", loginSettings.defaultRedirectUri);
          }

          const signedinUrl = "/signedin";

          const params = new URLSearchParams();
          if (selectedSession.factors?.user?.loginName) {
            params.append("loginName", selectedSession.factors?.user?.loginName);
          }
          if (selectedSession.factors?.user?.organizationId) {
            params.append("organization", selectedSession.factors?.user?.organizationId);
          }
          return { redirect: signedinUrl + "?" + params.toString() };
        } else {
          return { error: "Unknown error occurred" };
        }
      }
    }
  }

  // If no session found or no valid cookie, return error
  return { error: "Session not found or invalid" };
}
