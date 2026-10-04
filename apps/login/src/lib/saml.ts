import { Cookie } from "@/lib/cookies";
import { getLoginSettings, ServiceConfig } from "@/lib/zitadel";
import { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { guardedCreateResponse, isPolicyRejected, redirectForVerdict } from "./azdigi/issue";
import { checkSessionPolicy } from "./session";

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
    // AZDIGI: refuse here with a precise next step instead of a blind sendLoginname
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
          return { redirect: url };
        } else if (url && binding.case === "post") {
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

        if (error && typeof error === "object" && "code" in error && error?.code === 9) {
          const loginSettings = await getLoginSettings({
            serviceConfig,
            organization: selectedSession.factors?.user?.organizationId,
          });

          if (loginSettings?.defaultRedirectUri) {
            return { redirect: loginSettings.defaultRedirectUri };
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
