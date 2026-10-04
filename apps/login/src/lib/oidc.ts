import { Cookie } from "@/lib/cookies";
import { getLoginSettings, ServiceConfig } from "@/lib/zitadel";
import { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { guardedCreateCallback, isPolicyRejected, redirectForVerdict } from "./azdigi/issue";
import { checkSessionPolicy } from "./session";

type LoginWithOIDCAndSession = {
  serviceConfig: ServiceConfig;
  authRequest: string;
  sessionId: string;
  sessions: Session[];
  sessionCookies: Cookie[];
};
export async function loginWithOIDCAndSession({
  serviceConfig,
  authRequest,
  sessionId,
  sessions,
  sessionCookies,
}: LoginWithOIDCAndSession): Promise<{ error: string } | { redirect: string }> {
  const selectedSession = sessions.find((s) => s.id === sessionId);

  if (selectedSession && selectedSession.id) {
    // AZDIGI: refuse here with a precise next step instead of a blind sendLoginname; the token wrapper below
    // re-checks with the session token anyway
    const verdict = await checkSessionPolicy({ serviceConfig, session: selectedSession });

    if (!verdict.ok) {
      return { redirect: redirectForVerdict(verdict, selectedSession, `oidc_${authRequest}`) };
    }

    const cookie = sessionCookies.find((cookie) => cookie.id === selectedSession?.id);

    if (cookie && cookie.id && cookie.token) {
      const session = {
        sessionId: cookie?.id,
        sessionToken: cookie?.token,
      };

      try {
        const { callbackUrl } = await guardedCreateCallback({ serviceConfig, authRequestId: authRequest, session });
        if (callbackUrl) {
          return { redirect: callbackUrl };
        } else {
          return { error: "An error occurred!" };
        }
      } catch (error: unknown) {
        if (isPolicyRejected(error)) {
          return { redirect: redirectForVerdict(error.verdict, error.session ?? selectedSession, `oidc_${authRequest}`) };
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
