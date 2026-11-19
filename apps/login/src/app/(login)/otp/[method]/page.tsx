import { Alert } from "@/components/alert";
import { DynamicTheme } from "@/components/dynamic-theme";
import { LoginOTP } from "@/components/login-otp";
import { Translated } from "@/components/translated";
import { UserAvatar } from "@/components/user-avatar";
import { decoyLoginName, decoyOrganization } from "@/lib/azdigi/decoy";
import { enrolmentReturnTarget } from "@/lib/azdigi/enrolment-return";
import { availableChannels, maskPhone, OTP_CHANNEL_METADATA_KEY, OtpChannel, phoneChannels } from "@/lib/azdigi/otp-channel";
import { decideOtpFirstForUser } from "@/lib/azdigi/otp-first";
import { hasVerifiedFirstFactor } from "@/lib/azdigi/policy";
import { getServiceConfig } from "@/lib/server/service-url";
import { loadMostRecentSession, loadSessionById } from "@/lib/server/session";
import { getBrandingSettings, getLoginSettings, getUserByID, getUserMetadata } from "@/lib/server/zitadel";
import { CheckCircleIcon } from "@heroicons/react/24/outline";
import { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { headers } from "next/headers";
import { redirect } from "next/navigation";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("otp");
  return { title: t("verify.title") };
}

export default async function Page(props: {
  searchParams: Promise<Record<string | number | symbol, string | undefined>>;
  params: Promise<Record<string | number | symbol, string | undefined>>;
}) {
  const params = await props.params;
  const searchParams = await props.searchParams;

  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  const {
    loginName, // send from password page
    requestId,
    sessionId,
    organization,
    code,
    altPassword,
    altPasskey,
  } = searchParams;

  const { method } = params;

  const session = sessionId
    ? await loadSessionById(serviceConfig, sessionId, organization)
    : await loadMostRecentSession({ serviceConfig, sessionParams: { loginName, organization } });

  const user = session?.factors?.user?.id
    ? await getUserByID({ serviceConfig, userId: session.factors.user.id })
        .then((resp) => resp.user)
        .catch(() => undefined)
    : undefined;
  const humanUser = user?.type.case === "human" ? user.type.value : undefined;

  // AZDIGI: a code as the first factor requires eligibility; new customers recover through verification, others use the
  // password (the server action enforces the same rule, this just avoids a dead screen)
  if (session?.factors?.user?.id && ["email", "sms"].includes(method ?? "") && !hasVerifiedFirstFactor(session)) {
    const decision = await decideOtpFirstForUser({
      serviceConfig,
      userId: session.factors.user.id,
      organizationId: session.factors.user.organizationId,
      humanUser,
      userState: user?.state,
    });
    if (!decision.eligible) {
      const params = new URLSearchParams({ loginName: loginName ?? session.factors.user.loginName });
      if (organization ?? session.factors.user.organizationId) {
        params.append("organization", organization ?? session.factors.user.organizationId);
      }
      if (requestId) {
        params.append("requestId", requestId);
      }
      if (decision.reason === "setup-required") {
        // no mail while rendering (upstream's rule: a link alone changes nothing); /verify offers to send the code
        params.set("invite", String(decision.invite));
        redirect("/verify?" + params);
      }
      redirect("/password?" + params);
    }
  }

  // AZDIGI: channel choice (email · Zalo · SMS) for users with a verified phone once SMS delivery is enabled
  let channels: { current: OtpChannel; phoneMasked: string; available: OtpChannel[] } | undefined;
  const phones = phoneChannels();
  if (session?.factors?.user?.id && phones.length > 0 && humanUser?.phone?.isVerified) {
    const stored = await getUserMetadata({
      serviceConfig,
      userId: session.factors.user.id,
      key: OTP_CHANNEL_METADATA_KEY,
    }).catch(() => undefined);
    // the screen shows which channel is in use: /otp/sms carries zalo or sms (whatever was stored), /otp/email is email;
    // a stored channel that is not offered any more is shown as the phone channel that does carry the code
    const phoneCurrent: OtpChannel = stored === "zalo" || stored === "sms" ? stored : "sms";
    const current: OtpChannel = method === "sms" ? (phones.includes(phoneCurrent) ? phoneCurrent : phones[0]!) : "email";
    channels = { current, phoneMasked: maskPhone(humanUser.phone.phone), available: availableChannels() };
  }

  // AZDIGI: an unknown name in a customer context lands here without a session (lib/azdigi/decoy.ts): render the same
  // first-factor screen as for a real customer. The first-factor screen never shows the account's display name.
  const decoy =
    !session && method === "email" && !!loginName && !sessionId && !!(await decoyOrganization(serviceConfig, organization));
  const firstFactor = decoy || (!!session && !hasVerifiedFirstFactor(session));
  // no session outside a customer context (staff with ignoreUnknownUsernames start without one): the password page
  if (!session && !decoy && method === "email" && loginName && !sessionId) {
    redirect(
      "/password?" +
        new URLSearchParams({ loginName, ...(organization && { organization }), ...(requestId && { requestId }) }),
    );
  }
  const justVerifiedEmail =
    method === "email" && firstFactor && searchParams.emailVerified === "true" && !!humanUser?.email?.isVerified;
  const shownLoginName = decoy && loginName ? decoyLoginName(loginName) : (loginName ?? session?.factors?.user?.loginName);
  const afterSetup = method === "time-based" && searchParams.afterSetup === "true";

  // email links do not come with organization, thus we need to use the session's organization
  const branding = await getBrandingSettings({
    serviceConfig,
    organization: organization ?? session?.factors?.user?.organizationId,
  });

  const loginSettings = await getLoginSettings({
    serviceConfig,
    organization: organization ?? session?.factors?.user?.organizationId,
  });

  return (
    <DynamicTheme branding={branding}>
      <div className="flex flex-col space-y-4">
        <h1>
          <Translated i18nKey={firstFactor ? "verify.firstFactorTitle" : "verify.title"} namespace="otp" />
        </h1>
        {justVerifiedEmail && (
          <div
            role="status"
            className="flex items-start gap-3 rounded-lg border border-green-600/20 bg-green-50 p-4 text-green-800 dark:bg-green-950/30 dark:text-green-200"
          >
            <CheckCircleIcon aria-hidden="true" className="h-5 w-5 shrink-0" />
            <span>
              <Translated i18nKey="verify.emailVerifiedTitle" namespace="otp" />
            </span>
          </div>
        )}
        {/* AZDIGI: arriving from the authenticator set-up (its own code could not complete the sign-in): say what
            happened and why a code is asked again */}
        {afterSetup && (
          <div
            role="status"
            data-testid="totp-after-setup"
            className="flex items-start gap-3 rounded-lg border border-green-600/20 bg-green-50 p-4 text-green-800 dark:bg-green-950/30 dark:text-green-200"
          >
            <CheckCircleIcon aria-hidden="true" className="h-5 w-5 shrink-0" />
            <span>
              <Translated i18nKey="verify.totpAfterSetupTitle" namespace="otp" />
            </span>
          </div>
        )}
        {method === "time-based" && (
          <p className="ztdl-p">
            <Translated
              i18nKey={afterSetup ? "verify.totpAfterSetupDescription" : "verify.totpDescription"}
              namespace="otp"
            />
          </p>
        )}
        {method === "sms" && (
          <p className="ztdl-p">
            <Translated i18nKey="verify.smsDescription" namespace="otp" />
          </p>
        )}
        {method === "email" && (
          <p className="ztdl-p">
            <Translated
              i18nKey={
                justVerifiedEmail
                  ? "verify.afterVerificationDescription"
                  : firstFactor
                    ? "verify.emailFirstDescription"
                    : "verify.emailDescription"
              }
              namespace="otp"
            />
          </p>
        )}

        {!session && !decoy && (
          <div className="py-4">
            <Alert>
              {/* context was provided but the session could not be resolved (cookie missing, invalid or expired) */}
              <Translated i18nKey={loginName || sessionId ? "sessionExpired" : "unknownContext"} namespace="error" />
            </Alert>
          </div>
        )}

        {(session || decoy) && (
          <UserAvatar
            loginName={shownLoginName}
            displayName={firstFactor ? shownLoginName : session?.factors?.user?.displayName}
            showDropdown
            searchParams={searchParams}
          ></UserAvatar>
        )}
      </div>

      <div className="w-full">
        {method && (session || decoy) && (
          <LoginOTP
            loginName={shownLoginName}
            sessionId={sessionId}
            requestId={requestId}
            organization={organization ?? session?.factors?.user?.organizationId}
            method={method}
            loginSettings={loginSettings}
            code={code}
            altPassword={altPassword === "true"}
            altPasskey={altPasskey === "true"}
            channels={channels}
            returnTo={firstFactor ? undefined : enrolmentReturnTarget(searchParams.returnTo)}
          ></LoginOTP>
        )}
      </div>
    </DynamicTheme>
  );
}
