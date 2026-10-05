import { Alert } from "@/components/alert";
import { DynamicTheme } from "@/components/dynamic-theme";
import { LoginOTP } from "@/components/login-otp";
import { Translated } from "@/components/translated";
import { UserAvatar } from "@/components/user-avatar";
import { availableChannels, maskPhone, OTP_CHANNEL_METADATA_KEY, OtpChannel, phoneChannels } from "@/lib/azdigi/otp-channel";
import { decideOtpFirstForUser } from "@/lib/azdigi/otp-first";
import { hasVerifiedFirstFactor } from "@/lib/azdigi/policy";
import { getSessionCookieById } from "@/lib/cookies";
import { getPublicHost } from "@/lib/server/host";
import { getServiceConfig } from "@/lib/service-url";
import { loadMostRecentSession } from "@/lib/session";
import { getBrandingSettings, getLoginSettings, getSession, getUserByID, getUserMetadata } from "@/lib/zitadel";
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
  const host = getPublicHost(_headers);

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
    ? await loadSessionById(sessionId, organization)
    : await loadMostRecentSession({ serviceConfig, sessionParams: { loginName, organization } });

  async function loadSessionById(sessionId: string, organization?: string) {
    const recent = await getSessionCookieById({ sessionId, organization });

    if (!recent) {
      return undefined;
    }

    return getSession({ serviceConfig, sessionId: recent.id, sessionToken: recent.token }).then((response) => {
      if (response?.session) {
        return response.session;
      }
    });
  }

  const user = session?.factors?.user?.id
    ? await getUserByID({ serviceConfig, userId: session.factors.user.id })
        .then((resp) => resp.user)
        .catch(() => undefined)
    : undefined;
  const humanUser = user?.type.case === "human" ? user.type.value : undefined;

  // AZDIGI: a code as the first factor only for eligible users; everyone else is sent to the password page
  // (the server action enforces the same rule, this just avoids a dead screen)
  if (session?.factors?.user?.id && ["email", "sms"].includes(method ?? "") && !hasVerifiedFirstFactor(session)) {
    const decision = await decideOtpFirstForUser({
      serviceConfig,
      userId: session.factors.user.id,
      organizationId: session.factors.user.organizationId,
      humanUser: user?.type.case === "human" ? user.type.value : undefined,
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
      redirect("/password?" + params);
    }
  }

  // AZDIGI: channel choice (email · Zalo · SMS) for users with a verified phone once SMS delivery is enabled
  let channels: { current: OtpChannel; phoneMasked: string; available: OtpChannel[] } | undefined;
  const phones = phoneChannels();
  if (session?.factors?.user?.id && phones.length > 0 && humanUser?.phone?.isVerified) {
    const stored = await getUserMetadata({ serviceConfig, userId: session.factors.user.id, key: OTP_CHANNEL_METADATA_KEY }).catch(
      () => undefined,
    );
    // the screen shows which channel is in use: /otp/sms carries zalo or sms (whatever was stored), /otp/email is email
    // a stored channel that is not offered any more is shown as the phone channel that does carry the code
    const phoneCurrent: OtpChannel = stored === "zalo" || stored === "sms" ? stored : "sms";
    const current: OtpChannel = method === "sms" ? (phones.includes(phoneCurrent) ? phoneCurrent : phones[0]!) : "email";
    channels = { current, phoneMasked: maskPhone(humanUser.phone.phone), available: availableChannels() };
  }

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
          <Translated
            i18nKey={session && !hasVerifiedFirstFactor(session) ? "verify.firstFactorTitle" : "verify.title"}
            namespace="otp"
          />
        </h1>
        {method === "time-based" && (
          <p className="ztdl-p">
            <Translated i18nKey="verify.totpDescription" namespace="otp" />
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
              i18nKey={session && !hasVerifiedFirstFactor(session) ? "verify.emailFirstDescription" : "verify.emailDescription"}
              namespace="otp"
            />
          </p>
        )}

        {!session && (
          <div className="py-4">
            <Alert>
              <Translated i18nKey="unknownContext" namespace="error" />
            </Alert>
          </div>
        )}

        {session && (
          <UserAvatar
            loginName={loginName ?? session.factors?.user?.loginName}
            displayName={session.factors?.user?.displayName}
            showDropdown
            searchParams={searchParams}
          ></UserAvatar>
        )}
      </div>

      <div className="w-full">
        {method && session && (
          <LoginOTP
            loginName={loginName ?? session.factors?.user?.loginName}
            sessionId={sessionId}
            requestId={requestId}
            organization={organization ?? session?.factors?.user?.organizationId}
            method={method}
            loginSettings={loginSettings}
            host={host}
            code={code}
            altPassword={altPassword === "true"}
            altPasskey={altPasskey === "true"}
            channels={channels}
          ></LoginOTP>
        )}
      </div>
    </DynamicTheme>
  );
}
