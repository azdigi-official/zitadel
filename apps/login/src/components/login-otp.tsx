"use client";

import { completeFlowOrGetUrl } from "@/lib/actions/flow";
import { resetPassword } from "@/lib/actions/password";
import { updateOrCreateSession } from "@/lib/actions/session";
import { OtpChannel } from "@/lib/azdigi/otp-channel";
import { handleServerActionResponse } from "@/lib/client-utils";
import { create } from "@zitadel/client";
import { RequestChallengesSchema } from "@zitadel/proto/zitadel/session/v2/challenge_pb";
import { ChecksSchema } from "@zitadel/proto/zitadel/session/v2/session_service_pb";
import { LoginSettings } from "@zitadel/proto/zitadel/settings/v2/login_settings_pb";
import { useTranslations } from "next-intl";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";
import { useForm } from "react-hook-form";
import { Alert, AlertType } from "./alert";
import { AutoSubmitForm } from "./auto-submit-form";
import { OtpChannelPicker } from "./azdigi/otp-channel-picker";
import { BackButton } from "./back-button";
import { Button, ButtonVariants } from "./button";
import { TextInput } from "./input";
import { Spinner } from "./spinner";
import { Translated } from "./translated";

// either loginName or sessionId must be provided
type Props = {
  loginName?: string;
  sessionId?: string;
  requestId?: string;
  organization?: string;
  method: string;
  code?: string;
  loginSettings?: LoginSettings;
  /** AZDIGI: offer the password as an alternative when the code is the first factor (from the organisation's policy) */
  altPassword?: boolean;
  /** AZDIGI: offer the passkey as an alternative (from the organisation's policy) */
  altPasskey?: boolean;
  /** AZDIGI: channel choice (email · Zalo · SMS) when the user has a verified phone and SMS delivery is enabled */
  channels?: { current: OtpChannel; phoneMasked: string; available: OtpChannel[] };
};

type Inputs = {
  code: string;
};

export function LoginOTP({
  loginName,
  sessionId,
  requestId,
  organization,
  method,
  code,
  loginSettings,
  altPassword = false,
  altPasskey = false,
  channels,
}: Props) {
  const t = useTranslations("otp");

  const [error, setError] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [samlData, setSamlData] = useState<{ url: string; fields: Record<string, string> } | null>(null);
  // seconds until the server accepts another OTP SMS request
  const [resendCooldown, setResendCooldown] = useState<number>(0);
  const resendAvailableAt = useRef<number>(0);

  const router = useRouter();

  const initialized = useRef(false);
  // AZDIGI: the code request still in flight. It rotates the session token, and so does the password or passkey step; if
  // both run at once the browser can keep the older token, and every later page fails to read the session.
  const pendingChallenge = useRef<Promise<unknown> | null>(null);

  const { register, handleSubmit, formState } = useForm<Inputs>({
    mode: "onChange",
    defaultValues: {
      code: code ? code : "",
    },
  });

  // resolves to the error to show to the user, if any
  const updateSessionForOTPChallenge = useCallback(async (): Promise<string | undefined> => {
    let challenges;

    if (method === "email") {
      // the link in the email is built on the server
      challenges = create(RequestChallengesSchema, {
        otpEmail: {},
      });
    }

    if (method === "sms") {
      challenges = create(RequestChallengesSchema, {
        otpSms: {},
      });
    }

    let response;
    const request = updateOrCreateSession({
      loginName,
      sessionId,
      organization,
      challenges,
      requestId,
    });
    pendingChallenge.current = request;
    try {
      response = await request;
    } catch {
      return t("errors.couldNotRequestChallenge");
    } finally {
      if (pendingChallenge.current === request) pendingChallenge.current = null;
    }

    if (response && "retryAfterSeconds" in response && response.retryAfterSeconds) {
      // the code was either just sent or, if the server refused, sent moments ago (e.g. before a reload): the countdown covers both
      resendAvailableAt.current = Date.now() + response.retryAfterSeconds * 1000;
      setResendCooldown(response.retryAfterSeconds);
      return;
    }

    if (response && "error" in response && response.error) {
      // AZDIGI: a refused code request names where to continue (verification, password)
      if (response.redirect) {
        router.push(response.redirect);
      }
      return response.error;
    }
  }, [method, requestId, loginName, sessionId, organization, t, router]);

  useEffect(() => {
    if (resendCooldown <= 0) {
      return;
    }
    const timer = setTimeout(() => {
      // timers are throttled or suspended in background tabs, so catch up with the time that actually passed
      const remainingSeconds = Math.ceil((resendAvailableAt.current - Date.now()) / 1000);
      setResendCooldown(Math.max(Math.min(resendCooldown - 1, remainingSeconds), 0));
    }, 1000);
    return () => clearTimeout(timer);
  }, [resendCooldown]);

  useEffect(() => {
    if (!initialized.current && ["email", "sms"].includes(method) && !code) {
      initialized.current = true;
      setLoading(true);
      updateSessionForOTPChallenge()
        .then((challengeError) => {
          if (challengeError) {
            setError(challengeError);
          }
        })
        .finally(() => {
          setLoading(false);
        });
    }
  }, [updateSessionForOTPChallenge, method, code]);

  async function submitCode(values: Inputs, organization?: string) {
    setLoading(true);

    let body: any = {
      code: values.code,
      method,
    };

    if (organization) {
      body.organization = organization;
    }

    if (requestId) {
      body.requestId = requestId;
    }

    let checks;

    if (method === "sms") {
      checks = create(ChecksSchema, {
        otpSms: { code: values.code },
      });
    }
    if (method === "email") {
      checks = create(ChecksSchema, {
        otpEmail: { code: values.code },
      });
    }
    if (method === "time-based") {
      checks = create(ChecksSchema, {
        totp: { code: values.code },
      });
    }

    const response = await updateOrCreateSession({
      loginName,
      sessionId,
      organization,
      checks,
      requestId,
    })
      .catch(() => {
        setError(t("errors.couldNotVerifyCode"));
        return;
      })
      .finally(() => {
        setLoading(false);
      });

    if (response && "error" in response && response.error) {
      if (response.redirect) {
        router.push(response.redirect);
      }
      setError(response.error);
      return;
    }

    return response;
  }

  // AZDIGI: "forgot password" from the email-code page (the answer is the same whether or not the account exists)
  async function forgotPassword() {
    setError("");
    setLoading(true);
    const response = await resetPassword({ loginName: loginName ?? "", organization, requestId })
      .catch(() => ({ error: t("verify.errors.couldNotSendResetCode") }))
      .finally(() => setLoading(false));
    if (response && "error" in response && response.error) {
      setError(response.error);
      return;
    }
    const params = new URLSearchParams();
    if (loginName) params.append("loginName", loginName);
    if (organization) params.append("organization", organization);
    if (requestId) params.append("requestId", requestId);
    router.push("/password/set?" + params);
  }

  async function goTo(path: "/password" | "/passkey") {
    if (pendingChallenge.current) {
      setLoading(true);
      await pendingChallenge.current.catch(() => undefined);
    }
    const params = new URLSearchParams();
    if (loginName) params.append("loginName", loginName);
    if (sessionId) params.append("sessionId", sessionId);
    if (organization) params.append("organization", organization);
    if (requestId) params.append("requestId", requestId);
    if (path === "/passkey" && altPassword) params.append("altPassword", "true");
    router.push(path + "?" + params);
  }

  function setCodeAndContinue(values: Inputs) {
    return submitCode(values, organization).then(async (response) => {
      if (response && "sessionId" in response) {
        setLoading(true);
        // Wait for 2 seconds to avoid eventual consistency issues with an OTP code being verified in the /login endpoint
        await new Promise((resolve) => setTimeout(resolve, 2000));

        // Use unified approach that handles both OIDC/SAML and regular flows
        if (response.factors?.user) {
          const callbackResponse = await completeFlowOrGetUrl(
            requestId && response.sessionId
              ? {
                  sessionId: response.sessionId,
                  requestId: requestId,
                  organization: response.factors?.user?.organizationId,
                }
              : {
                  loginName: response.factors.user.loginName,
                  organization: response.factors?.user?.organizationId,
                },
            loginSettings?.defaultRedirectUri,
          );
          setLoading(false);

          handleServerActionResponse(callbackResponse, router, setSamlData, setError);
        } else {
          setLoading(false);
        }
      }
    });
  }

  return (
    <>
      {samlData && <AutoSubmitForm url={samlData.url} fields={samlData.fields} />}
      <form className="w-full">
        {channels && ["email", "sms"].includes(method) && (
          <OtpChannelPicker
            current={channels.current}
            phoneMasked={channels.phoneMasked}
            available={channels.available}
            loginName={loginName}
            organization={organization}
            requestId={requestId}
            altPassword={altPassword}
            onError={setError}
          />
        )}
        {["email", "sms"].includes(method) && (
          <Alert type={AlertType.INFO}>
            <div className="flex flex-row">
              <span className="mr-auto flex-1 text-left">
                <Translated i18nKey="verify.noCodeReceived" namespace="otp" />
              </span>
              <button
                disabled={loading || resendCooldown > 0}
                type="button"
                className="text-primary-light-500 hover:text-primary-light-400 dark:text-primary-dark-500 hover:dark:text-primary-dark-400 ml-4 cursor-pointer disabled:cursor-default disabled:text-gray-400 dark:disabled:text-gray-700"
                onClick={async () => {
                  setError("");
                  setLoading(true);
                  const challengeError = await updateSessionForOTPChallenge();
                  if (challengeError) {
                    setError(challengeError);
                  }
                  setLoading(false);
                }}
                data-testid="resend-button"
              >
                {resendCooldown > 0 ? (
                  <Translated i18nKey="verify.resendCodeIn" namespace="otp" data={{ seconds: resendCooldown }} />
                ) : (
                  <Translated i18nKey="verify.resendCode" namespace="otp" />
                )}
              </button>
            </div>
          </Alert>
        )}
        <div className="mt-4">
          <TextInput
            type="text"
            autoFocus
            {...register("code", { required: t("verify.required.code") })}
            label={t("verify.labels.code")}
            autoComplete="one-time-code"
            data-testid="code-text-input"
          />
        </div>

        {error && (
          <div className="py-4" data-testid="error">
            <Alert>{error}</Alert>
          </div>
        )}

        <div className="mt-8 flex w-full flex-row items-center">
          {altPassword || altPasskey ? (
            <div className="flex flex-col items-start gap-1">
              <div className="flex flex-row gap-2">
                {altPasskey && (
                  <Button
                    type="button"
                    variant={ButtonVariants.Secondary}
                    onClick={() => goTo("/passkey")}
                    data-testid="passkey-button"
                  >
                    <Translated i18nKey="verify.usePasskey" namespace="otp" />
                  </Button>
                )}
                {altPassword && (
                  <Button
                    type="button"
                    variant={ButtonVariants.Secondary}
                    onClick={() => goTo("/password")}
                    data-testid="password-button"
                  >
                    <Translated i18nKey="verify.usePassword" namespace="otp" />
                  </Button>
                )}
              </div>
              {altPassword && (
                <button
                  type="button"
                  disabled={loading}
                  onClick={forgotPassword}
                  className="text-primary-light-500 dark:text-primary-dark-500 text-xs hover:underline disabled:text-gray-400"
                  data-testid="forgot-password-button"
                >
                  <Translated i18nKey="verify.forgotPassword" namespace="otp" />
                </button>
              )}
            </div>
          ) : (
            <BackButton data-testid="back-button" />
          )}
          <span className="flex-grow"></span>
          <Button
            type="submit"
            className="self-end"
            variant={ButtonVariants.Primary}
            disabled={loading || !formState.isValid}
            onClick={handleSubmit(setCodeAndContinue)}
            data-testid="submit-button"
          >
            {loading && <Spinner className="mr-2 h-5 w-5" />} <Translated i18nKey="verify.submit" namespace="otp" />
          </Button>
        </div>
      </form>
    </>
  );
}
