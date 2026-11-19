"use client";

import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { EMAIL, SMS, TOTP, U2F } from "./auth-methods";

type Props = {
  loginName?: string;
  sessionId?: string;
  requestId?: string;
  organization?: string;
  userMethods: AuthenticationMethodType[];
  returnTo?: string;
};

export function ChooseSecondFactor({ loginName, sessionId, requestId, organization, userMethods, returnTo }: Props) {
  const params = new URLSearchParams({});
  // AZDIGI: the enrolment page to come back to after the factor (validated by the page, lib/azdigi/enrolment-return.ts)
  if (returnTo) {
    params.append("returnTo", returnTo);
  }

  if (loginName) {
    params.append("loginName", loginName);
  }
  if (sessionId) {
    params.append("sessionId", sessionId);
  }
  if (requestId) {
    params.append("requestId", requestId);
  }
  if (organization) {
    params.append("organization", organization);
  }

  return (
    <div className="grid w-full grid-cols-1 gap-5 pt-4">
      {userMethods.map((method, i) => {
        return (
          <div key={"method-" + i}>
            {method === AuthenticationMethodType.TOTP && TOTP(false, "/otp/time-based?" + params)}
            {method === AuthenticationMethodType.U2F && U2F(false, "/u2f?" + params)}
            {method === AuthenticationMethodType.OTP_EMAIL && EMAIL(false, "/otp/email?" + params)}
            {method === AuthenticationMethodType.OTP_SMS && SMS(false, "/otp/sms?" + params)}
          </div>
        );
      })}
    </div>
  );
}
