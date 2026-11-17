"use client";

import { Alert, AlertType } from "@/components/alert";
import { useTranslations } from "next-intl";
import { useEffect, useState } from "react";

// A one-time "this just happened" note carried across the sign-in that follows a registration. It lives in this tab's
// sessionStorage: it only chooses a sentence to show and is never trusted for anything else.
const KEY = "azdigi.account.notice";
const NOTICES = ["passkey"] as const;
type Notice = (typeof NOTICES)[number];

export function rememberAccountNotice(notice: Notice) {
  try {
    window.sessionStorage.setItem(KEY, notice);
  } catch {
    // private mode or storage disabled: the page simply shows no note
  }
}

export function AccountNotice() {
  const t = useTranslations("azdigiAccount");
  const [notice, setNotice] = useState<Notice | null>(null);

  useEffect(() => {
    try {
      const stored = window.sessionStorage.getItem(KEY);
      window.sessionStorage.removeItem(KEY);
      if (stored && (NOTICES as readonly string[]).includes(stored)) setNotice(stored as Notice);
    } catch {
      // nothing to show
    }
  }, []);

  if (!notice) return null;
  return (
    <div className="pb-4" data-testid="account-notice">
      <Alert type={AlertType.INFO}>{t(`notice.${notice}`)}</Alert>
    </div>
  );
}
