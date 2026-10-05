"use client";

import { Button, ButtonVariants } from "@/components/button";
import { signOutEverywhereOnThisBrowser } from "@/lib/server/azdigi/denied";
import { useTranslations } from "next-intl";
import { useRouter } from "next/navigation";
import { useState } from "react";

export function DeniedActions() {
  const t = useTranslations("denied");
  const router = useRouter();
  const [busy, setBusy] = useState(false);

  async function switchAccount() {
    setBusy(true);
    const result = await signOutEverywhereOnThisBrowser().catch(() => ({ redirect: "/loginname" }));
    router.push(result.redirect);
  }

  return (
    <div className="mt-8 flex w-full flex-row items-center">
      <span className="flex-grow"></span>
      <Button type="button" variant={ButtonVariants.Primary} disabled={busy} onClick={switchAccount} data-testid="denied-switch-account">
        {t("switchAccount")}
      </Button>
    </div>
  );
}
