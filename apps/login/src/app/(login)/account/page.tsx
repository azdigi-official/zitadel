// AZDIGI: "My account" — what the signed-in user can sign in with, and where to go next. Read-only overview; the
// account is always the user of one of this browser's own sessions (lib/azdigi/account.ts).
import { AccountNotice } from "@/components/azdigi/account-notice";
import { Button, ButtonVariants } from "@/components/button";
import { DynamicTheme } from "@/components/dynamic-theme";
import { UserAvatar } from "@/components/user-avatar";
import { loadAccount } from "@/lib/azdigi/account";
import { accountSignInUrl } from "@/lib/azdigi/account-url";
import { getServiceConfig } from "@/lib/service-url";
import { getBrandingSettings, getLoginSettings } from "@/lib/zitadel";
import { PasskeysType } from "@zitadel/proto/zitadel/settings/v2/login_settings_pb";
import { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { headers } from "next/headers";
import Link from "next/link";
import { redirect } from "next/navigation";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("azdigiAccount");
  return { title: t("title") };
}

function Section({ title, testId, children }: { title: string; testId: string; children: React.ReactNode }) {
  return (
    <section className="border-t border-divider-light py-4 dark:border-divider-dark" data-testid={testId}>
      <h2 className="mb-2 text-base font-semibold">{title}</h2>
      {children}
    </section>
  );
}

export default async function Page(props: { searchParams: Promise<Record<string | number | symbol, string | undefined>> }) {
  const searchParams = await props.searchParams;
  const params = { loginName: searchParams.loginName, organization: searchParams.organization, sessionId: searchParams.sessionId };

  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  const result = await loadAccount({ serviceConfig, params });
  if (result.kind === "continue") {
    // signed in but a step short of the organisation's policy: finish that step, which ends back here
    redirect(result.url);
  }
  if (result.kind === "signin") {
    // not signed in (or not fully): the ordinary sign-in, which ends back here when no application asked for it
    redirect(accountSignInUrl(params));
  }
  const { account } = result;

  const [t, branding, loginSettings] = await Promise.all([
    getTranslations("azdigiAccount"),
    getBrandingSettings({ serviceConfig, organization: account.organizationId }),
    getLoginSettings({ serviceConfig, organization: account.organizationId }),
  ]);

  const passkeysAllowed = loginSettings?.passkeysType === PasskeysType.ALLOWED;
  const passwordAllowed = loginSettings?.allowUsernamePassword !== false;
  const addPasskey = new URLSearchParams({ loginName: account.loginName, organization: account.organizationId });
  const signOut = new URLSearchParams({ organization: account.organizationId });

  return (
    <DynamicTheme branding={branding}>
      <div className="flex flex-col space-y-4">
        <h1>{t("title")}</h1>
        <p className="ztdl-p mb-6 block">{t("description")}</p>
        <UserAvatar loginName={account.loginName} displayName={account.displayName} showDropdown searchParams={searchParams} />
      </div>

      <div className="w-full">
        <AccountNotice />

        {passkeysAllowed && (
          <Section title={t("passkeys.title")} testId="account-passkeys">
            {account.passkeys === null ? (
              <p className="ztdl-p" data-testid="account-passkeys-unknown">{t("passkeys.unknown")}</p>
            ) : account.passkeys.length === 0 ? (
              <p className="ztdl-p" data-testid="account-passkeys-none">{t("passkeys.none")}</p>
            ) : (
              <ul className="space-y-1" data-testid="account-passkeys-list">
                {account.passkeys.map((name, index) => (
                  <li key={index} className="ztdl-p truncate" title={name}>
                    {name || t("passkeys.unnamed")}
                  </li>
                ))}
              </ul>
            )}
            <div className="mt-3">
              <Link href={"/passkey/set?" + addPasskey} data-testid="account-add-passkey">
                <Button type="button" variant={ButtonVariants.Secondary}>
                  {account.passkeys && account.passkeys.length > 0 ? t("passkeys.addAnother") : t("passkeys.add")}
                </Button>
              </Link>
            </div>
          </Section>
        )}

        {passwordAllowed && (
          <Section title={t("password.title")} testId="account-password">
            <p className="ztdl-p" data-testid={account.hasPassword ? "account-password-set" : "account-password-unset"}>
              {account.hasPassword ? t("password.set") : t("password.unset")}
            </p>
          </Section>
        )}

        <Section title={t("secondFactors.title")} testId="account-second-factors">
          {account.secondFactors.length === 0 ? (
            <p className="ztdl-p" data-testid="account-second-factors-none">{t("secondFactors.none")}</p>
          ) : (
            <ul className="space-y-1" data-testid="account-second-factors-list">
              {account.secondFactors.map((factor) => (
                <li key={factor} className="ztdl-p" data-testid={`account-factor-${factor}`}>
                  {t(`secondFactors.${factor}`)}
                </li>
              ))}
            </ul>
          )}
        </Section>

        <div className="mt-6 flex w-full flex-row items-center">
          <Link href={"/logout?" + signOut} data-testid="account-sign-out">
            <Button type="button" variant={ButtonVariants.Secondary}>
              {t("signOut")}
            </Button>
          </Link>
          <span className="flex-grow"></span>
          {loginSettings?.defaultRedirectUri && (
            <Link href={loginSettings.defaultRedirectUri} data-testid="account-continue">
              <Button type="button" variant={ButtonVariants.Primary}>
                {t("continue")}
              </Button>
            </Link>
          )}
        </div>
      </div>
    </DynamicTheme>
  );
}
