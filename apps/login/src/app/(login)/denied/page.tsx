import { DeniedActions } from "@/components/azdigi/denied-actions";
import { DynamicTheme } from "@/components/dynamic-theme";
import { deniedReason } from "@/lib/azdigi/denied";
import { getServiceConfig } from "@/lib/service-url";
import { getBrandingSettings, getLegalAndSupportSettings } from "@/lib/zitadel";
import { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { headers } from "next/headers";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("denied");
  return { title: t("title") };
}

/**
 * AZDIGI: where a relying party sends the customer after its token request was refused by the eligibility gateway
 * (403 `azdigi_ineligible:<reason>`, D-16). The customer has already authenticated; the page explains why the
 * system refused (owner decision: specific reasons) and offers another account.
 */
export default async function Page(props: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const searchParams = await props.searchParams;
  const reason = deniedReason(searchParams.reason);

  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);
  const branding = await getBrandingSettings({ serviceConfig });
  const legal = await getLegalAndSupportSettings({ serviceConfig }).catch(() => undefined);
  const t = await getTranslations("denied");
  const supportEmail = legal?.supportEmail;

  return (
    <DynamicTheme branding={branding}>
      <div className="flex flex-col space-y-4">
        <h1>{t("title")}</h1>
        <p className="ztdl-p" data-testid="denied-reason" data-reason={reason}>
          {t(`reasons.${reason}`)}
        </p>
        {supportEmail && (
          <p className="ztdl-p text-sm">
            {t("support")}{" "}
            <a className="underline" href={`mailto:${supportEmail}`}>
              {supportEmail}
            </a>
          </p>
        )}
      </div>
      <div className="w-full">
        <DeniedActions />
      </div>
    </DynamicTheme>
  );
}
