import { LANGUAGE_COOKIE_NAME, LANGUAGE_HEADER_NAME, pickLocale } from "@/lib/i18n";
import { getServiceConfig } from "@/lib/service-url";
import { getHostedLoginTranslation } from "@/lib/zitadel";
import { JsonObject } from "@zitadel/client";
import deepmerge from "deepmerge";
import { getRequestConfig } from "next-intl/server";
import { cookies, headers } from "next/headers";

export default getRequestConfig(async () => {
  const fallback = "en";
  const cookiesList = await cookies();
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  // AZDIGI: vi by default, cookie override, vi whenever the browser lists it (lib/i18n.ts)
  const locale = pickLocale(_headers.get(LANGUAGE_HEADER_NAME), cookiesList?.get(LANGUAGE_COOKIE_NAME)?.value);

  const i18nOrganization = _headers.get("x-zitadel-i18n-organization") || ""; // You may need to set this header in middleware

  let translations: JsonObject | {} = {};
  try {
    const i18nJSON = await getHostedLoginTranslation({ serviceConfig, locale,
      organization: i18nOrganization,
    });

    if (i18nJSON) {
      translations = i18nJSON;
    }
  } catch (error) {
    console.warn("Error fetching custom translations:", error);
  }

  const customMessages = translations;
  const localeMessages = (await import(`../../locales/${locale}.json`)).default;
  const fallbackMessages = (await import(`../../locales/${fallback}.json`))
    .default;

  return {
    locale,
    // AZDIGI: times on the screens (lockout ETA) in Vietnam's zone, not the container's
    timeZone: process.env.AZDIGI_TIME_ZONE || "Asia/Ho_Chi_Minh",
    messages: deepmerge.all([
      fallbackMessages,
      localeMessages,
      customMessages,
    ]) as Record<string, string>,
  };
});
