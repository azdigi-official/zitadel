import { DEFAULT_LOCALE, LANGUAGE_COOKIE_NAME, LANGUAGE_HEADER_NAME, pickLocale } from "@/lib/i18n";
import { mergeMessages } from "@/lib/server/merge-messages";
import { getServiceConfig } from "@/lib/server/service-url";
import { getHostedLoginTranslation } from "@/lib/server/zitadel";
import { JsonObject } from "@zitadel/client";
import { getRequestConfig } from "next-intl/server";
import { cookies, headers } from "next/headers";

export default getRequestConfig(async () => {
  const fallback = "en";
  const cookiesList = await cookies();

  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  // AZDIGI: vi by default, cookie override, vi whenever the browser lists it (lib/i18n.ts pickLocale). The instance's
  // allowed-language list is not applied: Zitadel does not ship vi, so it would drop the default language.
  const defaultLanguage = DEFAULT_LOCALE;
  const locale = pickLocale(_headers.get(LANGUAGE_HEADER_NAME), cookiesList?.get(LANGUAGE_COOKIE_NAME)?.value);

  const i18nOrganization = _headers.get("x-zitadel-i18n-organization") || ""; // You may need to set this header in middleware

  let translations: JsonObject | Record<string, never> = {};
  try {
    const i18nJSON = await getHostedLoginTranslation({
      serviceConfig,
      locale,
      organization: i18nOrganization,
    });

    if (i18nJSON) {
      translations = i18nJSON;
    }
  } catch (error) {
    console.warn("Error fetching custom translations:", error);
  }

  const customMessages = translations;

  // Load locale messages, fall back to default language messages if locale not found
  let localeMessages;
  try {
    localeMessages = (await import(`../../locales/${locale}.json`)).default;
  } catch {
    try {
      localeMessages = (await import(`../../locales/${defaultLanguage}.json`)).default;
    } catch {
      localeMessages = (await import(`../../locales/${fallback}.json`)).default;
    }
  }

  const fallbackMessages = (await import(`../../locales/${fallback}.json`)).default;

  return {
    locale,
    // AZDIGI: times on the screens (lockout ETA) in Vietnam's zone, not the container's
    timeZone: process.env.AZDIGI_TIME_ZONE || "Asia/Ho_Chi_Minh",
    messages: mergeMessages(fallbackMessages, localeMessages, customMessages) as Record<string, string>,
  };
});
