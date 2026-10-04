export interface Lang {
  name: string;
  code: string;
}

export const LANGS: Lang[] = [
  {
    name: "Tiếng Việt",
    code: "vi",
  },
  {
    name: "English",
    code: "en",
  },
  {
    name: "Deutsch",
    code: "de",
  },
  {
    name: "Italiano",
    code: "it",
  },
  {
    name: "Español",
    code: "es",
  },
  {
    name: "Français",
    code: "fr",
  },
  {
    name: "Nederlands",
    code: "nl",
  },
  {
    name: "Polski",
    code: "pl",
  },
  {
    name: "简体中文",
    code: "zh",
  },
  {
    name: "Русский",
    code: "ru",
  },  
  {
    name: "Türkçe",
    code: "tr",
  },
  {
    name: "日本語",
    code: "ja",
  },
  {
    name: "Українська",
    code: "uk",
  },
  {
    name: "العربية",
    code: "ar",
  },
];

export const LANGUAGE_COOKIE_NAME = "NEXT_LOCALE";
export const LANGUAGE_HEADER_NAME = "accept-language";

// AZDIGI: Vietnamese first. The cookie wins; otherwise `vi` wins whenever the browser lists it at all (q > 0);
// otherwise the first Accept-Language entry we ship; otherwise `vi`. Missing keys fall back to `en` (request.ts).
export const DEFAULT_LOCALE = "vi";

export function parseAcceptLanguage(header: string | null | undefined): string[] {
  if (!header) {
    return [];
  }
  return header
    .split(",")
    .map((part, index) => {
      const [tag, ...params] = part.trim().split(";");
      const q = params.map((p) => p.trim()).find((p) => p.startsWith("q="));
      const weight = q ? Number(q.slice(2)) : 1;
      return { code: tag.trim().split("-")[0].toLowerCase(), weight: Number.isFinite(weight) ? weight : 0, index };
    })
    .filter((entry) => entry.code && entry.weight > 0)
    .sort((a, b) => b.weight - a.weight || a.index - b.index)
    .map((entry) => entry.code);
}

export function pickLocale(acceptLanguage: string | null | undefined, cookie?: string | null): string {
  const supported = LANGS.map((l) => l.code);
  if (cookie && supported.includes(cookie)) {
    return cookie;
  }
  const wanted = parseAcceptLanguage(acceptLanguage);
  if (wanted.includes(DEFAULT_LOCALE)) {
    return DEFAULT_LOCALE;
  }
  return wanted.find((code) => supported.includes(code)) ?? DEFAULT_LOCALE;
}
