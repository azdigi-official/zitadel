import { describe, expect, test } from "vitest";
import { DEFAULT_LOCALE, LANGS, parseAcceptLanguage, pickLocale } from "./i18n";

describe("pickLocale (AZDIGI)", () => {
  test("vi is the default and the first listed language", () => {
    expect(DEFAULT_LOCALE).toBe("vi");
    expect(LANGS[0].code).toBe("vi");
    expect(pickLocale(undefined)).toBe("vi");
    expect(pickLocale("")).toBe("vi");
  });

  test("vi wins whenever the browser lists it, at any position with q > 0", () => {
    expect(pickLocale("en-US,en;q=0.9,vi;q=0.8")).toBe("vi");
    expect(pickLocale("vi-VN,vi;q=0.9,en;q=0.8")).toBe("vi");
    expect(pickLocale("en,vi;q=0")).toBe("en");
  });

  test("otherwise the first supported entry by weight, else vi", () => {
    expect(pickLocale("en-US")).toBe("en");
    expect(pickLocale("fr;q=0.5,de;q=0.9")).toBe("de");
    expect(pickLocale("xx-YY,zz")).toBe("vi");
  });

  test("the cookie wins when it names a shipped locale", () => {
    expect(pickLocale("vi", "en")).toBe("en");
    expect(pickLocale("en-US", "vi")).toBe("vi");
    expect(pickLocale("en-US", "xx")).toBe("en");
  });

  test("parseAcceptLanguage sorts by q and keeps order for ties", () => {
    expect(parseAcceptLanguage("de;q=0.7, en, fr;q=0.7")).toEqual(["en", "de", "fr"]);
    expect(parseAcceptLanguage(null)).toEqual([]);
  });
});
