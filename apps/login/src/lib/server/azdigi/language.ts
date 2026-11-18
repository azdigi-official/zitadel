"use server";

// AZDIGI: the only cookie the browser may ask the login to set by itself: the interface language, from the supported list.
import { LANGS, LANGUAGE_COOKIE_NAME } from "@/lib/i18n";
import { cookies } from "next/headers";

export async function setLanguageCookie(language: string) {
  if (typeof language !== "string" || !LANGS.some((lang) => lang.code === language)) {
    return;
  }
  const cookiesList = await cookies();
  cookiesList.set({ name: LANGUAGE_COOKIE_NAME, value: language, httpOnly: true, path: "/" });
}
