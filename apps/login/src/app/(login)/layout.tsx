import "@/styles/globals.scss";
// AZDIGI design system (#48), after globals so it wins on equal specificity
import "@/styles/azdigi.scss";

import { FooterLinks } from "@/components/azdigi/footer-links";
import { BackgroundWrapper } from "@/components/background-wrapper";
import { LanguageProvider } from "@/components/language-provider";
import { LanguageSwitcher } from "@/components/language-switcher";
import { Skeleton } from "@/components/skeleton";
import { ThemeProvider } from "@/components/theme-provider";
import * as Tooltip from "@radix-ui/react-tooltip";
import { Be_Vietnam_Pro } from "next/font/google";
import React, { Suspense } from "react";
import type { Metadata } from "next";
import { getLocale, getTranslations } from "next-intl/server";

// AZDIGI: the AntiWHMCS typeface (#48); next/font downloads it at build time and serves it from the login (CSP font-src 'self')
const beVietnamPro = Be_Vietnam_Pro({
  weight: ["400", "500", "600", "700", "800", "900"],
  subsets: ["latin", "vietnamese"],
});

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("common");
  return { title: t("title") };
}

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const locale = await getLocale();

  return (
    <html lang={locale} className={`${beVietnamPro.className}`} suppressHydrationWarning>
      <head />
      <body>
        <ThemeProvider>
          <Tooltip.Provider>
            <Suspense
              fallback={
                <BackgroundWrapper
                  className={`relative flex min-h-screen flex-col justify-center azdigi-page`}
                >
                  <div className="relative mx-auto w-full max-w-[440px] py-8">
                    <Skeleton>
                      <div className="h-40"></div>
                    </Skeleton>
                  </div>
                </BackgroundWrapper>
              }
            >
              <LanguageProvider>
                <BackgroundWrapper
                  className={`relative flex min-h-screen flex-col justify-center azdigi-page`}
                >
                  <div className="relative mx-auto w-full max-w-[1200px] py-6">
                    <div>{children}</div>
                    {/* AZDIGI: light only, no theme switch (#48) */}
                    <div className="flex flex-row items-center justify-end space-x-4 py-2 px-4 md:px-6">
                      <LanguageSwitcher />
                    </div>
                    <FooterLinks />
                  </div>
                </BackgroundWrapper>
              </LanguageProvider>
            </Suspense>
          </Tooltip.Provider>
        </ThemeProvider>
      </body>
    </html>
  );
}
