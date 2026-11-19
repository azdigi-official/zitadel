import "@/styles/globals.scss";
// AZDIGI design system (#48), after globals so it wins on equal specificity
import "@/styles/azdigi.scss";

import { FooterLinks } from "@/components/azdigi/footer-links";
import { BackgroundWrapper } from "@/components/background-wrapper";
import { LanguageProvider } from "@/components/language-provider";
import { Skeleton } from "@/components/skeleton";
import { ThemeProvider } from "@/components/theme-provider";
import * as Tooltip from "@radix-ui/react-tooltip";
import type { Metadata } from "next";
import { getLocale, getTranslations } from "next-intl/server";
import { Be_Vietnam_Pro } from "next/font/google";
import React, { Suspense } from "react";

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

  // AZDIGI: the language switcher sits in the form header (components/azdigi/auth-frame.tsx) and the theme is light
  // only, so the stock footer with both is not rendered
  return (
    <html lang={locale} className={`${beVietnamPro.className}`} suppressHydrationWarning>
      <head />
      <body>
        <ThemeProvider>
          <Tooltip.Provider>
            <Suspense
              fallback={
                <BackgroundWrapper className={`azdigi-page relative flex min-h-screen flex-col justify-center`}>
                  <div className="relative mx-auto w-full max-w-[440px] py-8">
                    <Skeleton>
                      <div className="h-40"></div>
                    </Skeleton>
                  </div>
                </BackgroundWrapper>
              }
            >
              <LanguageProvider>
                <BackgroundWrapper className={`azdigi-page relative flex min-h-screen flex-col justify-center`}>
                  <div className="azdigi-shell">
                    <div>{children}</div>
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
