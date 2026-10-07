"use client";

import { BrandingSettings } from "@zitadel/proto/zitadel/settings/v2/branding_settings_pb";
import { useTranslations } from "next-intl";
import { usePathname } from "next/navigation";
import { Children, ReactNode } from "react";

/**
 * AZDIGI page frame: the same two-card layout as the AntiWHMCS sign-in and registration screens (GuestAuthFrame,
 * design system "soft-clay", #48): a navy brand card (logo, step-dependent message) and a white form card. On phones the
 * brand card shrinks to a strip (logo + title) above the form. Styling lives in styles/azdigi.scss under `.azdigi-auth`.
 *
 * Children follow DynamicTheme's convention: the first child is the page title/description, the second the form; a
 * single child goes into the form card as is.
 */

const AZDIGI_LOGO = `${process.env.NEXT_PUBLIC_BASE_PATH ?? ""}/azdigi/logo.png`;

export type FrameStep = "signin" | "signout" | "register" | "verify" | "password" | "setup" | "done" | "denied";

/** Which message the brand card shows for a route (the path is without the base path). */
export function frameStepFor(pathname: string | null): FrameStep {
  const path = pathname ?? "";
  if (path.startsWith("/denied")) return "denied";
  if (path.startsWith("/signedin") || path.startsWith("/logout/done")) return "done";
  if (path.startsWith("/logout")) return "signout";
  // set or reset a password (forgot password, or a password chosen at registration)
  if (path.startsWith("/password/set")) return "password";
  if (path.startsWith("/verify")) return "verify";
  if (path.startsWith("/register") || path.startsWith("/invite") || /^\/idp\/[^/]+\/complete-registration/.test(path)) return "register";
  if (/\/set(\/|$)/.test(path) || path.startsWith("/authenticator")) return "setup";
  return "signin";
}

const HIGHLIGHTS: Record<FrameStep, number> = { signin: 3, signout: 0, register: 3, verify: 0, password: 0, setup: 2, done: 0, denied: 0 };

export function AuthFrame({ branding, children }: { branding?: BrandingSettings; children: ReactNode }) {
  const t = useTranslations("azdigiFrame");
  const step = frameStepFor(usePathname());
  const logo = branding?.lightTheme?.logoUrl || AZDIGI_LOGO;

  const parts = Children.toArray(children);
  const heading = parts.length > 1 ? parts[0] : null;
  const form = parts.length > 1 ? parts[1] : parts[0];

  return (
    <div className="azdigi-auth" data-frame-step={step}>
      <div className="azdigi-auth__grid">
        <aside className="azdigi-auth__brand" aria-label={t(`${step}.eyebrow`)}>
          <div className="azdigi-auth__logo">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src={logo} alt="AZDIGI" width={152} height={34} />
          </div>
          <p className="azdigi-auth__eyebrow">{t(`${step}.eyebrow`)}</p>
          <p className="azdigi-auth__title">{t(`${step}.title`)}</p>
          <p className="azdigi-auth__description">{t(`${step}.description`)}</p>
          {HIGHLIGHTS[step] > 0 && (
            <ul className="azdigi-auth__highlights">
              {Array.from({ length: HIGHLIGHTS[step] }, (_, i) => (
                <li key={i}>{t(`${step}.highlight${i + 1}`)}</li>
              ))}
            </ul>
          )}
        </aside>

        <main className="azdigi-auth__main">
          <div className="azdigi-auth__card">
            {heading && <div className="azdigi-auth__heading">{heading}</div>}
            <div className="azdigi-auth__form">{form}</div>
          </div>
        </main>
      </div>
    </div>
  );
}
