"use client";

import { LanguageSwitcher } from "@/components/language-switcher";
import { BrandingSettings } from "@zitadel/proto/zitadel/settings/v2/branding_settings_pb";
import { Cloud, Globe2, Mail, PanelsTopLeft, Server, ShieldCheck } from "lucide-react";
import { useTranslations } from "next-intl";
import { usePathname } from "next/navigation";
import { Children, ReactNode } from "react";

/** Shared login shell. Authentication children remain owned by their original routes. */
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
  if (path.startsWith("/register") || path.startsWith("/invite") || /^\/idp\/[^/]+\/complete-registration/.test(path))
    return "register";
  if (/\/set(\/|$)/.test(path) || path.startsWith("/authenticator")) return "setup";
  return "signin";
}

const SERVICES = [
  { name: "Domain", icon: Globe2, position: "top-left" },
  { name: "Hosting", icon: PanelsTopLeft, position: "top-right" },
  { name: "Cloud", icon: Cloud, position: "middle-left" },
  { name: "VPS", icon: Server, position: "middle-right" },
  { name: "Email", icon: Mail, position: "bottom-left" },
  { name: "SSL", icon: ShieldCheck, position: "bottom-right" },
];

export function AuthFrame({ branding, children }: { branding?: BrandingSettings; children: ReactNode }) {
  const t = useTranslations("azdigiFrame");
  const pathname = usePathname();
  const step = frameStepFor(pathname);
  const isEntry = pathname === "/loginname" || pathname === "/";
  const logo = branding?.lightTheme?.logoUrl || AZDIGI_LOGO;
  const parts = Children.toArray(children);
  const heading = parts.length > 1 ? parts[0] : null;
  const form = parts.length > 1 ? parts.slice(1) : parts[0];

  return (
    <div className="azdigi-auth" data-frame-step={step}>
      <main className="azdigi-auth__grid">
        <section className="azdigi-auth__main">
          <header className="azdigi-auth__header">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img className="azdigi-auth__logo" src={logo} alt="AZDIGI" width={180} height={42} />
            <LanguageSwitcher />
          </header>
          <div className="azdigi-auth__card">
            {isEntry && (
              <div className="azdigi-auth__intro">
                <p className="azdigi-auth__title">{t("portal.title")}</p>
                <p>{t("portal.description")}</p>
              </div>
            )}
            {heading && <div className="azdigi-auth__heading">{heading}</div>}
            <div className="azdigi-auth__form">{form}</div>
          </div>
        </section>
        <aside className="azdigi-auth__ecosystem" aria-label={t("portal.ecosystem")}>
          <div className="azdigi-auth__orbit" aria-hidden="true" />
          <div className="azdigi-auth__diagram">
            <svg className="azdigi-auth__connections" viewBox="0 0 600 480" fill="none" aria-hidden="true">
              <path d="M180 80H260Q300 80 300 120V360Q300 400 260 400H180M420 80H340Q300 80 300 120M420 400H340Q300 400 300 360M120 240H480" />
              {[
                [180, 80],
                [420, 80],
                [120, 240],
                [480, 240],
                [180, 400],
                [420, 400],
              ].map(([cx, cy]) => (
                <circle key={`${cx}-${cy}`} cx={cx} cy={cy} r="4" />
              ))}
            </svg>
            <div className="azdigi-auth__service azdigi-auth__service--portal">
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img src={logo} alt="AZDIGI" width={136} height={32} />
              <span>AZDIGI Portal</span>
            </div>
            {SERVICES.map(({ name, icon: Icon, position }) => (
              <div key={name} className={`azdigi-auth__service azdigi-auth__service--${position}`}>
                <Icon aria-hidden="true" strokeWidth={1.6} />
                <span>{name}</span>
              </div>
            ))}
          </div>
          <p className="azdigi-auth__caption">{t("portal.caption")}</p>
        </aside>
      </main>
    </div>
  );
}
