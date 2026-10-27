import { getServiceConfig } from "@/lib/service-url";
import { getLegalAndSupportSettings } from "@/lib/zitadel";
import { getTranslations } from "next-intl/server";
import { headers } from "next/headers";

/**
 * AZDIGI: terms / privacy / help links under every screen, read from the instance legal & support settings
 * (managed by foundation in the azdigi-login repo). Renders nothing while no link is configured.
 */
export async function FooterLinks() {
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);
  const t = await getTranslations("register");

  const legal = await getLegalAndSupportSettings({ serviceConfig }).catch(() => undefined);
  const links = [
    { href: legal?.tosLink, label: t("termsOfService") },
    { href: legal?.privacyPolicyLink, label: t("privacyPolicy") },
    { href: legal?.helpLink, label: t("help") },
    { href: legal?.supportEmail ? `mailto:${legal.supportEmail}` : undefined, label: legal?.supportEmail ?? "" },
  ].filter((link): link is { href: string; label: string } => !!link.href);

  return (
    <footer className="azdigi-footer">
      <p>© {new Date().getFullYear()} AZDIGI. All rights reserved.</p>
      <nav aria-label="legal" className="azdigi-footer__links">
        {links.map((link) => (
          <a
            key={link.href}
            href={link.href}
            target={link.href.startsWith("mailto:") ? undefined : "_blank"}
            rel="noreferrer"
            className="hover:underline"
          >
            {link.label}
          </a>
        ))}
      </nav>
    </footer>
  );
}
