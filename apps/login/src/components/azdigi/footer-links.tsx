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
  ].filter((link): link is { href: string; label: string } => !!link.href);

  if (links.length === 0) {
    return null;
  }

  return (
    <nav
      aria-label="legal"
      className="mx-auto flex max-w-[440px] flex-wrap justify-center gap-x-4 gap-y-1 px-4 pb-4 text-xs text-text-light-secondary-500 dark:text-text-dark-secondary-500 md:max-w-full"
    >
      {links.map((link) => (
        <a key={link.href} href={link.href} target="_blank" rel="noreferrer" className="hover:underline">
          {link.label}
        </a>
      ))}
    </nav>
  );
}
