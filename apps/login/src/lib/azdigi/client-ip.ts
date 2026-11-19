/**
 * Client IP for rate limiting. Cloudflare sets CF-Connecting-IP in production; the local Traefik sends a real
 * X-Forwarded-For. The right-most proxies are trusted upstream (Caddy `trusted_proxies`), so the first XFF entry
 * is the client. Returns undefined when nothing usable is present (the IP limiter is then skipped).
 */
export function clientIpFromHeaders(headers: { get(name: string): string | null }): string | undefined {
  const cf = headers.get("cf-connecting-ip")?.trim();
  if (cf) {
    return cf;
  }
  const xff = headers.get("x-forwarded-for");
  if (xff) {
    const first = xff.split(",")[0]?.trim();
    if (first) {
      return first;
    }
  }
  const real = headers.get("x-real-ip")?.trim();
  return real || undefined;
}
