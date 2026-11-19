// AZDIGI: going to the next page after a server action.
//
// The sign-in steps are server actions that write the session cookie and return the next URL, which the form then
// pushes. Measured on 18/11/2026 (tools/e2e, browser CPU slowed 6x: 6 of 20 staff password steps; 1 of 20 at full
// speed; also on CI): the server finished and answered, the browser fetched the next page in full, and the page never
// changed. The user sees a "Continue" button that does nothing.
//
// Two measures. The push is issued in a later task than the action's continuation, so the router has applied the
// action's own result first (this alone cut the rate to a third). And if the address still has not changed after a few
// seconds, the browser loads the next page itself: a full page load cannot be dropped by the router.
const FALLBACK_AFTER_MS = 4000;

/** The URL a full page load needs: app-relative paths get the base path the router would add. */
export function absolutePathFor(url: string, basePath: string | undefined): string {
  if (!url.startsWith("/") || url.startsWith("//")) return url;
  const base = basePath ?? "";
  return base && !url.startsWith(base + "/") && url !== base ? base + url : url;
}

export function navigateAfterAction(router: { push: (url: string) => void }, url: string) {
  if (typeof window === "undefined") {
    router.push(url);
    return;
  }
  const before = window.location.href;
  setTimeout(() => router.push(url), 0);
  setTimeout(() => {
    if (window.location.href === before) {
      console.warn("[azdigi] the next page did not open; loading it directly");
      window.location.assign(absolutePathFor(url, process.env.NEXT_PUBLIC_BASE_PATH));
    }
  }, FALLBACK_AFTER_MS);
}
