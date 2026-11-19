/**
 * Reasons a relying system may give when the eligibility gateway (Identity Notifier, D-16) refuses a token. The RP
 * sends the customer to /denied?reason=<code>; only these codes have their own text, anything else is shown as the
 * generic message (the parameter is never reflected into the page).
 */
export const DENIED_REASONS = [
  "missing_email",
  "principal_not_found",
  "provider_identity_not_linked",
  "client_deleted",
  "client_user_inactive",
  "client_user_provider_locked",
  "client_user_provider_inactive",
  "client_banned",
  "membership_not_found",
  "client_user_invite_acceptance_required",
  "eligibility_unavailable",
] as const;
export type DeniedReason = (typeof DENIED_REASONS)[number] | "not_eligible";

/** Accepts the bare code or the `azdigi_ineligible:<code>` form the token endpoint returns. */
export function deniedReason(value: unknown): DeniedReason {
  const raw = typeof value === "string" ? value.replace(/^azdigi_ineligible:/, "") : "";
  return (DENIED_REASONS as readonly string[]).includes(raw) ? (raw as DeniedReason) : "not_eligible";
}
