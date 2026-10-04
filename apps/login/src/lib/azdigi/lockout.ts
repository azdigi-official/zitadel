/**
 * Account lockout as seen from the login. Zitadel locks a user after too many wrong passwords/codes and never
 * unlocks by itself (D-13); the Identity Notifier worker (M2) unlocks customers after 30′ and staff after 15′.
 * The screens only promise an unlock time while that worker is switched on (AZDIGI_UNLOCK_ETA_ENABLED=true).
 */
export type OrgKind = "customers" | "internal";

/** Messages Zitadel v4.11 returns for a locked user (observed 04/10/2026). */
export function isLockedMessage(raw: string | undefined): boolean {
  return !!raw && /Errors\.User\.Locked|User is locked|COMMAND-S6h4R|COMMAND-SF3fg|Errors\.User\.NotActive|SESSION-Gj4ko/i.test(raw);
}

export function unlockEtaEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.AZDIGI_UNLOCK_ETA_ENABLED === "true";
}

export function unlockWindowMinutes(orgKind: OrgKind, env: NodeJS.ProcessEnv = process.env): number {
  const raw = orgKind === "internal" ? env.AZDIGI_UNLOCK_MINUTES_INTERNAL : env.AZDIGI_UNLOCK_MINUTES_CUSTOMERS;
  const minutes = Number(raw);
  if (Number.isFinite(minutes) && minutes > 0) {
    return minutes;
  }
  return orgKind === "internal" ? 15 : 30;
}

/** Staff organisations force MFA; everything else is treated as a customer organisation. */
export function orgKindFromSettings(settings: { forceMfa?: boolean } | undefined): OrgKind {
  return settings?.forceMfa ? "internal" : "customers";
}

/**
 * Expected unlock time: the user's last change (the lock) plus the organisation's window. Undefined while the
 * worker is off, when the change date is unknown, or when the window has already passed (the worker will act).
 */
export function estimateUnlockAt(
  changeDate: Date | undefined,
  orgKind: OrgKind,
  now = new Date(),
  env: NodeJS.ProcessEnv = process.env,
): Date | undefined {
  if (!unlockEtaEnabled(env) || !changeDate || Number.isNaN(changeDate.getTime())) {
    return undefined;
  }
  const at = new Date(changeDate.getTime() + unlockWindowMinutes(orgKind, env) * 60_000);
  return at.getTime() > now.getTime() ? at : undefined;
}
