import { TextQueryMethod } from "@zitadel/proto/zitadel/object/v2/object_pb";
import { OrganizationService } from "@zitadel/proto/zitadel/org/v2/org_service_pb";
import { createServiceForHost } from "../service";
import { ServiceConfig } from "../zitadel";

/**
 * Organisations whose users may sign in with an email code as the first factor. Resolved by name so no org id is
 * hard-coded; the login client may list organisations (checked on the local stack, 04/10/2026). Several name
 * queries would be AND-ed by the API, so names are looked up one at a time.
 */
export const DEFAULT_OTP_FIRST_ORG_NAMES = ["AZDIGI Customers"];

const CACHE_TTL_MS = 5 * 60 * 1000;
const FAILURE_TTL_MS = 30 * 1000;

type Cache = { ids: Set<string>; expiresAt: number };
const store = globalThis as typeof globalThis & { __azdigiOtpFirstOrgs?: Cache };

export function otpFirstOrgNames(env: NodeJS.ProcessEnv = process.env): string[] {
  const raw = env.AZDIGI_OTP_FIRST_ORG_NAMES;
  if (raw === undefined) {
    return DEFAULT_OTP_FIRST_ORG_NAMES;
  }
  return raw
    .split(",")
    .map((n) => n.trim())
    .filter(Boolean);
}

export async function resolveOtpFirstOrgIds(serviceConfig: ServiceConfig, now = Date.now()): Promise<Set<string>> {
  const cached = store.__azdigiOtpFirstOrgs;
  if (cached && cached.expiresAt > now) {
    return cached.ids;
  }
  const names = otpFirstOrgNames();
  try {
    const ids = new Set<string>();
    if (names.length > 0) {
      const orgService = await createServiceForHost(OrganizationService, serviceConfig);
      for (const name of names) {
        const resp = await orgService.listOrganizations(
          { queries: [{ query: { case: "nameQuery", value: { name, method: TextQueryMethod.EQUALS } } }] },
          {},
        );
        for (const org of resp.result ?? []) {
          ids.add(org.id);
        }
      }
    }
    store.__azdigiOtpFirstOrgs = { ids, expiresAt: now + CACHE_TTL_MS };
    return ids;
  } catch (error) {
    // fail closed: keep the last known set (or nobody) until the lookup works again
    console.warn("[azdigi] could not resolve OTP-first organisations", { names, error: String(error) });
    store.__azdigiOtpFirstOrgs = { ids: cached?.ids ?? new Set(), expiresAt: now + FAILURE_TTL_MS };
    return store.__azdigiOtpFirstOrgs.ids;
  }
}

export async function isOtpFirstOrg(serviceConfig: ServiceConfig, orgId: string | undefined): Promise<boolean> {
  if (!orgId) {
    return false;
  }
  const ids = await resolveOtpFirstOrgIds(serviceConfig);
  return ids.has(orgId);
}

export function clearOtpFirstOrgCache() {
  delete store.__azdigiOtpFirstOrgs;
}
