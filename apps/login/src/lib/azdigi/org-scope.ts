import { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { getOrgsByDomain, ServiceConfig } from "../zitadel";

/**
 * Organisation scopes (`urn:zitadel:iam:org:id:{id}`, `urn:zitadel:iam:org:domain:primary:{domain}`) restrict who may
 * sign in to an application. Zitadel does not enforce them when the login asks for tokens: it issues them for any
 * session and puts the *requested* org into `urn:zitadel:iam:org:id` (measured 05/10/2026, #46). The login therefore
 * checks that the session's user belongs to a requested organisation before every OIDC callback.
 */

const ORG_ID_SCOPE = /^urn:zitadel:iam:org:id:([0-9]+)$/;
const ORG_DOMAIN_SCOPE = /^urn:zitadel:iam:org:domain:primary:(.+)$/;

/** Organisation ids named directly in the scopes (no lookup); empty when none. */
export function orgIdsInScopes(scopes: readonly string[] | undefined): string[] {
  return (scopes ?? []).map((s) => ORG_ID_SCOPE.exec(s)?.[1]).filter((id): id is string => !!id);
}

/**
 * The organisations a request admits, or `null` when it carries no organisation scope (anyone may sign in). A primary
 * domain that does not resolve to exactly one organisation admits nobody (fail closed).
 */
export async function requiredOrgIds(serviceConfig: ServiceConfig, scopes: readonly string[] | undefined): Promise<Set<string> | null> {
  const ids = new Set(orgIdsInScopes(scopes));
  const domains = (scopes ?? []).map((s) => ORG_DOMAIN_SCOPE.exec(s)?.[1]).filter((d): d is string => !!d);
  if (ids.size === 0 && domains.length === 0) return null;
  for (const domain of domains) {
    const orgs = await getOrgsByDomain({ serviceConfig, domain }).catch(() => undefined);
    if (orgs?.result?.length === 1 && orgs.result[0].id) ids.add(orgs.result[0].id);
  }
  return ids;
}

/** For SSO session selection: does the session's user belong to an organisation named in the scopes (ids only)? */
export function sessionInScopedOrg(session: Session, scopes: readonly string[] | undefined): boolean {
  const ids = orgIdsInScopes(scopes);
  return ids.length === 0 || ids.includes(session.factors?.user?.organizationId ?? "");
}
