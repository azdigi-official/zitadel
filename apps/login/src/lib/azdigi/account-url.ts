// URLs of the AZDIGI account page. No server-only import here: client components reach this through lib/client.ts.

export type AccountParams = { loginName?: string; organization?: string; sessionId?: string };

/** Where a flow that did not start at an application ends: the account page of the session that just signed in. */
export function accountUrl(props: { sessionId?: string; loginName?: string; organization?: string }): string {
  const params = new URLSearchParams();
  if (props.loginName) params.set("loginName", props.loginName);
  if (props.sessionId) params.set("sessionId", props.sessionId);
  if (props.organization) params.set("organization", props.organization);
  return "/account?" + params;
}

/** Sign-in entry that leads back to the account page (no application request: the flow ends at /account). */
export function accountSignInUrl(params: AccountParams): string {
  const query = new URLSearchParams();
  if (params.loginName) query.set("loginName", params.loginName);
  if (params.organization) query.set("organization", params.organization);
  return "/loginname?" + query;
}
