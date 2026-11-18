#!/usr/bin/env node
// AZDIGI: fails when the built login publishes a server action that is not on the list below.
//
// Next publishes EVERY export of a "use server" module the build reaches as an endpoint anyone can POST to, whether or
// not a page uses it. Helpers that trust their arguments (session cookie writers, mail senders with a link template,
// session creation with caller-chosen challenges) must therefore never live in such a module. This list is the public
// surface of the login; adding a name here is a security decision and needs a review of what the function trusts.
//
//   node scripts/azdigi/check-server-actions.mjs [path to server-reference-manifest.json]
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ALLOWED = {
  "lib/server/auth-flow.ts": ["completeAuthFlow"],
  "lib/server/azdigi/denied.ts": ["signOutEverywhereOnThisBrowser"],
  "lib/server/azdigi/language.ts": ["setLanguageCookie"],
  "lib/server/azdigi/otp-channel.ts": ["setOtpChannel"],
  "lib/server/device.ts": ["completeDeviceAuthorization"],
  // external IdPs are off in every AZDIGI organisation; these need an IdP intent only Zitadel can issue
  // validateIDPLinkingPermissions only answers whether an organisation's login policy allows an IdP: no account data
  "lib/server/idp-intent.ts": ["processIDPCallback", "validateIDPLinkingPermissions"],
  "lib/server/idp.ts": ["createNewSessionForLDAP", "createNewSessionFromIdpIntent", "redirectToIdp"],
  "lib/server/loginname.ts": ["sendLoginname"],
  "lib/server/oidc.ts": ["getDeviceAuthorizationRequest"],
  "lib/server/passkeys.ts": ["registerPasskeyLink", "sendPasskey", "verifyPasskeyRegistration"],
  "lib/server/password.ts": ["changePassword", "checkSessionAndSetPassword", "resetPassword", "sendPassword"],
  "lib/server/register.ts": ["registerUser", "registerUserAndLinkToIDP"],
  "lib/server/session.ts": ["clearSession", "continueWithSession", "skipMFAAndContinueWithNextUrl", "updateOrCreateSession"],
  "lib/server/u2f.ts": ["addU2F", "verifyU2F"],
  "lib/server/verify.ts": ["resendVerification", "sendVerification", "verifyTOTP"],
};

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const manifestPath = process.argv[2] ?? path.join(root, "apps/login/.next/server/server-reference-manifest.json");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));

const published = new Map();
for (const entry of Object.values(manifest.node ?? {})) {
  const file = String(entry.filename ?? "?").replace(/^.*?src\//, "").replace(/^\.\//, "");
  const name = String(entry.exportedName ?? "?");
  // Next's own cache wrappers ("use cache") are not callable actions
  if (name.startsWith("$$RSC_SERVER_CACHE")) continue;
  if (!published.has(file)) published.set(file, new Set());
  published.get(file).add(name);
}

const unexpected = [];
for (const [file, names] of published) {
  for (const name of names) {
    if (!(ALLOWED[file] ?? []).includes(name)) unexpected.push(`${file}: ${name}`);
  }
}
const missing = [];
for (const [file, names] of Object.entries(ALLOWED)) {
  for (const name of names) {
    if (!published.get(file)?.has(name)) missing.push(`${file}: ${name}`);
  }
}

const total = [...published.values()].reduce((sum, names) => sum + names.size, 0);
if (unexpected.length) {
  console.error(`server actions: ${unexpected.length} published action(s) are not on the allow list:`);
  for (const line of unexpected.sort()) console.error(`  ${line}`);
  console.error("Move the function to a module without \"use server\", or review it and add it to scripts/azdigi/check-server-actions.mjs.");
  process.exit(1);
}
if (missing.length) console.warn(`server actions: on the allow list but not published (remove them from the list): ${missing.sort().join(", ")}`);
console.log(`server actions: ${total} published, all on the allow list`);
