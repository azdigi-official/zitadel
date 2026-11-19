# AZDIGI fork of Login V2

Branch `azdigi/v4.20` is built from upstream tag `v4.20.4` with the AZDIGI changes re-applied (the previous line,
`azdigi/v4.11` from `v4.11.0`, is kept for rollback). All AZDIGI changes stay inside `apps/login` (plus
`scripts/azdigi/` and `.github/workflows/azdigi-login.yml`). Rules, security-sensitive files, upgrade and release
procedure: `docs/login-fork-policy.md` in https://github.com/azdigi-official/azdigi-login. Plan:
`plans/261003-1608-m1-login-v2-fork/` in that repo.

Local image: `corepack pnpm install --frozen-lockfile && scripts/azdigi/make-image.sh zitadel-login:dev`.

## Security changes (M1 phase 4)

`src/lib/azdigi/` holds the policy that decides whether a session may receive tokens (`policy.ts`), the only token
wrapper (`issue.ts`), OTP-first eligibility (`otp-first.ts`, `org-lookup.ts`), the enrolment gate (`enrolment-guard.ts`)
and rate limits. AZDIGI server actions live in `src/lib/actions/azdigi/` and are listed in
`checks/server-actions.allowlist.json` (upstream's build check). Signed session cookies, the verification check and
OTP challenge sanitising are upstream's (`src/lib/server/session-cookie-signature.ts`, `verification-check.ts`,
`challenges.ts`). Upstream files only call into these; see `docs/login-otp-email-first.md` in the azdigi-login repo for the
full map and the unit matrix. Runtime env: `AZDIGI_OTP_FIRST_ORG_NAMES` (default `AZDIGI Customers`).
