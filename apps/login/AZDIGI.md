# AZDIGI fork of Login V2

Branch `azdigi/v4.11` tracks upstream tag `v4.11.0`. All AZDIGI changes stay inside `apps/login` (plus
`scripts/azdigi/` and `.github/workflows/azdigi-login.yml`). Rules, security-sensitive files, upgrade and release
procedure: `docs/login-fork-policy.md` in https://github.com/azdigi-official/azdigi-login. Plan:
`plans/261003-1608-m1-login-v2-fork/` in that repo.

Local image: `corepack pnpm install --frozen-lockfile && scripts/azdigi/make-image.sh zitadel-login:dev`.

## Security changes (M1 phase 4)

`src/lib/azdigi/` holds the policy that decides whether a session may receive tokens (`policy.ts`), the only token
wrapper (`issue.ts`), OTP-first eligibility (`otp-first.ts`, `org-lookup.ts`), server-built challenges and rate
limits. Upstream files only call into these; see `docs/login-otp-email-first.md` in the azdigi-login repo for the
full map and the unit matrix. Runtime env: `AZDIGI_OTP_FIRST_ORG_NAMES` (default `AZDIGI Customers`).
