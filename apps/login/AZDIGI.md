# AZDIGI fork of Login V2

Branch `azdigi/v4.11` tracks upstream tag `v4.11.0`. All AZDIGI changes stay inside `apps/login` (plus
`scripts/azdigi/` and `.github/workflows/azdigi-login.yml`). Rules, security-sensitive files, upgrade and release
procedure: `docs/login-fork-policy.md` in https://github.com/azdigi-official/azdigi-login. Plan:
`plans/261003-1608-m1-login-v2-fork/` in that repo.

Local image: `corepack pnpm install --frozen-lockfile && scripts/azdigi/make-image.sh zitadel-login:dev`.
