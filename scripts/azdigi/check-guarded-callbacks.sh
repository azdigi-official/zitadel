#!/usr/bin/env sh
# Fork policy: tokens are issued only through src/lib/azdigi/issue.ts. Until that wrapper lands (phase 4 of the
# AZDIGI plan) this check only reports; once the wrapper exists, any other call site fails the build.
set -eu
cd "$(dirname "$0")/../../apps/login/src"
if [ ! -f lib/azdigi/issue.ts ]; then
  echo "lib/azdigi/issue.ts not present yet — guard check skipped"
  exit 0
fi
hits=$(grep -rnE '\b(createCallback|createResponse|authorizeOrDenyDeviceAuthorization)\(' --include='*.ts' --include='*.tsx' . \
  | grep -v 'lib/azdigi/issue.ts' | grep -v 'lib/zitadel.ts' | grep -v '\.test\.' || true)
if [ -n "$hits" ]; then
  echo "direct token issuance outside lib/azdigi/issue.ts:" >&2
  echo "$hits" >&2
  exit 1
fi
echo "all token issuance goes through lib/azdigi/issue.ts"
