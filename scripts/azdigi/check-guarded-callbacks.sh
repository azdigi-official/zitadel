#!/usr/bin/env sh
# Fork policy: tokens are issued only through src/lib/azdigi/issue.ts. Any other call site of the raw Zitadel
# functions fails the check; lib/server/zitadel.ts only defines them.
set -eu
cd "$(dirname "$0")/../../apps/login/src"
if [ ! -f lib/azdigi/issue.ts ] || [ ! -f lib/server/zitadel.ts ]; then
  echo "lib/azdigi/issue.ts or lib/server/zitadel.ts is missing: the module layout changed, update this check" >&2
  exit 1
fi
hits=$(grep -rnE '\b(createCallback|createResponse|authorizeOrDenyDeviceAuthorization)\(' --include='*.ts' --include='*.tsx' . \
  | grep -v 'lib/azdigi/issue.ts' | grep -v 'lib/server/zitadel.ts' | grep -v '\.test\.' || true)
if [ -n "$hits" ]; then
  echo "direct token issuance outside lib/azdigi/issue.ts:" >&2
  echo "$hits" >&2
  exit 1
fi
echo "all token issuance goes through lib/azdigi/issue.ts"
