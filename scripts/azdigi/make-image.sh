#!/usr/bin/env bash
# Build the AZDIGI login image locally the same way the release workflow does.
#   scripts/azdigi/make-image.sh [image-tag]      (default zitadel-login:dev)
# Steps: proto generate (AZDIGI_SKIP_GENERATE=1 to reuse) → Next standalone build (build-time env from apps/login/azdigi-image.vars;
# the build itself fails when the published server actions differ from apps/login/checks/server-actions.allowlist.json) → docker build apps/login.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/../.."
TAG="${1:-zitadel-login:dev}"
LOG="${AZDIGI_BUILD_LOG:-/tmp/azdigi-login-image.log}"
: > "$LOG"
{
  # AZDIGI_SKIP_GENERATE=1 reuses the protos already generated (buf.build rate-limits repeated generate runs)
  if [ "${AZDIGI_SKIP_GENERATE:-0}" = "1" ]; then echo "== generate skipped"; else echo "== generate"; time corepack pnpm nx run-many --target generate --skip-nx-cache; fi
  # the login target depends on generate; with AZDIGI_SKIP_GENERATE=1 that dependency is not re-run either
  EXTRA=""; [ "${AZDIGI_SKIP_GENERATE:-0}" = "1" ] && EXTRA="--excludeTaskDependencies"
  echo "== next build"; set -a; . apps/login/azdigi-image.vars; set +a
  # no retry: a "SecurityFatalError" stop means the pinned Next has a published advisory, so upgrade Next instead
  time corepack pnpm nx run @zitadel/login:build --skip-nx-cache $EXTRA
  echo "== docker build"; time docker build -t "$TAG" apps/login
} >> "$LOG" 2>&1
echo "image $TAG built; log: $LOG"
grep -E "^real" "$LOG"
docker image inspect "$TAG" --format 'size={{.Size}} user={{.Config.User}}'
