#!/usr/bin/env bash
# Build the AZDIGI login image locally the same way the release workflow does.
#   scripts/azdigi/make-image.sh [image-tag]      (default zitadel-login:dev)
# Steps: proto generate → Next standalone build (build-time env from apps/login/azdigi-image.vars) → docker build apps/login.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/../.."
TAG="${1:-zitadel-login:dev}"
LOG="${AZDIGI_BUILD_LOG:-/tmp/azdigi-login-image.log}"
: > "$LOG"
{
  echo "== generate"; time corepack pnpm nx run-many --target generate --skip-nx-cache
  echo "== next build"; set -a; . apps/login/azdigi-image.vars; set +a; time corepack pnpm nx run @zitadel/login:build --skip-nx-cache
  echo "== docker build"; time docker build -t "$TAG" apps/login
} >> "$LOG" 2>&1
echo "image $TAG built; log: $LOG"
grep -E "^real" "$LOG"
docker image inspect "$TAG" --format 'size={{.Size}} user={{.Config.User}}'
