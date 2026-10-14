#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT=${DEPLOY_ROOT:-/mnt/ebs-data/services/artex}
REVISION=${1:?revision required}
export ARTEX_IMAGE=${2:?image required}
[[ "$REVISION" =~ ^[a-f0-9]{40}$ ]] || exit 2
[[ "$ARTEX_IMAGE" == "127.0.0.1:15000/artex/app:$REVISION" ]] || exit 2
RELEASE=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$ROOT"
exec 9>"$ROOT/deploy.lock"
flock -n 9
cd "$ROOT"
test -s .env
if [[ -s image.env && -s docker-compose.yml ]]; then
    # Back up the previous version, not the incoming image.
    env -u ARTEX_IMAGE DEPLOY_ROOT="$ROOT" bash "$RELEASE/deploy/backup.sh"
fi
cp "$RELEASE/docker-compose.prod.yml" docker-compose.yml
compose=(docker compose --env-file .env -f docker-compose.yml)
"${compose[@]}" config -q
"${compose[@]}" pull
ACTUAL=$(docker image inspect "$ARTEX_IMAGE" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')
test "$ACTUAL" = "$REVISION"
"${compose[@]}" up -d --no-build --no-recreate --wait --wait-timeout 120 postgres
"${compose[@]}" up -d --no-build --no-deps --wait --wait-timeout 240 artex
printf 'ARTEX_IMAGE=%s
' "$ARTEX_IMAGE" > image.env
printf '%s
' "$REVISION" > .runtime-revision
"${compose[@]}" ps
curl -fsS http://127.0.0.1:18500/api/health
curl -fsS http://127.0.0.1:18500/api/auth/status
