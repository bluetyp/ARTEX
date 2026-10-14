#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT=${DEPLOY_ROOT:-/mnt/ebs-data/services/artex}
cd "$ROOT"
compose=(docker compose --env-file .env --env-file image.env -f docker-compose.yml)
OUT="$ROOT/backups/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"
RUNNING=$("${compose[@]}" ps --status running -q artex)
if [[ -n "$RUNNING" ]]; then
    "${compose[@]}" stop artex
    trap '"${compose[@]}" start artex >/dev/null' EXIT
fi
"${compose[@]}" exec -T postgres pg_dump -U artex -d artex -Fc > "$OUT/postgres.dump"
test -s "$OUT/postgres.dump"
"${compose[@]}" exec -T postgres pg_restore --list < "$OUT/postgres.dump" >/dev/null
tar -czf "$OUT/state.tar.gz" --exclude=state/postgres .env image.env docker-compose.yml state
tar -tzf "$OUT/state.tar.gz" >/dev/null
sha256sum "$OUT/postgres.dump" "$OUT/state.tar.gz" > "$OUT/SHA256SUMS"
echo "backup=$OUT"
