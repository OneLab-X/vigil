#!/usr/bin/env bash
# Upgrade to the version in this checkout's VERSION file (git pull / unpack the new release first).
#   deploy/scripts/upgrade.sh [--yes]
# Takes a backup, keeps the current images tagged for rollback, builds, migrates, health-gates.
source "$(dirname "$0")/lib.sh"
require_env
[ "${1:-}" = "--yes" ] && export ASSUME_YES=1
from="$(env_get VIGIL_VERSION)"; to="$(cat "$REPO_DIR/VERSION")"
info "upgrade $from -> $to"
[ "$from" = "$to" ] && warn "same version: images are rebuilt from this checkout"
confirm "Proceed (takes a backup and briefly stops writers)?" || die "aborted"

"$DEPLOY_DIR/scripts/backup.sh"
backup="$(ls -1d "$BACKUP_ROOT"/*/ | sort | tail -1)"
for img in api agents web; do
  docker image inspect "vigil/$img:$from" >/dev/null 2>&1 && docker tag "vigil/$img:$from" "vigil/$img:rollback-$from"
done
printf '%s\n' "$from" > "$backup/previous-version"

env_set VIGIL_VERSION "$to"
dc build
if dc up -d --wait --wait-timeout 300; then
  dc exec -T api node -e "fetch('http://127.0.0.1:8080/readyz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" || die "readiness failed — roll back with: deploy/scripts/rollback.sh $backup"
  ok "upgraded to $to (backup: $backup)"
else
  dc ps
  die "upgrade failed health checks — roll back with: deploy/scripts/rollback.sh $backup"
fi
