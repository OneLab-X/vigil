#!/usr/bin/env bash
# Roll back a failed or unwanted upgrade:  deploy/scripts/rollback.sh <pre-upgrade-backup-dir> [--yes]
# Migrations are forward-only, so rollback = previous images + the database/evidence from before the upgrade.
source "$(dirname "$0")/lib.sh"
require_env
dir="${1:-}"; [ -n "$dir" ] && [ -f "$dir/previous-version" ] || die "usage: rollback.sh <backup-dir made by upgrade.sh> [--yes]"
[ "${2:-}" = "--yes" ] && export ASSUME_YES=1
prev="$(cat "$dir/previous-version")"
for img in api agents web; do
  if docker image inspect "vigil/$img:rollback-$prev" >/dev/null 2>&1; then docker tag "vigil/$img:rollback-$prev" "vigil/$img:$prev"
  else die "image vigil/$img:rollback-$prev not found; check out version $prev and run 'docker compose build' first"; fi
done
confirm "Roll back to $prev? Data written since the upgrade backup will be lost." || die "aborted"
dc stop web api worker agents >/dev/null 2>&1 || true
env_set VIGIL_VERSION "$prev"
ASSUME_YES=1 "$DEPLOY_DIR/scripts/restore.sh" "$dir"
ok "rolled back to $prev"
