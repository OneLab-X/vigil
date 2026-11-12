#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
usage() { cat <<EOF
Roll back a failed or unwanted upgrade to the version recorded in an upgrade backup.
Migrations are forward-only, so rollback = previous images + previous compose file + the database/evidence
from before the upgrade. Data written since that backup is lost.

Usage: $(basename "$0") [<pre-upgrade-backup-dir>] [--yes]
  default backup dir: the newest backup in $BACKUP_ROOT that was made by an upgrade
EOF
}
dir=""
while [ $# -gt 0 ]; do case "$1" in
  --yes) export ASSUME_YES=1; shift;;
  -h|--help) usage; exit 0;;
  -*) usage >&2; die "unknown option $1";;
  *) dir="$1"; shift;; esac; done
require_env
if [ -z "$dir" ]; then
  dir="$(find "$BACKUP_ROOT" -mindepth 2 -maxdepth 2 -name previous-version -print 2>/dev/null | sort | tail -1)"
  dir="${dir%/previous-version}"
fi
[ -n "$dir" ] && [ -f "$dir/previous-version" ] || die "no upgrade backup found; usage: rollback.sh <backup-dir made by upgrade.sh> [--yes]"
prev="$(cat "$dir/previous-version")"
[[ "$prev" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid previous version '$prev' in $dir"
info "rolling back to $prev using $dir"

for img in "${VIGIL_IMAGES[@]}"; do
  if docker image inspect "$(image_ref "$img" "rollback-$prev")" >/dev/null 2>&1; then
    docker tag "$(image_ref "$img" "rollback-$prev")" "$(image_ref "$img" "$prev")"
  elif [ "$INSTALL_MODE" = release ]; then
    : # pulled (and verified) below
  else
    die "image $(image_ref "$img" "rollback-$prev") not found; check out version $prev and run 'docker compose build' first"
  fi
done
confirm "Roll back to $prev? Data written since the upgrade backup will be lost." || die "aborted"
dc stop web api worker agents >/dev/null 2>&1 || true
if [ "$INSTALL_MODE" = release ] && [ -f "$dir/compose.yaml" ]; then
  cp "$DEPLOY_DIR/compose.yaml" "$DEPLOY_DIR/compose.yaml.rolled-back"
  cp "$dir/compose.yaml" "$DEPLOY_DIR/compose.yaml"
  printf '%s\n' "$prev" > "$DEPLOY_DIR/VERSION"
fi
env_set VIGIL_VERSION "$prev"
if [ "$INSTALL_MODE" = release ]; then
  dc pull --quiet || die "could not pull images for $prev"
  verify_signatures "$prev" || die "refusing to roll back to unverified images"
fi
ASSUME_YES=1 "$DEPLOY_DIR/scripts/restore.sh" "$dir"
ok "rolled back to $prev"
