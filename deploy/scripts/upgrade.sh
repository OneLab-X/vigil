#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
usage() { cat <<EOF
Upgrade to the version these deploy files describe.
  source mode:  the checkout's VERSION (git pull / check out the new release first)
  release mode: the bundle's VERSION (use 'vigil upgrade --version X' to fetch a new bundle)
Takes a backup, keeps the current images tagged for rollback, gets new images, migrates, health-gates.

Usage: $(basename "$0") [--yes]
EOF
}
while [ $# -gt 0 ]; do case "$1" in
  --yes) export ASSUME_YES=1; shift;;
  -h|--help) usage; exit 0;;
  *) usage >&2; die "unknown option $1";; esac; done
require_env
from="$(env_get VIGIL_VERSION)"; to="$(target_version)"
info "upgrade $from -> $to ($INSTALL_MODE mode)"
if [ "$from" = "$to" ]; then
  if [ "$INSTALL_MODE" = source ]; then warn "same version: images are rebuilt from this checkout"; else warn "same version: images are re-pulled and verified"; fi
fi
confirm "Proceed (takes a backup and briefly stops writers)?" || die "aborted"

"$DEPLOY_DIR/scripts/backup.sh"
backup="$(latest_backup)"; [ -n "$backup" ] || die "backup not found in $BACKUP_ROOT"
for img in "${VIGIL_IMAGES[@]}"; do
  if docker image inspect "$(image_ref "$img" "$from")" >/dev/null 2>&1; then
    docker tag "$(image_ref "$img" "$from")" "$(image_ref "$img" "rollback-$from")"
  fi
done
printf '%s\n' "$from" > "$backup/previous-version"
printf '%s\n' "$INSTALL_MODE" > "$backup/previous-mode"
# Keep the compose file that ran the previous version so rollback can restore it exactly.
# (vigil upgrade swaps in the new bundle first and passes the old compose file via VIGIL_PREVIOUS_COMPOSE.)
if [ -n "${VIGIL_PREVIOUS_COMPOSE:-}" ] && [ -f "$VIGIL_PREVIOUS_COMPOSE" ]; then cp "$VIGIL_PREVIOUS_COMPOSE" "$backup/compose.yaml"
else cp "$DEPLOY_DIR/compose.yaml" "$backup/compose.yaml"; fi

env_set VIGIL_VERSION "$to"
if ! fetch_images "$to"; then
  env_set VIGIL_VERSION "$from"
  die "could not get images for $to; still on $from"
fi
if dc up -d --wait --wait-timeout 300; then
  readyz >/dev/null || die "readiness failed — roll back with: $DEPLOY_DIR/scripts/rollback.sh $backup"
  ok "upgraded to $to (backup: $backup)"
else
  dc ps
  die "upgrade failed health checks — roll back with: $DEPLOY_DIR/scripts/rollback.sh $backup"
fi
