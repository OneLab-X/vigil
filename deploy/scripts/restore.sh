#!/usr/bin/env bash
# Restore a backup made by backup.sh:  deploy/scripts/restore.sh <backup-dir> [--yes]
# Replaces the current database and bundled evidence store. Destructive; asks for confirmation.
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
usage() { cat <<EOF
Restore a backup made by backup.sh. REPLACES the current database and bundled evidence store.

Usage: $(basename "$0") <backup-dir> [--yes]
EOF
}
case "${1:-}" in -h|--help) usage; exit 0;; esac
dir=""
while [ $# -gt 0 ]; do case "$1" in --yes) export ASSUME_YES=1; shift;; -*) usage >&2; die "unknown option $1";; *) dir="$1"; shift;; esac; done
{ [ -n "$dir" ] && [ -f "$dir/manifest.json" ]; } || { usage >&2; die "backup directory with manifest.json required"; }
dir="$(cd "$dir" && pwd)"

info "verifying backup checksums"
for f in db.dump evidence.tar env; do
  [ -f "$dir/$f" ] || continue
  want=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['files'].get(sys.argv[2],''))" "$dir/manifest.json" "$f")
  [ "$want" = "$(sha256f "$dir/$f")" ] || die "checksum mismatch for $f — backup is corrupt or altered"
done
ok "checksums match"
confirm "This REPLACES the current Vigil database and evidence with the backup from $(basename "$dir"). Continue?" || die "aborted"

if [ ! -f "$ENV_FILE" ]; then cp "$dir/env" "$ENV_FILE"; chmod 600 "$ENV_FILE"; ok "restored deploy/.env from backup"
elif ! cmp -s "$dir/env" "$ENV_FILE"; then
  warn "deploy/.env differs from the backup's; using the backup's copy (the old one is saved as .env.pre-restore)"
  cp "$ENV_FILE" "$ENV_FILE.pre-restore"; cp "$dir/env" "$ENV_FILE"; chmod 600 "$ENV_FILE" "$ENV_FILE.pre-restore"
fi

info "stopping application services"
dc stop web api worker agents >/dev/null 2>&1 || true
dc up -d --wait postgres objectstore

info "restoring database"
dc exec -T postgres psql -U postgres -v ON_ERROR_STOP=1 -q -c "DROP DATABASE IF EXISTS vigil WITH (FORCE)" -c "CREATE DATABASE vigil OWNER vigil_owner"
dc exec -T postgres pg_restore -U postgres -d vigil --exit-on-error < "$dir/db.dump"
ok "database restored"

if [ -f "$dir/evidence.tar" ]; then
  if bundled_store; then
    info "restoring evidence store"
    dc stop objectstore >/dev/null
    dc run --rm --no-deps -T --entrypoint /bin/sh objectstore -c 'rm -rf /data/* && tar -C /data -xf -' < "$dir/evidence.tar"
    ok "evidence restored"
  else warn "backup has bundled evidence but deploy/.env points to external storage; evidence not restored"; fi
fi

info "starting services (migrations run automatically)"
dc up -d --wait --wait-timeout 300 || die "services did not become healthy — run diagnostics.sh"
info "verifying integrity"
dc exec -T api vigil-admin verify-audit
dc exec -T api vigil-admin verify-evidence --sample 200
ok "restore complete"
