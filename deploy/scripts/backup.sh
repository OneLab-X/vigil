#!/usr/bin/env bash
# Consistent backup: database + evidence + configuration.  deploy/scripts/backup.sh [--online]
# Default briefly stops api/worker (writers) so the database and evidence store match exactly.
source "$(dirname "$0")/lib.sh"
require_env
ONLINE=0; [ "${1:-}" = "--online" ] && ONLINE=1
ts="$(date -u +%Y%m%dT%H%M%SZ)"; dir="$BACKUP_ROOT/$ts"
umask 077; mkdir -p "$dir"
restart=()
if [ "$ONLINE" = 0 ]; then
  for s in api worker; do [ -n "$(dc ps -q --status running "$s")" ] && restart+=("$s"); done
  [ ${#restart[@]} -gt 0 ] && { info "pausing writers: ${restart[*]}"; dc stop "${restart[@]}" >/dev/null; }
fi
trap '[ ${#restart[@]} -gt 0 ] && dc start "${restart[@]}" >/dev/null' EXIT

info "dumping database"
dc exec -T postgres pg_dump -U postgres -Fc vigil > "$dir/db.dump"
if bundled_store; then
  info "archiving bundled evidence store"
  dc exec -T objectstore tar -C /data -cf - . > "$dir/evidence.tar"
else
  warn "external S3 evidence store: protect it with bucket versioning/replication (not included in this backup)"
fi
cp "$ENV_FILE" "$dir/env"
{
  printf '{"created_at":"%s","version":"%s","online":%s,"files":{' "$ts" "$(env_get VIGIL_VERSION)" "$([ "$ONLINE" = 1 ] && echo true || echo false)"
  first=1; for f in db.dump evidence.tar env; do [ -f "$dir/$f" ] || continue; [ $first = 1 ] || printf ','; first=0; printf '"%s":"%s"' "$f" "$(sha256f "$dir/$f")"; done
  printf '}}\n'
} > "$dir/manifest.json"
ok "backup written to $dir"
warn "it contains deploy/.env (database passwords and VIGIL_SECRET_KEY): store it encrypted and access-controlled"
