#!/usr/bin/env bash
# Collect installation diagnostics into a local archive. Nothing is uploaded anywhere.
# Secrets from deploy/.env and common credential patterns are masked; security event content is not collected.
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
usage() { cat <<EOF
Collect installation diagnostics into a local .tar.gz (secrets masked, no security event content).
Nothing is uploaded anywhere.

Usage: $(basename "$0")
EOF
}
case "${1:-}" in -h|--help) usage; exit 0;; esac
ts="$(date -u +%Y%m%dT%H%M%SZ)"; out="$DEPLOY_DIR/diagnostics-$ts"; umask 077; mkdir -p "$out"
redact() {
  local sed_args=(-E -e 's/(AKIA[0-9A-Z]{16})/AKIA****************/g' -e 's/(AIza[0-9A-Za-z_-]{35})/AIza****/g'
    -e 's/(sk-[A-Za-z0-9_-]{8})[A-Za-z0-9_-]+/\1****/g' -e 's/([Bb]earer )[A-Za-z0-9._~+\/=-]+/\1****/g'
    -e 's#(postgres://[^:]+:)[^@]+@#\1****@#g')
  if [ -f "$ENV_FILE" ]; then
    while IFS='=' read -r k v; do
      case "$k" in *PASSWORD*|*SECRET*|*TOKEN*|*_KEY|*API_KEY*) [ ${#v} -ge 6 ] && sed_args+=(-e "s#$(printf '%s' "$v" | sed 's/[.[\*^$#/]/\\&/g')#****#g");; esac
    done < <(grep -E '^[A-Z_]+=.' "$ENV_FILE")
  fi
  sed "${sed_args[@]}"
}
{ echo "collected: $ts"; uname -a; docker version --format 'docker {{.Server.Version}}' 2>&1; docker compose version 2>&1; echo "deploy files: $(target_version) ($INSTALL_MODE mode)"; } > "$out/versions.txt"
"$DEPLOY_DIR/scripts/preflight.sh" > "$out/preflight.txt" 2>&1 || true
if [ -f "$ENV_FILE" ]; then
  sed -E 's/^([A-Z_]*(PASSWORD|SECRET|TOKEN|_KEY|API_KEY)[A-Z_]*)=.+/\1=****/' "$ENV_FILE" > "$out/env.masked"
  dc ps -a > "$out/services.txt" 2>&1 || true
  dc exec -T api node -e "fetch('http://127.0.0.1:8080/readyz').then(r=>r.text()).then(console.log)" > "$out/readyz.json" 2>&1 || true
  dc logs --no-color --tail 400 2>&1 | redact > "$out/logs.txt" || true
  docker system df > "$out/docker-df.txt" 2>&1 || true
  dc exec -T postgres psql -U postgres -d vigil -Atc "select now(), pg_size_pretty(pg_database_size('vigil')), (select count(*) from drizzle.__drizzle_migrations)" > "$out/database.txt" 2>&1 \
    || dc exec -T postgres psql -U postgres -d vigil -Atc "select now(), pg_size_pretty(pg_database_size('vigil'))" > "$out/database.txt" 2>&1 || true
fi
tar -C "$DEPLOY_DIR" -czf "$out.tar.gz" "$(basename "$out")" && rm -rf "$out"
ok "diagnostics saved to $out.tar.gz (local only; review before sharing)"
