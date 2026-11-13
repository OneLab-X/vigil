#!/usr/bin/env bash
# First-time installation:  deploy/scripts/install.sh [--admin-email E --admin-name N --org O] [--yes]
source "$(dirname "$0")/lib.sh"
ADMIN_EMAIL=""; ADMIN_NAME=""; ORG=""
while [ $# -gt 0 ]; do case "$1" in
  --admin-email) ADMIN_EMAIL="$2"; shift 2;; --admin-name) ADMIN_NAME="$2"; shift 2;; --org) ORG="$2"; shift 2;;
  --yes) export ASSUME_YES=1; shift;; *) die "unknown option $1";; esac; done

"$DEPLOY_DIR/scripts/preflight.sh"

if [ -f "$ENV_FILE" ]; then
  info "using existing deploy/.env (secrets are not regenerated)"
else
  info "generating deploy/.env with random secrets"
  umask 077
  cp "$DEPLOY_DIR/env.template" "$ENV_FILE"; chmod 600 "$ENV_FILE"
  for k in $(grep -E '^[A-Z0-9_]+=__GENERATE_HEX32__$' "$ENV_FILE" | cut -d= -f1); do env_set "$k" "$(openssl rand -hex 32)"; done
  for k in $(grep -E '^[A-Z0-9_]+=__GENERATE__$' "$ENV_FILE" | cut -d= -f1); do env_set "$k" "$(openssl rand -hex 24)"; done
  ! grep -qE '^[A-Z0-9_]+=__GENERATE' "$ENV_FILE" || die "secret generation incomplete"
  env_set VIGIL_VERSION "$(cat "$REPO_DIR/VERSION")"
  # optional overrides from the environment at install time
  for k in VIGIL_WEB_PORT VIGIL_WEB_BIND VIGIL_WEB_ORIGIN GEMINI_API_KEY; do [ -n "${!k:-}" ] && env_set "$k" "${!k}"; done
  [ -n "${VIGIL_WEB_PORT:-}" ] && [ -z "${VIGIL_WEB_ORIGIN:-}" ] && env_set VIGIL_WEB_ORIGIN "http://localhost:$VIGIL_WEB_PORT"
  ok "deploy/.env written (mode 600). Back it up securely: it holds the key that decrypts stored credentials."
fi

info "building images (version $(env_get VIGIL_VERSION))"
dc build
info "starting services"
dc up -d --wait --wait-timeout 300 || { dc ps; die "services did not become healthy — run deploy/scripts/diagnostics.sh"; }
ok "all services healthy"
dc exec -T api node -e "fetch('http://127.0.0.1:8080/readyz').then(r=>r.json()).then(j=>{console.log(JSON.stringify(j));process.exit(j.ok?0:1)})" || die "readiness check failed"

has_users=$(dc exec -T api vigil-admin status | sed -n 's/.*"users":\([0-9]*\).*/\1/p')
if [ "${has_users:-0}" = 0 ]; then
  info "create the first administrator"
  [ -n "$ADMIN_EMAIL" ] || read -r -p "Administrator email: " ADMIN_EMAIL
  [ -n "$ADMIN_NAME" ] || read -r -p "Administrator name: " ADMIN_NAME
  [ -n "$ORG" ] || read -r -p "Organization name: " ORG
  dc exec -T api vigil-admin create-owner --email "$ADMIN_EMAIL" --name "$ADMIN_NAME" --org "$ORG"
else
  ok "users already exist; skipping administrator creation"
fi
info "Vigil is running at $(env_get VIGIL_WEB_ORIGIN) (bound to $(env_get VIGIL_WEB_BIND):$(env_get VIGIL_WEB_PORT))"
