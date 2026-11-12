#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
usage() { cat <<EOF
First-time installation (safe to re-run: existing .env and data are kept, secrets are never regenerated).

Usage: $(basename "$0") [--admin-email E --admin-name N --org O] [--yes] [--skip-preflight]

  --admin-email/--admin-name/--org  first owner account (prompted for if missing and a terminal is attached)
  --yes                             non-interactive; fail instead of prompting
  --skip-preflight                  skip deploy/scripts/preflight.sh (not recommended)

Mode: $INSTALL_MODE (source = build from this checkout, release = pull signed images; override with VIGIL_INSTALL_MODE)
EOF
}
ADMIN_EMAIL=""; ADMIN_NAME=""; ORG=""; PREFLIGHT=1
while [ $# -gt 0 ]; do case "$1" in
  --admin-email) ADMIN_EMAIL="${2:?--admin-email needs a value}"; shift 2;;
  --admin-name) ADMIN_NAME="${2:?--admin-name needs a value}"; shift 2;;
  --org) ORG="${2:?--org needs a value}"; shift 2;;
  --yes) export ASSUME_YES=1; shift;;
  --skip-preflight) PREFLIGHT=0; shift;;
  -h|--help) usage; exit 0;;
  *) usage >&2; die "unknown option $1";; esac; done

[ "$PREFLIGHT" = 1 ] && "$DEPLOY_DIR/scripts/preflight.sh"

if [ -f "$ENV_FILE" ]; then
  info "using existing $ENV_FILE (secrets are not regenerated)"
  chmod 600 "$ENV_FILE"
else
  info "generating $ENV_FILE with random secrets"
  umask 077
  cp "$DEPLOY_DIR/env.template" "$ENV_FILE"; chmod 600 "$ENV_FILE"
  while IFS= read -r k; do env_set "$k" "$(openssl rand -hex 32)"; done < <(grep -E '^[A-Z0-9_]+=__GENERATE_HEX32__$' "$ENV_FILE" | cut -d= -f1)
  while IFS= read -r k; do env_set "$k" "$(openssl rand -hex 24)"; done < <(grep -E '^[A-Z0-9_]+=__GENERATE__$' "$ENV_FILE" | cut -d= -f1)
  ! grep -qE '^[A-Z0-9_]+=__GENERATE' "$ENV_FILE" || die "secret generation incomplete"
  env_set VIGIL_VERSION "$(target_version)"
  # optional overrides from the environment at install time
  for k in VIGIL_WEB_PORT VIGIL_WEB_BIND VIGIL_WEB_ORIGIN VIGIL_IMAGE_REGISTRY GEMINI_API_KEY; do
    if [ -n "${!k:-}" ]; then env_set "$k" "${!k}"; fi
  done
  if [ -n "${VIGIL_WEB_PORT:-}" ] && [ -z "${VIGIL_WEB_ORIGIN:-}" ]; then env_set VIGIL_WEB_ORIGIN "http://localhost:$VIGIL_WEB_PORT"; fi
  ok "$ENV_FILE written (mode 600). Back it up securely: it holds the key that decrypts stored credentials."
fi

version="$(env_get VIGIL_VERSION)"
fetch_images "$version" || die "could not get images for $version"
info "starting services"
dc up -d --wait --wait-timeout 300 || { dc ps; die "services did not become healthy — run deploy/scripts/diagnostics.sh"; }
ok "all services healthy"
readyz || die "readiness check failed"

has_users=$(dc exec -T api vigil-admin status | sed -n 's/.*"users":\([0-9]*\).*/\1/p')
if [ "${has_users:-0}" = 0 ]; then
  info "create the first administrator"
  if [ -z "$ADMIN_EMAIL" ] || [ -z "$ADMIN_NAME" ] || [ -z "$ORG" ]; then
    [ "${ASSUME_YES:-0}" = 1 ] || [ -t 0 ] || die "--admin-email, --admin-name and --org are required without a terminal"
    [ "${ASSUME_YES:-0}" = 1 ] && die "--admin-email, --admin-name and --org are required with --yes"
  fi
  [ -n "$ADMIN_EMAIL" ] || read -r -p "Administrator email: " ADMIN_EMAIL
  [ -n "$ADMIN_NAME" ] || read -r -p "Administrator name: " ADMIN_NAME
  [ -n "$ORG" ] || read -r -p "Organization name: " ORG
  dc exec -T api vigil-admin create-owner --email "$ADMIN_EMAIL" --name "$ADMIN_NAME" --org "$ORG"
else
  ok "users already exist; skipping administrator creation"
fi
info "Vigil $version is running at $(env_get VIGIL_WEB_ORIGIN) (bound to $(env_get VIGIL_WEB_BIND):$(env_get VIGIL_WEB_PORT))"
