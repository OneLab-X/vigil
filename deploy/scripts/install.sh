#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
usage() { cat <<EOF
First-time installation (safe to re-run: existing .env and data are kept, secrets are never regenerated).

Usage: $(basename "$0") [--admin-email E --admin-name N --org O] [--yes] [--no-start] [--password-file F] [--skip-preflight]

  --admin-email/--admin-name/--org  first owner account (prompted for if missing and a terminal is attached)
  --yes                             non-interactive; fail instead of prompting
  --no-start                        only write .env (and fetch nothing); start later by re-running without it
  --password-file F                 write the first owner's one-time password to F (mode 600) instead of the
                                    terminal — use for unattended installs whose output is logged
  --skip-preflight                  skip deploy/scripts/preflight.sh (not recommended)

Mode: $INSTALL_MODE (source = build from this checkout, release = pull signed images; override with VIGIL_INSTALL_MODE)
EOF
}
ADMIN_EMAIL=""; ADMIN_NAME=""; ORG=""; PREFLIGHT=1; NO_START=0; PASSWORD_FILE=""
while [ $# -gt 0 ]; do case "$1" in
  --admin-email) ADMIN_EMAIL="${2:?--admin-email needs a value}"; shift 2;;
  --admin-name) ADMIN_NAME="${2:?--admin-name needs a value}"; shift 2;;
  --org) ORG="${2:?--org needs a value}"; shift 2;;
  --yes) export ASSUME_YES=1; shift;;
  --skip-preflight) PREFLIGHT=0; shift;;
  --no-start) NO_START=1; shift;;
  --password-file) PASSWORD_FILE="${2:?--password-file needs a path}"; shift 2;;
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
  for k in VIGIL_WEB_PORT VIGIL_WEB_BIND VIGIL_WEB_ORIGIN VIGIL_IMAGE_REGISTRY VIGIL_INSTALL_MODE GEMINI_API_KEY \
           VIGIL_DOMAIN VIGIL_TLS_MODE VIGIL_ACME_EMAIL VIGIL_TLS_CERT_FILE VIGIL_TLS_KEY_FILE; do
    if [ -n "${!k:-}" ]; then env_set "$k" "${!k}"; fi
  done
  if [ -n "${VIGIL_WEB_PORT:-}" ] && [ -z "${VIGIL_WEB_ORIGIN:-}" ]; then env_set VIGIL_WEB_ORIGIN "http://localhost:$VIGIL_WEB_PORT"; fi
  if tls_enabled && [ -z "${VIGIL_WEB_ORIGIN:-}" ]; then env_set VIGIL_WEB_ORIGIN "https://$(env_get VIGIL_DOMAIN)"; fi
  ok "$ENV_FILE written (mode 600). Back it up securely: it holds the key that decrypts stored credentials."
fi

version="$(env_get VIGIL_VERSION)"
if [ "$NO_START" = 1 ]; then
  ok "configuration ready; not starting (--no-start). Start with: $DEPLOY_DIR/scripts/install.sh"
  exit 0
fi
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
  owner_out="$(dc exec -T api vigil-admin create-owner --email "$ADMIN_EMAIL" --name "$ADMIN_NAME" --org "$ORG")" || die "could not create the first owner"
  otp="$(sed -n 's/^one-time password: //p' <<<"$owner_out")"
  [ -n "$otp" ] || die "unexpected output from vigil-admin create-owner"
  ok "created organization \"$ORG\" and owner $ADMIN_EMAIL"
else
  ok "users already exist; skipping administrator creation"
fi

printf '\n%s\n' "Vigil $version is running."
if tls_enabled; then printf '  URL:   %s  (HTTPS via the built-in proxy, TLS mode %s)\n' "$(env_get VIGIL_WEB_ORIGIN)" "$(tls_mode)"
else printf '  URL:   %s  (bound to %s:%s)\n' "$(env_get VIGIL_WEB_ORIGIN)" "$(env_get VIGIL_WEB_BIND)" "$(env_get VIGIL_WEB_PORT)"; fi
if [ -n "${otp:-}" ]; then
  if [ -n "$PASSWORD_FILE" ]; then
    (umask 077; printf '%s\n' "$otp" > "$PASSWORD_FILE"); chmod 600 "$PASSWORD_FILE"
    printf '  Owner: %s — one-time password saved to %s (root-only). Read it, then delete the file.\n' "$ADMIN_EMAIL" "$PASSWORD_FILE"
  else
    printf '  Owner: %s\n  One-time password: %s\n' "$ADMIN_EMAIL" "$otp"
  fi
  printf '  Sign in and change it immediately; it is not stored anywhere else in plain text.\n'
fi
if ! tls_enabled && [ "$(env_get VIGIL_WEB_BIND)" = 127.0.0.1 ]; then
  printf '  The UI listens on this host only. Enable HTTPS with VIGIL_DOMAIN (get.sh --domain), use your own TLS proxy, or SSH:\n'
  printf '    ssh -L %s:127.0.0.1:%s <user>@<this-host>   then open http://localhost:%s\n' "$(env_get VIGIL_WEB_PORT)" "$(env_get VIGIL_WEB_PORT)" "$(env_get VIGIL_WEB_PORT)"
fi
