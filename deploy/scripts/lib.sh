#!/usr/bin/env bash
# Shared helpers for Vigil operator scripts. Source, don't execute.
set -euo pipefail
DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd "$DEPLOY_DIR/.." && pwd)"
ENV_FILE="$DEPLOY_DIR/.env"
BACKUP_ROOT="${VIGIL_BACKUP_DIR:-$DEPLOY_DIR/backups}"

c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_off=$'\033[0m'
info() { printf '%s\n' "==> $*"; }
ok()   { printf '%s\n' "${c_grn}ok${c_off}   $*"; }
warn() { printf '%s\n' "${c_yel}warn${c_off} $*" >&2; }
die()  { printf '%s\n' "${c_red}fail${c_off} $*" >&2; exit 1; }

dc() { docker compose --project-directory "$DEPLOY_DIR" -f "$DEPLOY_DIR/compose.yaml" --env-file "$ENV_FILE" "$@"; }
env_get() { grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2-; }
env_set() { # env_set KEY VALUE (in place, keeps mode 600)
  [[ "$1" =~ ^[A-Z0-9_]+$ ]] || die "env_set: bad key '$1'"
  local tmp; tmp="$(mktemp)"; awk -v k="$1" -v v="$2" 'BEGIN{FS=OFS="="} $1==k{print k"="v; f=1; next} {print} END{if(!f) print k"="v}' "$ENV_FILE" > "$tmp"
  cat "$tmp" > "$ENV_FILE"; rm -f "$tmp"; }
require_env() { [ -f "$ENV_FILE" ] || die "deploy/.env not found — run deploy/scripts/install.sh first"; }
confirm() { [ "${ASSUME_YES:-0}" = 1 ] && return 0; read -r -p "$1 [y/N] " a; [[ "$a" =~ ^[Yy]$ ]]; }
sha256f() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
bundled_store() { [ "$(env_get VIGIL_S3_ENDPOINT)" = "http://objectstore:8333" ]; }
