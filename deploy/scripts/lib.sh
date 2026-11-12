#!/usr/bin/env bash
# Shared helpers for Vigil operator scripts. Source, don't execute.
# shellcheck disable=SC2034  # variables here are used by the scripts that source this file
set -euo pipefail
DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd "$DEPLOY_DIR/.." && pwd)"
ENV_FILE="$DEPLOY_DIR/.env"
BACKUP_ROOT="${VIGIL_BACKUP_DIR:-$DEPLOY_DIR/backups}"
DEFAULT_IMAGE_REGISTRY="ghcr.io/onelab-x"
# Release images are signed keylessly (Sigstore) by this workflow on a v* tag.
COSIGN_IDENTITY_REGEXP='^https://github\.com/OneLab-X/vigil/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$'
COSIGN_OIDC_ISSUER="https://token.actions.githubusercontent.com"
VIGIL_IMAGES=(api agents web)

if [ -t 1 ]; then c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_off=$'\033[0m'; else c_red=""; c_grn=""; c_yel=""; c_off=""; fi
info() { printf '%s\n' "==> $*"; }
ok()   { printf '%s\n' "${c_grn}ok${c_off}   $*"; }
warn() { printf '%s\n' "${c_yel}warn${c_off} $*" >&2; }
fail() { printf '%s\n' "${c_red}fail${c_off} $*" >&2; }
die()  { fail "$*"; exit 1; }

env_get() { [ -f "$ENV_FILE" ] || return 0; grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- || true; }
env_set() { # env_set KEY VALUE (in place, keeps mode 600)
  [[ "$1" =~ ^[A-Z0-9_]+$ ]] || die "env_set: bad key '$1'"
  local tmp; tmp="$(mktemp)"; awk -v k="$1" -v v="$2" 'BEGIN{FS=OFS="="} $1==k{print k"="v; f=1; next} {print} END{if(!f) print k"="v}' "$ENV_FILE" > "$tmp"
  cat "$tmp" > "$ENV_FILE"; rm -f "$tmp"; }
require_env() { [ -f "$ENV_FILE" ] || die "$ENV_FILE not found — run install first"; }
confirm() { [ "${ASSUME_YES:-0}" = 1 ] && return 0; [ -t 0 ] || die "confirmation required: re-run with --yes"; local a; read -r -p "$1 [y/N] " a; [[ "$a" =~ ^[Yy]$ ]]; }
sha256f() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
bundled_store() { [ "$(env_get VIGIL_S3_ENDPOINT)" = "http://objectstore:8333" ]; }

# source  = build images from a git checkout (deploy/ inside the repo)
# release = pull signed, prebuilt images (installed from release assets, e.g. /opt/vigil)
install_mode() {
  local m="${VIGIL_INSTALL_MODE:-}"
  [ -n "$m" ] || m="$(env_get VIGIL_INSTALL_MODE)"
  if [ -z "$m" ]; then
    if [ -f "$REPO_DIR/apps/api/package.json" ] && [ -f "$DEPLOY_DIR/compose.build.yaml" ]; then m=source; else m=release; fi
  fi
  case "$m" in source|release) printf '%s\n' "$m";; *) die "VIGIL_INSTALL_MODE must be 'source' or 'release' (got '$m')";; esac
}

INSTALL_MODE="$(install_mode)"

# Version these files describe: the checkout's VERSION (source) or the release bundle's VERSION (release).
target_version() {
  local f; if [ "$INSTALL_MODE" = source ]; then f="$REPO_DIR/VERSION"; else f="$DEPLOY_DIR/VERSION"; fi
  [ -f "$f" ] || die "$f not found"
  local v; v="$(tr -d '[:space:]' < "$f")"
  [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid version '$v' in $f"
  printf '%s\n' "$v"
}

image_registry() { local r="${VIGIL_IMAGE_REGISTRY:-}"; [ -n "$r" ] || r="$(env_get VIGIL_IMAGE_REGISTRY)"; printf '%s\n' "${r:-$DEFAULT_IMAGE_REGISTRY}"; }
image_ref() { # image_ref api|agents|web VERSION_OR_TAG
  if [ "$INSTALL_MODE" = source ]; then printf 'vigil/%s:%s\n' "$1" "$2"; else printf '%s/vigil-%s:%s\n' "$(image_registry)" "$1" "$2"; fi
}

dc() {
  local files=(-f "$DEPLOY_DIR/compose.yaml")
  [ "$INSTALL_MODE" = source ] && files+=(-f "$DEPLOY_DIR/compose.build.yaml")
  docker compose --project-directory "$DEPLOY_DIR" "${files[@]}" --env-file "$ENV_FILE" "$@"
}

# Verify release image signatures with cosign (returns non-zero on failure). VIGIL_VERIFY_SIGNATURES: auto (default; warn if cosign missing),
# require (fail if cosign missing), off. A failed verification is always fatal.
verify_signatures() { # verify_signatures VERSION
  [ "$INSTALL_MODE" = release ] || return 0
  local policy="${VIGIL_VERIFY_SIGNATURES:-}"; [ -n "$policy" ] || policy="$(env_get VIGIL_VERIFY_SIGNATURES)"; policy="${policy:-auto}"
  case "$policy" in
    off) warn "image signature verification is disabled (VIGIL_VERIFY_SIGNATURES=off)"; return 0;;
    auto|require) ;;
    *) die "VIGIL_VERIFY_SIGNATURES must be auto, require or off";;
  esac
  if ! command -v cosign >/dev/null 2>&1; then
    if [ "$policy" = require ]; then fail "cosign not installed and VIGIL_VERIFY_SIGNATURES=require"; return 1; fi
    warn "cosign not installed — image signatures NOT verified (install cosign: https://docs.sigstore.dev/cosign/system_config/installation/)"
    return 0
  fi
  local n ref
  for n in "${VIGIL_IMAGES[@]}"; do
    ref="$(image_ref "$n" "$1")"
    cosign verify --certificate-identity-regexp "$COSIGN_IDENTITY_REGEXP" --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
      "$ref" >/dev/null 2>&1 || { fail "signature verification FAILED for $ref — do not run these images"; return 1; }
  done
  ok "image signatures verified (cosign, $COSIGN_OIDC_ISSUER)"
}

# Get the images for VERSION: build from the checkout (source) or pull + verify (release).
fetch_images() { # fetch_images VERSION
  if [ "$INSTALL_MODE" = source ]; then
    info "building images from this checkout (version $1)"
    dc build || return 1
  else
    info "pulling release images $(image_registry)/vigil-{api,agents,web}:$1"
    dc pull --quiet || { fail "could not pull images (check network access to $(image_registry))"; return 1; }
    verify_signatures "$1" || return 1
  fi
}

readyz() { dc exec -T api node -e "fetch('http://127.0.0.1:8080/readyz').then(r=>r.json()).then(j=>{console.log(JSON.stringify(j));process.exit(j.ok?0:1)}).catch(e=>{console.error(String(e));process.exit(1)})"; }
latest_backup() { find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -name '20*' | sort | tail -1; }

# Add settings introduced by a newer env.template to an existing .env (never touches existing values;
# __GENERATE__ placeholders get fresh random values). Existing secrets, incl. VIGIL_SECRET_KEY, are never regenerated.
env_merge_template() {
  require_env
  local line k v added=()
  while IFS= read -r line; do
    [[ "$line" =~ ^([A-Z0-9_]+)=(.*)$ ]] || continue
    k="${BASH_REMATCH[1]}"; v="${BASH_REMATCH[2]}"
    grep -qE "^$k=" "$ENV_FILE" && continue
    case "$v" in __GENERATE_HEX32__) v="$(openssl rand -hex 32)";; __GENERATE__) v="$(openssl rand -hex 24)";; esac
    env_set "$k" "$v"; added+=("$k")
  done < "$DEPLOY_DIR/env.template"
  if [ ${#added[@]} -gt 0 ]; then ok "added new settings to .env with defaults: ${added[*]}"; fi
}

# ---- release assets (release mode) ----
VIGIL_REPO="${VIGIL_REPO:-OneLab-X/vigil}"
RELEASE_BASE_URL="${VIGIL_RELEASE_BASE_URL:-https://github.com/$VIGIL_REPO/releases/download}"
RELEASE_API_URL="${VIGIL_RELEASE_API_URL:-https://api.github.com/repos/$VIGIL_REPO/releases/latest}"
fetch_url() { curl -fsSL --proto '=https,http' --retry 3 --retry-delay 2 --connect-timeout 15 -o "$2" "$1"; }
latest_release_version() {
  local tmp v; tmp="$(mktemp)"
  fetch_url "$RELEASE_API_URL" "$tmp" || { rm -f "$tmp"; return 1; }
  v="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tag_name"].lstrip("v"))' "$tmp" 2>/dev/null || true)"; rm -f "$tmp"
  [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && printf '%s\n' "$v"
}
# release_download VERSION DIR → extracts DIR/vigil-deploy-VERSION after verifying SHA256SUMS (+ its signature if cosign exists)
release_download() {
  local v="$1" d="$2" base="$RELEASE_BASE_URL/v$1" tarball="vigil-deploy-$1.tar.gz" want
  fetch_url "$base/SHA256SUMS" "$d/SHA256SUMS" || { fail "release v$v not found at $base"; return 1; }
  fetch_url "$base/$tarball" "$d/$tarball" || { fail "could not download $tarball"; return 1; }
  if command -v cosign >/dev/null 2>&1 && fetch_url "$base/SHA256SUMS.sigstore.json" "$d/SHA256SUMS.sigstore.json" 2>/dev/null; then
    cosign verify-blob --bundle "$d/SHA256SUMS.sigstore.json" --certificate-identity-regexp "$COSIGN_IDENTITY_REGEXP" \
      --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" "$d/SHA256SUMS" >/dev/null 2>&1 || { fail "SHA256SUMS signature verification FAILED"; return 1; }
    ok "SHA256SUMS signature verified (cosign)"
  fi
  want="$(awk -v f="$tarball" '{n=$2; sub(/^\*/,"",n)} n==f{print $1}' "$d/SHA256SUMS")"
  [ -n "$want" ] && [ "$(sha256f "$d/$tarball")" = "$want" ] || { fail "checksum mismatch for $tarball"; return 1; }
  ok "checksum verified: $tarball"
  tar -xzf "$d/$tarball" -C "$d"
  [ -f "$d/vigil-deploy-$v/compose.yaml" ] && [ -f "$d/vigil-deploy-$v/scripts/upgrade.sh" ] || { fail "release bundle incomplete"; return 1; }
}
semver_cmp() { # prints -1, 0 or 1
  local IFS=.; local -a a b; read -r -a a <<<"$1"; read -r -a b <<<"$2"; local i
  for i in 0 1 2; do
    if [ "${a[$i]:-0}" -lt "${b[$i]:-0}" ]; then echo -1; return; fi
    if [ "${a[$i]:-0}" -gt "${b[$i]:-0}" ]; then echo 1; return; fi
  done; echo 0; }
