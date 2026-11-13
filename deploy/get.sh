#!/usr/bin/env bash
# Vigil clean-VM installer. Installs Docker if missing, downloads a checksum-verified release bundle into
# /opt/vigil, generates secrets locally, starts the stack behind health checks and creates the first owner.
#
#   curl -fsSL https://github.com/OneLab-X/vigil/releases/download/vX.Y.Z/get.sh | sudo bash -s -- --version X.Y.Z [flags]
#
# or download, inspect, run:
#   curl -fsSLO https://github.com/OneLab-X/vigil/releases/download/vX.Y.Z/get.sh
#   less get.sh && sudo bash get.sh --version X.Y.Z
#
# Everything is wrapped in main() so a partially downloaded script never runs.
set -euo pipefail

VIGIL_REPO="${VIGIL_REPO:-OneLab-X/vigil}"
# Overridable for mirrors / air-gapped staging / CI smoke tests. Assets must still match the release SHA256SUMS.
RELEASE_BASE_URL="${VIGIL_RELEASE_BASE_URL:-https://github.com/$VIGIL_REPO/releases/download}"
RELEASE_API_URL="${VIGIL_RELEASE_API_URL:-https://api.github.com/repos/$VIGIL_REPO/releases/latest}"
COMPOSE_PLUGIN_VERSION="v2.40.3"   # only used where the distro has no compose plugin package (Amazon Linux 2023)
COMPOSE_SHA256_X86_64="dba9d98e1ba5bfe11d88c99b9bd32fc4a0624a30fafe68eea34d61a3e42fd372"
COMPOSE_SHA256_AARCH64="d26373b19e89160546d15407516cc59f453030d9bc5b43ba7faf16f7b4980137"

if [ -t 1 ]; then c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_bold=$'\033[1m'; c_off=$'\033[0m'; else c_red=""; c_grn=""; c_yel=""; c_bold=""; c_off=""; fi
info() { printf '%s\n' "==> $*"; }
ok()   { printf '%s\n' "${c_grn}ok${c_off}   $*"; }
warn() { printf '%s\n' "${c_yel}warn${c_off} $*" >&2; }
die()  { printf '%s\n' "${c_red}fail${c_off} $*" >&2; exit 1; }

usage() { cat <<'EOF'
Vigil installer for a clean Linux VM (Ubuntu 22.04/24.04, Debian 12, RHEL/Alma/Rocky 9, Amazon Linux 2023).

Usage: sudo bash get.sh [options]

  --version X.Y.Z       release to install (default: latest published release; never an unpinned "latest" image)
  --data-dir DIR        installation directory (default: /opt/vigil)
  --domain FQDN         serve Vigil over HTTPS at this name: built-in Caddy proxy on 80/443, HTTP->HTTPS redirect,
                        HSTS (DNS must point to this host for Let's Encrypt)
  --email ADDR          ACME account email for --domain (expiry notices; optional)
  --tls-mode MODE       acme (default with --domain) | custom (with --tls-cert/--tls-key) | internal (private CA) | off
  --tls-cert FILE       PEM certificate chain for --tls-mode custom
  --tls-key FILE        PEM private key for --tls-mode custom
  --admin-email ADDR    first owner's email      \
  --admin-name NAME     first owner's name        } prompted for when missing and a terminal is attached
  --org NAME            organization name        /
  --yes                 non-interactive: never prompt (admin flags required for a new install)
  --dont-start          install Docker and files, write .env, but do not start Vigil
  --reset               reinstall over an existing installation: takes a full backup, moves the old
                        directory aside (DIR.reset-<timestamp>) and removes the old volumes; asks you to type
                        the hostname to confirm (or set VIGIL_RESET_CONFIRM=<hostname> with --yes)
  --skip-docker-install fail instead of installing Docker when it is missing
  -h, --help            show this help

Re-running is safe: an existing installation keeps its .env (secrets are never regenerated) and data; files are
only upgraded through 'vigil upgrade --version X.Y.Z'.
EOF
}

# ---------------------------------------------------------------- helpers
tty_available() { [ -r /dev/tty ] && [ -w /dev/tty ] && { : < /dev/tty; } 2>/dev/null; }
ask() { # ask VAR "Prompt" — reads from the terminal even when this script is piped into bash
  local __v; tty_available || die "missing $1 and no terminal to ask on; pass it as a flag"
  read -r -p "$2" __v < /dev/tty; printf -v "$1" '%s' "$__v"; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
fetch() { curl -fsSL --proto '=https,http' --retry 3 --retry-delay 2 --connect-timeout 15 -o "$2" "$1"; }

detect_os() {
  [ -r /etc/os-release ] || die "cannot detect the operating system (/etc/os-release missing)"
  # Read os-release in a subshell: sourcing it here would overwrite VERSION (the --version flag) with the OS version.
  local fields
  # shellcheck disable=SC1091
  fields="$(. /etc/os-release && printf '%s\n%s\n%s\n%s' "${ID:-}" "${VERSION_ID:-}" "${VERSION_CODENAME:-}" "${PRETTY_NAME:-}")"
  { IFS= read -r OS_ID; IFS= read -r OS_VER; IFS= read -r OS_CODENAME; IFS= read -r OS_NAME; } <<<"$fields" || true
  case "$OS_ID:$OS_VER" in
    ubuntu:22.04|ubuntu:24.04) PKG=apt ;;
    debian:12*) PKG=apt ;;
    rhel:9*|almalinux:9*|rocky:9*) PKG=dnf ;;
    amzn:2023*) PKG=dnf ;;
    *) if docker compose version >/dev/null 2>&1; then
         warn "untested OS ${OS_NAME:-$OS_ID $OS_VER}; Docker + Compose are present, continuing"; PKG=none
       else die "unsupported OS ${OS_NAME:-$OS_ID $OS_VER}: install Docker Engine + Compose v2 yourself and re-run"; fi ;;
  esac
  ok "OS: ${OS_NAME:-$OS_ID $OS_VER} ($(uname -m))"
}

install_base_packages() {
  local need=()
  for c in curl tar openssl python3; do command -v "$c" >/dev/null 2>&1 || need+=("$c"); done
  [ ${#need[@]} -eq 0 ] && return 0
  info "installing ${need[*]}"
  case "$PKG" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates "${need[@]}" >/dev/null ;;
    dnf) dnf install -y -q ca-certificates "${need[@]}" >/dev/null ;;
    *) die "missing ${need[*]}; install them and re-run" ;;
  esac
}

install_docker() {
  if docker compose version >/dev/null 2>&1 && docker info >/dev/null 2>&1; then ok "Docker $(docker version --format '{{.Server.Version}}') + Compose $(docker compose version --short) already installed"; return 0; fi
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    systemctl enable --now docker >/dev/null 2>&1 || true
    docker info >/dev/null 2>&1 && { ok "Docker started"; return 0; }
  fi
  [ "$SKIP_DOCKER_INSTALL" = 1 ] && die "Docker Engine + Compose v2 not found (--skip-docker-install given)"
  info "installing Docker Engine + Compose plugin from Docker's repository"
  case "$OS_ID" in
    ubuntu|debian)
      DEBIAN_FRONTEND=noninteractive apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates curl >/dev/null
      install -m 0755 -d /etc/apt/keyrings
      fetch "https://download.docker.com/linux/$OS_ID/gpg" /etc/apt/keyrings/docker.asc
      chmod a+r /etc/apt/keyrings/docker.asc
      printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/%s %s stable\n' \
        "$(dpkg --print-architecture)" "$OS_ID" "$OS_CODENAME" > /etc/apt/sources.list.d/docker.list
      DEBIAN_FRONTEND=noninteractive apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null ;;
    rhel|almalinux|rocky)
      dnf install -y -q dnf-plugins-core >/dev/null
      dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo >/dev/null
      dnf install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null ;;
    amzn)
      # Docker's repositories do not cover Amazon Linux; use the distro's docker and a pinned, checksum-verified
      # compose plugin binary.
      dnf install -y -q docker >/dev/null
      local arch sum; arch="$(uname -m)"
      case "$arch" in x86_64) sum="$COMPOSE_SHA256_X86_64";; aarch64) sum="$COMPOSE_SHA256_AARCH64";; *) die "unsupported CPU $arch";; esac
      install -m 0755 -d /usr/local/lib/docker/cli-plugins
      fetch "https://github.com/docker/compose/releases/download/$COMPOSE_PLUGIN_VERSION/docker-compose-linux-$arch" "$TMP/docker-compose"
      [ "$(sha256 "$TMP/docker-compose")" = "$sum" ] || die "docker compose plugin checksum mismatch"
      install -m 0755 "$TMP/docker-compose" /usr/local/lib/docker/cli-plugins/docker-compose ;;
    *) die "cannot install Docker automatically on $OS_ID" ;;
  esac
  systemctl enable --now docker >/dev/null
  docker compose version >/dev/null 2>&1 || die "Docker installed but 'docker compose' is not working"
  ok "Docker $(docker version --format '{{.Server.Version}}') + Compose $(docker compose version --short) installed"
}

resolve_version() {
  if [ -n "$VERSION" ]; then VERSION="${VERSION#v}"
  else
    info "looking up the latest Vigil release"
    fetch "$RELEASE_API_URL" "$TMP/latest.json" || die "could not query $RELEASE_API_URL; pass --version X.Y.Z"
    VERSION="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tag_name"].lstrip("v"))' "$TMP/latest.json" 2>/dev/null || true)"
  fi
  [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid or unknown version '${VERSION:-}'; pass --version X.Y.Z"
  ok "Vigil version $VERSION"
}

download_bundle() { # verifies SHA256SUMS and (when cosign is present) its Sigstore signature
  local base="$RELEASE_BASE_URL/v$VERSION" tarball="vigil-deploy-$VERSION.tar.gz" want
  info "downloading release $VERSION assets"
  fetch "$base/SHA256SUMS" "$TMP/SHA256SUMS" || die "release v$VERSION not found at $base"
  fetch "$base/$tarball" "$TMP/$tarball" || die "could not download $tarball"
  if command -v cosign >/dev/null 2>&1 && fetch "$base/SHA256SUMS.sigstore.json" "$TMP/SHA256SUMS.sigstore.json" 2>/dev/null; then
    cosign verify-blob --bundle "$TMP/SHA256SUMS.sigstore.json" \
      --certificate-identity-regexp "^https://github\.com/$VIGIL_REPO/\.github/workflows/release\.yml@refs/tags/v" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com "$TMP/SHA256SUMS" >/dev/null 2>&1 \
      || die "SHA256SUMS signature verification FAILED"
    ok "SHA256SUMS signature verified (cosign)"
  fi
  want="$(awk -v f="$tarball" '{n=$2; sub(/^\*/,"",n)} n==f{print $1}' "$TMP/SHA256SUMS")"
  [ -n "$want" ] || die "$tarball is not listed in SHA256SUMS"
  [ "$(sha256 "$TMP/$tarball")" = "$want" ] || die "checksum mismatch for $tarball — refusing to install"
  ok "checksum verified: $tarball"
  tar -xzf "$TMP/$tarball" -C "$TMP"
  BUNDLE="$TMP/vigil-deploy-$VERSION"
  if [ ! -f "$BUNDLE/compose.yaml" ] || [ ! -x "$BUNDLE/scripts/install.sh" ]; then die "release bundle is incomplete"; fi
}

install_cli() {
  cat > /usr/local/bin/vigil <<EOF
#!/usr/bin/env bash
# Vigil operator CLI shim (installed by get.sh). The real CLI ships with each release in $DATA_DIR/scripts/vigil.sh.
exec env VIGIL_HOME="\${VIGIL_HOME:-$DATA_DIR}" bash "\${VIGIL_HOME:-$DATA_DIR}/scripts/vigil.sh" "\$@"
EOF
  chmod 755 /usr/local/bin/vigil
  ok "installed the 'vigil' command (/usr/local/bin/vigil → $DATA_DIR/scripts/vigil.sh)"
}

reset_existing() {
  local host stamp aside; host="$(hostname)"; stamp="$(date -u +%Y%m%dT%H%M%SZ)"; aside="$DATA_DIR.reset-$stamp"
  warn "--reset: the current installation in $DATA_DIR will be backed up, moved to $aside and its volumes removed"
  if [ "${VIGIL_RESET_CONFIRM:-}" != "$host" ]; then
    [ "$ASSUME_YES" = 1 ] && die "--reset with --yes requires VIGIL_RESET_CONFIRM=$host"
    local typed; ask typed "Type the hostname ($host) to confirm the reset: "
    [ "$typed" = "$host" ] || die "confirmation did not match; nothing changed"
  fi
  info "taking a full backup before reset"
  ASSUME_YES=1 bash "$DATA_DIR/scripts/backup.sh" || die "backup failed; nothing changed"
  (cd "$DATA_DIR" && bash -c 'source scripts/lib.sh && dc down -v --remove-orphans') || die "could not stop the old installation"
  mv "$DATA_DIR" "$aside"
  ok "old installation and its backups moved to $aside"
}

prepare_dir() {
  umask 022
  install -d -m 0755 "$DATA_DIR"
  local f
  for f in compose.yaml compose.tls.yaml env.template VERSION empty-credentials.json; do install -m 0644 "$BUNDLE/$f" "$DATA_DIR/$f"; done
  rm -rf "$DATA_DIR/scripts.new" "$DATA_DIR/postgres.new"
  cp -R "$BUNDLE/scripts" "$DATA_DIR/scripts.new"; cp -R "$BUNDLE/postgres" "$DATA_DIR/postgres.new"
  rm -rf "$DATA_DIR/scripts" "$DATA_DIR/postgres"; mv "$DATA_DIR/scripts.new" "$DATA_DIR/scripts"; mv "$DATA_DIR/postgres.new" "$DATA_DIR/postgres"
  if [ -d "$BUNDLE/proxy" ]; then rm -rf "$DATA_DIR/proxy"; cp -R "$BUNDLE/proxy" "$DATA_DIR/proxy"; fi
  chmod 755 "$DATA_DIR"/scripts/* "$DATA_DIR"/postgres/*.sh
  install -d -m 0700 "$DATA_DIR/backups"
  chown -R root:root "$DATA_DIR"
  ok "installed release files in $DATA_DIR"
}

main() {
  VERSION=""; DATA_DIR="/opt/vigil"; DOMAIN=""; ACME_EMAIL=""; TLS_MODE=""; TLS_CERT=""; TLS_KEY=""; ADMIN_EMAIL=""; ADMIN_NAME=""; ORG=""
  ASSUME_YES=0; DONT_START=0; RESET=0; SKIP_DOCKER_INSTALL=0
  while [ $# -gt 0 ]; do case "$1" in
    --version) VERSION="${2:?--version needs a value}"; shift 2;;
    --data-dir) DATA_DIR="${2:?--data-dir needs a value}"; shift 2;;
    --domain) DOMAIN="${2:?--domain needs a value}"; shift 2;;
    --email) ACME_EMAIL="${2:?--email needs a value}"; shift 2;;
    --tls-mode) TLS_MODE="${2:?--tls-mode needs a value}"; shift 2;;
    --tls-cert) TLS_CERT="${2:?--tls-cert needs a value}"; shift 2;;
    --tls-key) TLS_KEY="${2:?--tls-key needs a value}"; shift 2;;
    --admin-email) ADMIN_EMAIL="${2:?--admin-email needs a value}"; shift 2;;
    --admin-name) ADMIN_NAME="${2:?--admin-name needs a value}"; shift 2;;
    --org) ORG="${2:?--org needs a value}"; shift 2;;
    --yes|-y) ASSUME_YES=1; shift;;
    --dont-start) DONT_START=1; shift;;
    --reset) RESET=1; shift;;
    --skip-docker-install) SKIP_DOCKER_INSTALL=1; shift;;
    -h|--help) usage; exit 0;;
    *) usage >&2; die "unknown option: $1";; esac; done

  [ "$(id -u)" = 0 ] || die "run as root: curl -fsSL …/get.sh | sudo bash -s -- [options]"
  [ "$(uname -s)" = Linux ] || die "get.sh installs on Linux hosts; on macOS/Windows use Docker Desktop and deploy/scripts/install.sh from a checkout"
  [[ "$DATA_DIR" = /* ]] || die "--data-dir must be an absolute path"
  DATA_DIR="${DATA_DIR%/}"
  if [ -n "$DOMAIN" ]; then
    [[ "$DOMAIN" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$ ]] || die "invalid --domain '$DOMAIN'"
    TLS_MODE="${TLS_MODE:-acme}"
  else
    [ -z "$TLS_MODE" ] || [ "$TLS_MODE" = off ] || die "--tls-mode $TLS_MODE needs --domain"
    TLS_MODE=off
  fi
  case "$TLS_MODE" in acme|custom|internal|off) ;; *) die "--tls-mode must be acme, custom, internal or off";; esac
  [ -z "$ACME_EMAIL" ] || [[ "$ACME_EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "invalid --email '$ACME_EMAIL'"
  if [ "$TLS_MODE" = custom ]; then
    if [ ! -s "$TLS_CERT" ] || [ ! -s "$TLS_KEY" ]; then die "--tls-mode custom needs readable --tls-cert and --tls-key files"; fi
    TLS_CERT="$(cd "$(dirname "$TLS_CERT")" && pwd)/$(basename "$TLS_CERT")"; TLS_KEY="$(cd "$(dirname "$TLS_KEY")" && pwd)/$(basename "$TLS_KEY")"
  fi

  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  detect_os
  install_base_packages
  install_docker

  local existing=0
  if [ -f "$DATA_DIR/.env" ]; then
    if [ "$RESET" = 1 ]; then reset_existing
    else
      existing=1
      local installed; installed="$(grep -E '^VIGIL_VERSION=' "$DATA_DIR/.env" | tail -1 | cut -d= -f2-)"
      ok "existing installation found in $DATA_DIR (version $installed); keeping .env, data and files"
      [ -z "$VERSION" ] || [ "${VERSION#v}" = "$installed" ] || warn "--version ${VERSION#v} ignored for an existing install; upgrade with: sudo vigil upgrade --version ${VERSION#v}"
      VERSION="$installed"
    fi
  elif [ "$RESET" = 1 ]; then
    warn "--reset given but no installation found in $DATA_DIR; doing a fresh install"
  fi

  if [ "$existing" = 0 ]; then
    [ -d "$DATA_DIR" ] && [ -n "$(ls -A "$DATA_DIR" 2>/dev/null)" ] && die "$DATA_DIR exists and is not an empty Vigil installation; choose another --data-dir"
    resolve_version
    download_bundle
    prepare_dir
  fi
  install_cli

  # Settings applied when .env is first generated (install.sh never overwrites an existing .env).
  export VIGIL_INSTALL_MODE=release
  if [ -n "$DOMAIN" ]; then
    export VIGIL_DOMAIN="$DOMAIN" VIGIL_TLS_MODE="$TLS_MODE" VIGIL_ACME_EMAIL="$ACME_EMAIL"
    [ "$TLS_MODE" = off ] || export VIGIL_WEB_ORIGIN="https://$DOMAIN"
    [ "$TLS_MODE" != custom ] || export VIGIL_TLS_CERT_FILE="$TLS_CERT" VIGIL_TLS_KEY_FILE="$TLS_KEY"
    [ "$existing" = 0 ] || warn "--domain only applies to new installs; for this one set VIGIL_DOMAIN/VIGIL_TLS_MODE/VIGIL_WEB_ORIGIN in $DATA_DIR/.env and re-run"
  fi

  local args=()
  [ "$ASSUME_YES" = 1 ] && args+=(--yes)
  [ -n "$ADMIN_EMAIL" ] && args+=(--admin-email "$ADMIN_EMAIL")
  [ -n "$ADMIN_NAME" ] && args+=(--admin-name "$ADMIN_NAME")
  [ -n "$ORG" ] && args+=(--org "$ORG")
  [ "$DONT_START" = 1 ] && args+=(--no-start)
  # Never write the one-time password into non-interactive logs (cloud-init, CI): hand it over in a root-only file.
  [ -t 1 ] || args+=(--password-file "$DATA_DIR/initial-owner-password")

  if tty_available && [ "$ASSUME_YES" = 0 ]; then bash "$DATA_DIR/scripts/install.sh" "${args[@]}" < /dev/tty
  else ASSUME_YES=1 bash "$DATA_DIR/scripts/install.sh" "${args[@]}" < /dev/null; fi

  printf '\n%s\n' "${c_bold}Vigil $VERSION is installed in $DATA_DIR${c_off}"
  cat <<EOF
  Manage it with:  sudo vigil status | logs | backup | restore | upgrade --version X.Y.Z | rollback | diagnostics | uninstall
  Configuration:   $DATA_DIR/.env (mode 600 — back it up securely; it holds the key that decrypts stored credentials)
  Backups:         $DATA_DIR/backups
EOF
}

main "$@"
