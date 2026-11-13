#!/usr/bin/env bash
# Pre-installation validation. Read-only: changes nothing. Exit code 1 if a hard requirement fails.
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
usage() { cat <<EOF
Pre-installation validation. Read-only: changes nothing. Exit code 1 if a hard requirement fails.

Usage: $(basename "$0")
EOF
}
case "${1:-}" in -h|--help) usage; exit 0;; esac
fails=0
check() { if eval "$2" >/dev/null 2>&1; then ok "$1"; else fail "$1 — $3"; fails=$((fails+1)); fi; }
bad() { fail "$1"; fails=$((fails+1)); }

check "docker CLI present" "command -v docker" "install Docker Engine or Docker Desktop"
check "docker daemon reachable" "docker info" "start the Docker daemon"
check "docker compose v2" "docker compose version" "install the compose v2 plugin"
check "openssl present" "command -v openssl" "needed to generate secrets"
if docker info >/dev/null 2>&1; then
  cpus=$(docker info --format '{{.NCPU}}'); mem=$(docker info --format '{{.MemTotal}}')
  memg=$((mem / 1024 / 1024 / 1024))
  if [ "$cpus" -ge 4 ]; then ok "CPUs available to Docker: $cpus"
  elif [ "$cpus" -ge 2 ]; then warn "$cpus CPUs for Docker; 4 recommended"
  else warn "only $cpus CPU(s) for Docker; 2 minimum, 4 recommended"; fi
  # MemTotal reports slightly less than the VM size (kernel reservations), so a "4 GiB" VM shows ~3.8 GiB.
  if [ "$memg" -ge 7 ]; then ok "memory available to Docker: ${memg} GiB"
  elif [ "$memg" -ge 3 ]; then warn "${memg} GiB memory for Docker; 8 GiB recommended (4 GiB minimum)"
  else bad "${memg} GiB memory for Docker; 4 GiB minimum, 8 GiB recommended"; fi
  cv=$(docker compose version --short 2>/dev/null | sed 's/^v//'); major=${cv%%.*}; rest=${cv#*.}; minor=${rest%%.*}
  if [ "${major:-0}" -gt 2 ] || { [ "${major:-0}" -eq 2 ] && [ "${minor:-0}" -ge 20 ]; }; then ok "compose version $cv"; else bad "compose $cv; 2.20+ required"; fi
fi
if docker info >/dev/null 2>&1; then
  # Docker Desktop / Colima only share some host folders with their VM; bind mounts from elsewhere arrive empty.
  if docker run --rm -v "$DEPLOY_DIR:/vigil-deploy:ro" pgvector/pgvector:0.8.1-pg17 test -f /vigil-deploy/compose.yaml >/dev/null 2>&1; then
    ok "Docker can read $DEPLOY_DIR (bind mounts work)"
  else
    bad "Docker cannot see $DEPLOY_DIR — move Vigil under a folder shared with Docker (e.g. your home directory) or add it to Docker Desktop/Colima file sharing"
  fi
fi
free_kb=$(df -Pk "$DEPLOY_DIR" | awk 'NR==2{print $4}')
if [ "$((free_kb / 1024 / 1024))" -ge 10 ]; then ok "disk free: $((free_kb / 1024 / 1024)) GiB"; else warn "less than 10 GiB free on $(df -P "$DEPLOY_DIR" | awk 'NR==2{print $6}'); evidence storage grows with ingestion"; fi
port="${VIGIL_WEB_PORT:-$(env_get VIGIL_WEB_PORT)}"; port="${port:-3000}"
if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
  if docker ps --format '{{.Ports}}' 2>/dev/null | grep -q ":$port->3000"; then ok "port $port in use by an existing Vigil web container"; else bad "port $port already in use (set VIGIL_WEB_PORT)"; fi
else ok "port $port free"; fi
ok "no vendor-hosted service is required (only your cloud and AI provider endpoints, if configured)"
if [ "$fails" -eq 0 ]; then info "preflight passed"; else die "$fails preflight check(s) failed"; fi
