#!/usr/bin/env bash
# Pre-installation validation. Read-only: changes nothing. Exit code 1 if a hard requirement fails.
source "$(dirname "$0")/lib.sh"
fails=0
check() { if eval "$2" >/dev/null 2>&1; then ok "$1"; else printf '%s\n' "${c_red}fail${c_off} $1 — $3"; fails=$((fails+1)); fi; }

check "docker CLI present" "command -v docker" "install Docker Engine or Docker Desktop"
check "docker daemon reachable" "docker info" "start the Docker daemon"
check "docker compose v2" "docker compose version" "install the compose v2 plugin"
check "openssl present" "command -v openssl" "needed to generate secrets"
if docker info >/dev/null 2>&1; then
  cpus=$(docker info --format '{{.NCPU}}'); mem=$(docker info --format '{{.MemTotal}}')
  memg=$((mem / 1024 / 1024 / 1024))
  [ "$cpus" -ge 2 ] && ok "CPUs available to Docker: $cpus" || { warn "only $cpus CPU(s) for Docker; 2+ recommended"; }
  [ "$memg" -ge 3 ] && ok "memory available to Docker: ${memg} GiB" || { printf '%s\n' "${c_red}fail${c_off} ${memg} GiB memory for Docker; 4 GiB recommended (3 minimum)"; fails=$((fails+1)); }
  cv=$(docker compose version --short 2>/dev/null | sed 's/^v//'); major=${cv%%.*}; rest=${cv#*.}; minor=${rest%%.*}
  { [ "${major:-0}" -gt 2 ] || { [ "${major:-0}" -eq 2 ] && [ "${minor:-0}" -ge 20 ]; }; } && ok "compose version $cv" || { printf '%s\n' "${c_red}fail${c_off} compose $cv; 2.20+ required"; fails=$((fails+1)); }
fi
if docker info >/dev/null 2>&1; then
  # Docker Desktop / Colima only share some host folders with their VM; bind mounts from elsewhere arrive empty.
  if docker run --rm -v "$DEPLOY_DIR:/vigil-deploy:ro" pgvector/pgvector:0.8.1-pg17 test -f /vigil-deploy/compose.yaml >/dev/null 2>&1; then
    ok "Docker can read $DEPLOY_DIR (bind mounts work)"
  else
    printf '%s\n' "${c_red}fail${c_off} Docker cannot see $DEPLOY_DIR — move Vigil under a folder shared with Docker (e.g. your home directory) or add it to Docker Desktop/Colima file sharing"; fails=$((fails+1))
  fi
fi
free_kb=$(df -Pk "$DEPLOY_DIR" | awk 'NR==2{print $4}')
[ "$((free_kb / 1024 / 1024))" -ge 10 ] && ok "disk free: $((free_kb / 1024 / 1024)) GiB" || warn "less than 10 GiB free on $(df -P "$DEPLOY_DIR" | awk 'NR==2{print $6}'); evidence storage grows with ingestion"
port="${VIGIL_WEB_PORT:-$( [ -f "$ENV_FILE" ] && env_get VIGIL_WEB_PORT || echo 3000)}"
if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
  if docker ps --format '{{.Ports}}' 2>/dev/null | grep -q ":$port->3000"; then ok "port $port in use by an existing Vigil web container"; else printf '%s\n' "${c_red}fail${c_off} port $port already in use (set VIGIL_WEB_PORT)"; fails=$((fails+1)); fi
else ok "port $port free"; fi
ok "no vendor-hosted service is required (only your cloud and AI provider endpoints, if configured)"
[ "$fails" -eq 0 ] && info "preflight passed" || die "$fails preflight check(s) failed"
