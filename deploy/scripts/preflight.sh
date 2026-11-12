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
  if [ "${major:-0}" -gt 2 ] || { [ "${major:-0}" -eq 2 ] && [ "${minor:-0}" -ge 24 ]; }; then ok "compose version $cv"; else bad "compose $cv; 2.24+ required"; fi
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
port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
ours_on() { docker ps --format '{{.Ports}}' 2>/dev/null | grep -q ":$1->$2"; }
domain="${VIGIL_DOMAIN:-$(env_get VIGIL_DOMAIN)}"
tlsm="${VIGIL_TLS_MODE:-$(env_get VIGIL_TLS_MODE)}"; tlsm="${tlsm:-acme}"; [ -n "$domain" ] || tlsm=off
if [ "$tlsm" = off ]; then
  port="${VIGIL_WEB_PORT:-$(env_get VIGIL_WEB_PORT)}"; port="${port:-3000}"
  if port_busy "$port"; then
    if ours_on "$port" 3000; then ok "port $port in use by an existing Vigil web container"; else bad "port $port already in use (set VIGIL_WEB_PORT)"; fi
  else ok "port $port free"; fi
else
  for p in 80 443; do
    if port_busy "$p"; then
      if ours_on "$p" "$p"; then ok "port $p in use by the existing Vigil proxy"; else bad "port $p already in use — the built-in HTTPS proxy needs 80 and 443"; fi
    else ok "port $p free"; fi
  done
  if [ "$tlsm" = custom ]; then
    for k in VIGIL_TLS_CERT_FILE VIGIL_TLS_KEY_FILE; do
      f="${!k:-$(env_get "$k")}"
      if [ -n "$f" ] && [ -s "$f" ]; then ok "$k=$f"; else bad "VIGIL_TLS_MODE=custom needs $k pointing to a readable file"; fi
    done
  fi
  if [ "$tlsm" = acme ]; then
    # Compare DNS with this host's addresses: local interfaces plus the cloud metadata service's public IP
    # (AWS/GCP/Azure). No third-party "what is my IP" service is contacted.
    resolved="$(getent ahostsv4 "$domain" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')"
    if [ -z "$resolved" ]; then
      bad "$domain does not resolve — create an A record pointing to this host before installing (Let's Encrypt validates over HTTP)"
    else
      mine="$(hostname -I 2>/dev/null || true)"
      tok="$(curl -fs -m 2 -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token 2>/dev/null || true)"
      [ -n "$tok" ] && mine="$mine $(curl -fs -m 2 -H "X-aws-ec2-metadata-token: $tok" http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || true)"
      mine="$mine $(curl -fs -m 2 -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip 2>/dev/null || true)"
      mine="$mine $(curl -fs -m 2 -H 'Metadata: true' 'http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2021-02-01&format=text' 2>/dev/null || true)"
      match=0; for ip in $resolved; do case " $mine " in *" $ip "*) match=1;; esac; done
      if [ "$match" = 1 ]; then ok "$domain resolves to this host ($resolved)"
      else warn "$domain resolves to $resolved, which is not an address of this host ($(echo "$mine" | xargs)). Fine behind a load balancer/NAT that forwards 80/443 here; otherwise certificate issuance will fail."; fi
    fi
  fi
fi
ok "no vendor-hosted service is required (only your cloud and AI provider endpoints, if configured)"
if [ "$fails" -eq 0 ]; then info "preflight passed"; else die "$fails preflight check(s) failed"; fi
