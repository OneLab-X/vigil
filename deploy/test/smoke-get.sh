#!/usr/bin/env bash
# Installer smoke test: install Vigil with get.sh exactly as a user would, but from locally built images pushed to a
# throwaway local registry and release assets served from a local HTTP server. Then assert /readyz, first-owner login,
# idempotent re-run, --reset, backup, restore onto fresh secrets, same-version upgrade, rollback and uninstall.
#
# Needs: root, Docker, python3, curl, and images vigil/{api,web,agents}:<VERSION> built from this checkout
# (docker compose -f deploy/compose.yaml -f deploy/compose.build.yaml --env-file deploy/env.template build).
set -euo pipefail
usage() { echo "Usage: sudo $(basename "$0") [--keep] [--tls]   (--keep: leave it running; --tls: install with --domain vigil.test --tls-mode internal)"; }
KEEP=0; TLS=0
while [ $# -gt 0 ]; do case "$1" in --keep) KEEP=1; shift;; --tls) TLS=1; shift;; -h|--help) usage; exit 0;; *) usage >&2; exit 2;; esac; done
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
REG_PORT="${SMOKE_REGISTRY_PORT:-5000}"; ASSET_PORT="${SMOKE_ASSET_PORT:-8765}"
REGISTRY="localhost:$REG_PORT/onelab-x"
DATA_DIR="${SMOKE_DATA_DIR:-/opt/vigil-smoke}"
WORK="$(mktemp -d)"
step() { printf '\n\033[1m### %s\033[0m\n' "$*"; }
cleanup() {
  [ -n "${HTTP_PID:-}" ] && kill "$HTTP_PID" 2>/dev/null || true
  if [ "$KEEP" = 0 ]; then
    [ -f "$DATA_DIR/.env" ] && VIGIL_PURGE_CONFIRM="$(hostname)" VIGIL_HOME="$DATA_DIR" bash "$DATA_DIR/scripts/vigil.sh" uninstall --purge --yes >/dev/null 2>&1 || true
    rm -rf "$DATA_DIR" "$DATA_DIR".reset-*
    docker rm -f vigil-smoke-registry >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

step "local registry + images ($REGISTRY, $VERSION)"
docker rm -f vigil-smoke-registry >/dev/null 2>&1 || true
docker run -d --name vigil-smoke-registry -p "127.0.0.1:$REG_PORT:5000" registry:2.8.3 >/dev/null
for _ in $(seq 1 30); do curl -fs "http://127.0.0.1:$REG_PORT/v2/" >/dev/null && break; sleep 1; done
for n in api web agents; do
  docker tag "vigil/$n:$VERSION" "$REGISTRY/vigil-$n:$VERSION"
  docker push -q "$REGISTRY/vigil-$n:$VERSION" >/dev/null
done

step "render release assets and serve them"
mkdir -p "$WORK/www/v$VERSION"
bash "$ROOT/deploy/release/render-assets.sh" "$VERSION" "$REGISTRY" "$WORK/www/v$VERSION" >/dev/null
printf '{"tag_name":"v%s"}\n' "$VERSION" > "$WORK/www/latest.json"
(cd "$WORK/www" && exec python3 -m http.server "$ASSET_PORT" --bind 127.0.0.1 >/dev/null 2>&1) & HTTP_PID=$!
for _ in $(seq 1 30); do curl -fs "http://127.0.0.1:$ASSET_PORT/latest.json" >/dev/null && break; sleep 1; done
export VIGIL_RELEASE_BASE_URL="http://127.0.0.1:$ASSET_PORT" VIGIL_RELEASE_API_URL="http://127.0.0.1:$ASSET_PORT/latest.json"
export VIGIL_VERIFY_SIGNATURES=off   # local images are unsigned; signature checks are exercised in release.yml

step "tampered bundle is rejected"
cp "$WORK/www/v$VERSION/SHA256SUMS" "$WORK/sums.bak"
sed -i.tmp "s/^[0-9a-f]\{64\}\(  vigil-deploy\)/0000000000000000000000000000000000000000000000000000000000000000\1/" "$WORK/www/v$VERSION/SHA256SUMS"
if bash "$WORK/www/v$VERSION/get.sh" --data-dir "$DATA_DIR" --yes --admin-email a@example.com --admin-name A --org O > "$WORK/tamper.log" 2>&1; then
  echo "FAIL: install succeeded with a bad checksum" >&2; exit 1; fi
grep -q "checksum mismatch" "$WORK/tamper.log" || { cat "$WORK/tamper.log"; echo "FAIL: wrong error" >&2; exit 1; }
[ ! -e "$DATA_DIR/.env" ] || { echo "FAIL: files written despite bad checksum" >&2; exit 1; }
cp "$WORK/sums.bak" "$WORK/www/v$VERSION/SHA256SUMS"; echo "ok: rejected"

tls_args=(); [ "$TLS" = 1 ] && tls_args=(--domain vigil.test --tls-mode internal)
step "get.sh fresh install (latest version via API, non-interactive) ${tls_args[*]}"
curl -fsSL "$VIGIL_RELEASE_BASE_URL/v$VERSION/get.sh" | bash -s -- --data-dir "$DATA_DIR" --yes "${tls_args[@]}" \
  --admin-email owner@example.com --admin-name "Smoke Owner" --org "Smoke Org" | tee "$WORK/install.log"
[ "$(stat -c %a "$DATA_DIR/.env" 2>/dev/null || stat -f %Lp "$DATA_DIR/.env")" = 600 ] || { echo "FAIL: .env not mode 600" >&2; exit 1; }
grep -q '^VIGIL_INSTALL_MODE=release$' "$DATA_DIR/.env" || { echo "FAIL: not a release install" >&2; exit 1; }
! grep -q 'One-time password:' "$WORK/install.log" || { echo "FAIL: password printed to a non-terminal" >&2; exit 1; }
PW="$(cat "$DATA_DIR/initial-owner-password")"; [ -n "$PW" ] || { echo "FAIL: no password file" >&2; exit 1; }
KEY_BEFORE="$(grep '^VIGIL_SECRET_KEY=' "$DATA_DIR/.env")"

step "status + readyz"
vigil() { VIGIL_HOME="$DATA_DIR" bash "$DATA_DIR/scripts/vigil.sh" "$@"; }
vigil status

if [ "$TLS" = 0 ]; then
step "only the web port is published, on loopback"
pub="$(docker ps --filter "label=com.docker.compose.project=vigil" --format '{{.Names}} {{.Ports}}' | grep -- '->' || true)"
echo "$pub"
if ! { [ "$(grep -c -- '->' <<<"$pub")" = 1 ] && grep -q 'web' <<<"$pub" && grep -q '127.0.0.1:3000->3000' <<<"$pub"; }; then
  echo "FAIL: unexpected published ports" >&2; exit 1; fi
BASE=http://127.0.0.1:3000; ORIGIN=http://localhost:3000; CURL=(curl -s)
else
step "only the proxy publishes 80/443; web is not published"
pub="$(docker ps --filter "label=com.docker.compose.project=vigil" --format '{{.Names}} {{.Ports}}' | grep -- '->' || true)"
echo "$pub"
if ! { grep -q 'proxy' <<<"$pub" && ! grep -q 'web-1 .*->' <<<"$pub" && grep -q ':443->443' <<<"$pub" && grep -q ':80->80' <<<"$pub"; }; then
  echo "FAIL: unexpected published ports" >&2; exit 1; fi
grep -q '^VIGIL_WEB_ORIGIN=https://vigil.test$' "$DATA_DIR/.env" || { echo "FAIL: origin not https" >&2; exit 1; }
step "HTTP redirects to HTTPS; HSTS set"
loc="$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' --resolve vigil.test:80:127.0.0.1 http://vigil.test/login)"
echo "$loc"; [[ "$loc" =~ ^30[178]\ https://vigil.test/login ]] || { echo "FAIL: no redirect" >&2; exit 1; }
curl -sk -D - -o /dev/null --resolve vigil.test:443:127.0.0.1 https://vigil.test/login | grep -qi '^strict-transport-security: max-age=31536000' \
  || { echo "FAIL: no HSTS" >&2; exit 1; }
BASE=https://vigil.test; ORIGIN=https://vigil.test; CURL=(curl -sk --resolve vigil.test:443:127.0.0.1)
fi

step "first-owner login through the web proxy"
code="$("${CURL[@]}" -o "$WORK/login.json" -w '%{http_code}' -H 'content-type: application/json' -H "origin: $ORIGIN" \
  --data "{\"email\":\"owner@example.com\",\"password\":\"$PW\"}" "$BASE/api/v1/auth/login")"
cat "$WORK/login.json"; echo
if ! { [ "$code" = 200 ] && grep -q '"mustChangePassword":true' "$WORK/login.json"; }; then echo "FAIL: login returned $code" >&2; exit 1; fi

step "re-running get.sh is idempotent (keeps secrets and data)"
bash "$WORK/www/v$VERSION/get.sh" --data-dir "$DATA_DIR" --yes > "$WORK/rerun.log" 2>&1 || { cat "$WORK/rerun.log"; exit 1; }
grep -q "existing installation found" "$WORK/rerun.log"
[ "$(grep '^VIGIL_SECRET_KEY=' "$DATA_DIR/.env")" = "$KEY_BEFORE" ] || { echo "FAIL: secret key changed" >&2; exit 1; }
grep -q "users already exist" "$WORK/rerun.log"

step "--reset requires typed confirmation"
if bash "$WORK/www/v$VERSION/get.sh" --data-dir "$DATA_DIR" --yes --reset > "$WORK/reset.log" 2>&1; then echo "FAIL: reset without confirmation" >&2; exit 1; fi
grep -q "VIGIL_RESET_CONFIRM" "$WORK/reset.log"

step "backup"
vigil backup
ls "$DATA_DIR/backups"/*/manifest.json >/dev/null

step "restore onto a fresh install with different secrets (second-VM round trip)"
bk="$(find "$DATA_DIR/backups" -mindepth 1 -maxdepth 1 -type d | sort | tail -1)"
cp -R "$bk" "$WORK/backup"
VIGIL_RESET_CONFIRM="$(hostname)" bash "$WORK/www/v$VERSION/get.sh" --data-dir "$DATA_DIR" --yes --reset "${tls_args[@]}" \
  --admin-email other@example.com --admin-name Other --org Other > "$WORK/reinstall.log" 2>&1 || { cat "$WORK/reinstall.log"; exit 1; }
[ "$(grep '^VIGIL_SECRET_KEY=' "$DATA_DIR/.env")" != "$KEY_BEFORE" ] || { echo "FAIL: reset kept the old key" >&2; exit 1; }
cp -R "$WORK/backup" "$DATA_DIR/backups/restored"
vigil restore "$DATA_DIR/backups/restored" --yes
[ "$(grep '^VIGIL_SECRET_KEY=' "$DATA_DIR/.env")" = "$KEY_BEFORE" ] || { echo "FAIL: restore did not bring back the key" >&2; exit 1; }
vigil status
code="$("${CURL[@]}" -o "$WORK/login2.json" -w '%{http_code}' -H 'content-type: application/json' -H "origin: $ORIGIN" \
  --data "{\"email\":\"owner@example.com\",\"password\":\"$PW\"}" "$BASE/api/v1/auth/login")"
[ "$code" = 200 ] || { cat "$WORK/login2.json"; echo "FAIL: original owner cannot log in after restore ($code)" >&2; exit 1; }

step "upgrade to the same version (download, verify, swap files, health gate)"
vigil upgrade --version "$VERSION" --yes
vigil status

step "rollback to the pre-upgrade backup (health-gated restore)"
vigil rollback --yes
vigil status

step "uninstall keeps volumes by default"
vigil uninstall --yes
docker volume ls --format '{{.Name}}' | grep -q '^vigil_pgdata$' || { echo "FAIL: volume removed without --purge" >&2; exit 1; }

echo; echo "SMOKE TEST PASSED"
