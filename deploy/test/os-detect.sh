#!/usr/bin/env bash
# Run get.sh's detect_os inside each supported distro image and check it picks the right package manager
# without clobbering the --version flag (os-release defines its own VERSION variable).
#   bash deploy/test/os-detect.sh            # all supported distros
#   bash deploy/test/os-detect.sh debian:12  # just these images
set -euo pipefail

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  sed -n '2,5p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# image=expected package manager; tags pinned, never latest
IMAGES=("ubuntu:22.04=apt" "ubuntu:24.04=apt" "debian:12=apt" "rockylinux:9=dnf" "almalinux:9=dnf" "amazonlinux:2023=dnf")
if [ $# -gt 0 ]; then
  sel=()
  for want in "$@"; do for e in "${IMAGES[@]}"; do [ "${e%%=*}" != "$want" ] || sel+=("$e"); done; done
  [ ${#sel[@]} -gt 0 ] || { echo "no supported image matches: $*" >&2; exit 2; }
  IMAGES=("${sel[@]}")
fi

# shellcheck disable=SC2016  # expanded inside the container
PROBE='set -euo pipefail
ok(){ echo "ok: $*"; }; warn(){ echo "warn: $*"; }; die(){ echo "die: $*" >&2; exit 1; }
eval "$(sed -n "/^detect_os() {/,/^}/p" /m/deploy/get.sh)"
VERSION=9.8.7
detect_os
[ "$VERSION" = 9.8.7 ] || die "detect_os overwrote VERSION with \"$VERSION\""
[ "$PKG" = "$WANT_PKG" ] || die "PKG=$PKG, expected $WANT_PKG"
[ "$PKG" != apt ] || [ -n "$OS_CODENAME" ] || die "apt distro without VERSION_CODENAME"
echo "PKG=$PKG codename=${OS_CODENAME:-none}"'

fails=0
for e in "${IMAGES[@]}"; do
  img="${e%%=*}"; pkg="${e#*=}"
  printf '== %s\n' "$img"
  if ! docker run --rm -e WANT_PKG="$pkg" -v "$ROOT:/m:ro" "$img" bash -c "$PROBE"; then
    fails=$((fails + 1))
  fi
done
if [ "$fails" -gt 0 ]; then echo "FAIL: $fails image(s)" >&2; exit 1; fi
echo "PASS: OS detection on ${#IMAGES[@]} image(s)"
