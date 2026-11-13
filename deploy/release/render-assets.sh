#!/usr/bin/env bash
# Render the release assets for one version into OUT_DIR (used by .github/workflows/release.yml; runnable locally).
set -euo pipefail
usage() { cat <<EOF
Usage: $(basename "$0") VERSION REGISTRY OUT_DIR

Writes to OUT_DIR:
  compose.yaml                  compose file with images pinned to VERSION from REGISTRY
  env.template                  env template for a release install (VIGIL_VERSION, registry, release mode)
  vigil-deploy-VERSION.tar.gz   everything an install needs: compose.yaml, env.template, scripts/, postgres/, VERSION
  get.sh                        clean-VM bootstrap installer (if present in this tree)
  SHA256SUMS                    checksums of every file in OUT_DIR
EOF
}
case "${1:-}" in -h|--help) usage; exit 0;; esac
[ $# -eq 3 ] || { usage >&2; exit 2; }
VERSION="$1"; REGISTRY="$2"; OUT="$3"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "invalid version '$VERSION'" >&2; exit 2; }
[[ "$REGISTRY" =~ ^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)*$ ]] || { echo "invalid registry '$REGISTRY'" >&2; exit 2; }
DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
stage="$(mktemp -d)"; trap 'rm -rf "$stage"' EXIT
b="$stage/vigil-deploy-$VERSION"; mkdir -p "$b/scripts" "$b/postgres"

# compose.yaml: default registry and version pinned to this release (still overridable from .env).
{
  printf '# Vigil %s — release compose file. Images: %s/vigil-{api,web,agents}:%s\n' "$VERSION" "$REGISTRY" "$VERSION"
  sed -e "s|\${VIGIL_IMAGE_REGISTRY:-ghcr.io/onelab-x}|\${VIGIL_IMAGE_REGISTRY:-$REGISTRY}|g" \
      -e "s|\${VIGIL_VERSION:?VIGIL_VERSION must be set}|\${VIGIL_VERSION:-$VERSION}|g" "$DEPLOY_DIR/compose.yaml"
} > "$b/compose.yaml"
grep -q "vigil-api:\${VIGIL_VERSION:-$VERSION}" "$b/compose.yaml" || { echo "compose.yaml render failed" >&2; exit 1; }

sed -e "s|^VIGIL_VERSION=.*|VIGIL_VERSION=$VERSION|" \
    -e "s|^VIGIL_IMAGE_REGISTRY=.*|VIGIL_IMAGE_REGISTRY=$REGISTRY|" \
    -e "s|^VIGIL_INSTALL_MODE=.*|VIGIL_INSTALL_MODE=release|" "$DEPLOY_DIR/env.template" > "$b/env.template"
grep -q "^VIGIL_VERSION=$VERSION$" "$b/env.template" || { echo "env.template render failed" >&2; exit 1; }

cp "$DEPLOY_DIR"/scripts/*.sh "$b/scripts/"
cp "$DEPLOY_DIR"/postgres/* "$b/postgres/"
cp "$DEPLOY_DIR/empty-credentials.json" "$b/"
[ -d "$DEPLOY_DIR/proxy" ] && cp -R "$DEPLOY_DIR/proxy" "$b/"
printf '%s\n' "$VERSION" > "$b/VERSION"
chmod 755 "$b"/scripts/*.sh "$b"/postgres/*.sh

# Reproducible-ish tarball: fixed owner and sorted entries.
tar_opts=(--owner=0 --group=0 --numeric-owner)
tar --version 2>/dev/null | grep -q GNU || tar_opts=(--uid 0 --gid 0)
(cd "$stage" && find "vigil-deploy-$VERSION" -print | LC_ALL=C sort | tar "${tar_opts[@]}" --no-recursion -czf "$OUT/vigil-deploy-$VERSION.tar.gz" -T -)
cp "$b/compose.yaml" "$b/env.template" "$OUT/"
if [ -f "$DEPLOY_DIR/get.sh" ]; then install -m 755 "$DEPLOY_DIR/get.sh" "$OUT/get.sh"; fi

sums="$(mktemp)"
(cd "$OUT" && find . -maxdepth 1 -type f ! -name SHA256SUMS ! -name '*.sigstore.json' -print | sed 's|^\./||' | LC_ALL=C sort \
  | while IFS= read -r f; do if command -v sha256sum >/dev/null; then sha256sum "$f"; else shasum -a 256 "$f"; fi; done) > "$sums"
mv "$sums" "$OUT/SHA256SUMS"; chmod 644 "$OUT/SHA256SUMS"
echo "release assets for $VERSION in $OUT:"; (cd "$OUT" && ls -l)
