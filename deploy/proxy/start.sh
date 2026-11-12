#!/bin/sh
# Renders the Caddyfile from validated environment values and starts Caddy (runs inside the pinned caddy image).
set -eu
case "$VIGIL_DOMAIN" in *[!A-Za-z0-9.-]*|"") echo "invalid VIGIL_DOMAIN" >&2; exit 1;; esac
case "${VIGIL_ACME_EMAIL:-}" in *[!A-Za-z0-9.@+_-]*) echo "invalid VIGIL_ACME_EMAIL" >&2; exit 1;; esac
cfg=/tmp/Caddyfile
{
  echo "{"
  [ -n "${VIGIL_ACME_EMAIL:-}" ] && echo "	email ${VIGIL_ACME_EMAIL}"
  echo "}"
  echo "${VIGIL_DOMAIN} {"
  case "$VIGIL_TLS_MODE" in
    acme) ;;                                             # automatic Let's Encrypt (ZeroSSL fallback)
    custom) echo "	tls /certs/cert.pem /certs/key.pem";;  # your own certificate + key (VIGIL_TLS_CERT_FILE/KEY_FILE)
    internal) echo "	tls internal";;                     # Caddy's local CA (private networks; browsers will warn)
    *) echo "VIGIL_TLS_MODE must be acme, custom or internal" >&2; exit 1;;
  esac
  cat <<'CADDY'
	encode zstd gzip
	header {
		Strict-Transport-Security "max-age=31536000; includeSubDomains"
		X-Content-Type-Options "nosniff"
		Referrer-Policy "strict-origin-when-cross-origin"
		-Server
	}
	reverse_proxy web:3000
}
CADDY
} > "$cfg"
if [ "$VIGIL_TLS_MODE" = custom ]; then
  [ -s /certs/cert.pem ] && [ -s /certs/key.pem ] || { echo "VIGIL_TLS_MODE=custom needs VIGIL_TLS_CERT_FILE and VIGIL_TLS_KEY_FILE" >&2; exit 1; }
fi
caddy validate --config "$cfg" --adapter caddyfile >/dev/null
exec caddy run --config "$cfg" --adapter caddyfile
