#!/bin/bash
# Captures the Pocket ID screenshots for docs/how-to/providers/pocket-id.md
# and docs/tutorials/pocket-id-sso-login.md.
#
# Starts Pocket ID behind a Caddy TLS front (id.example.com) on its own
# network, then signs up the first administrator through /setup with a
# virtual passkey authenticator and walks the admin UI through the guide's
# steps (pocket-id.js). Everything is removed afterwards. Usage: pocket-id.sh
# (or `make idp-screenshots IDP=pocket-id`).

IDP=pocket-id
HOST=id.example.com
POCKET_ID_IMAGE="ghcr.io/pocket-id/pocket-id:v2.16.0"
CADDY_IMAGE="caddy:2.10-alpine"

# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

setup

cat >"$WORK/Caddyfile" <<EOF
{
	auto_https off
	admin off
}
https://$HOST:443 {
	tls /certs/chain.crt /certs/tls.key
	reverse_proxy luci-sso-shots-$IDP-app:1411
}
EOF

log "starting $POCKET_ID_IMAGE"
start app --tmpfs /app/data \
	-e APP_URL="https://$HOST" -e TRUST_PROXY=true -e ENCRYPTION_KEY="$(secret 32)" \
	"$POCKET_ID_IMAGE"
start tls --network-alias "$HOST" \
	-v "$WORK/Caddyfile:/etc/caddy/Caddyfile:ro" -v "$WORK/certs:/certs:ro" \
	"$CADDY_IMAGE"
wait_for "https://$HOST/.well-known/openid-configuration"

capture pocket-id.js
publish
