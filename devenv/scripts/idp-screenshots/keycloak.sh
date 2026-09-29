#!/bin/bash
# Captures the Keycloak screenshots for docs/how-to/providers/keycloak.md.
#
# Starts Keycloak (dev mode, HTTPS on 443 as auth.example.com) on its own
# network with a generated admin password, creates the realm `home`, then
# walks the admin console through the guide's steps (keycloak.js) and removes
# everything. Usage: keycloak.sh (or `make idp-screenshots IDP=keycloak`).

IDP=keycloak
HOST=auth.example.com
KEYCLOAK_IMAGE="quay.io/keycloak/keycloak:26.7.4"

# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

setup
ADMIN_PASSWORD="$(secret 24)"

log "starting $KEYCLOAK_IMAGE"
# Keycloak runs as an unprivileged user: let it bind 443 inside its own
# network namespace.
start keycloak --network-alias "$HOST" \
	--sysctl net.ipv4.ip_unprivileged_port_start=0 \
	--tmpfs /tmp --tmpfs /opt/keycloak/data \
	-v "$WORK/certs:/certs:ro" \
	-e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD="$ADMIN_PASSWORD" \
	"$KEYCLOAK_IMAGE" start-dev \
	--http-enabled=false --https-port=443 \
	--https-certificate-file=/certs/chain.crt --https-certificate-key-file=/certs/tls.key \
	--hostname="https://$HOST"
wait_for "https://$HOST/realms/master/.well-known/openid-configuration" 150

capture keycloak.js -e ADMIN_PASSWORD="$ADMIN_PASSWORD"
publish
