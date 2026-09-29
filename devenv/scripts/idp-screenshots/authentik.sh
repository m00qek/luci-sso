#!/bin/bash
# Captures the Authentik screenshots for docs/how-to/providers/authentik.md.
#
# Starts Authentik (server, worker and PostgreSQL, as in the upstream compose
# file, minus host ports and the docker socket) behind a Caddy TLS front
# (authentik.example.com) on its own network, with a generated bootstrap
# password for akadmin, then walks the admin interface through the guide's
# steps (authentik.js). Everything is removed afterwards. Usage: authentik.sh
# (or `make idp-screenshots IDP=authentik`).

IDP=authentik
HOST=authentik.example.com
AUTHENTIK_IMAGE="ghcr.io/goauthentik/server:2026.8.3"
POSTGRES_IMAGE="postgres:16-alpine"
CADDY_IMAGE="caddy:2.10-alpine"

# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

setup

PG_PASS="$(secret 32)"
AUTHENTIK_SECRET_KEY="$(secret 60)"
ADMIN_PASSWORD="$(secret 24)"
DB="luci-sso-shots-$IDP-db"

cat >"$WORK/Caddyfile" <<EOF
{
	auto_https off
	admin off
}
https://$HOST:443 {
	tls /certs/chain.crt /certs/tls.key
	reverse_proxy luci-sso-shots-$IDP-server:9000
}
EOF

log "starting $POSTGRES_IMAGE"
start db --tmpfs /var/lib/postgresql/data \
	-e POSTGRES_DB=authentik -e POSTGRES_USER=authentik -e POSTGRES_PASSWORD="$PG_PASS" \
	"$POSTGRES_IMAGE"
for _ in $(seq 60); do
	docker exec "$DB" pg_isready -q -d authentik -U authentik 2>/dev/null && break
	sleep 1
done

authentik_env=(
	-e AUTHENTIK_POSTGRESQL__HOST="$DB" -e AUTHENTIK_POSTGRESQL__NAME=authentik
	-e AUTHENTIK_POSTGRESQL__USER=authentik -e AUTHENTIK_POSTGRESQL__PASSWORD="$PG_PASS"
	-e AUTHENTIK_SECRET_KEY="$AUTHENTIK_SECRET_KEY"
	-e AUTHENTIK_BOOTSTRAP_PASSWORD="$ADMIN_PASSWORD" -e AUTHENTIK_BOOTSTRAP_EMAIL=akadmin@example.com
	-e AUTHENTIK_DISABLE_UPDATE_CHECK=true -e AUTHENTIK_ERROR_REPORTING__ENABLED=false
	--tmpfs /data --tmpfs /templates --tmpfs /tmp --shm-size 512m
)
log "starting $AUTHENTIK_IMAGE"
start server "${authentik_env[@]}" "$AUTHENTIK_IMAGE" server
start worker "${authentik_env[@]}" "$AUTHENTIK_IMAGE" worker
start tls --network-alias "$HOST" \
	-v "$WORK/Caddyfile:/etc/caddy/Caddyfile:ro" -v "$WORK/certs:/certs:ro" \
	"$CADDY_IMAGE"
wait_for "https://$HOST/-/health/ready/" 180 200
# The worker applies the default flows and the self-signed certificate after
# start-up; the login flow answers 404 until then.
wait_for "https://$HOST/api/v3/flows/executor/default-authentication-flow/" 180 200

capture authentik.js -e ADMIN_PASSWORD="$ADMIN_PASSWORD"
publish
