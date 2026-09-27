#!/bin/bash
# Shared helpers for the identity provider screenshot scripts. Sourced by
# <idp>.sh; not run on its own.
#
# Each IdP script gets:
#   - a work directory ($WORK) with a throwaway CA and a TLS certificate for
#     the IdP's example host name, removed on exit;
#   - its own docker network ($NET), on which the IdP answers at that host
#     name through a network alias, so the pages show example.com names;
#   - capture <script.js>: runs a Playwright script from this directory in
#     the devenv browser image, on that network, with the CA trusted;
#   - cleanup on exit: every container labelled with $LABEL, the network and
#     the work directory are removed, whatever happened.
#
# Nothing is published on the host, and every secret is generated per run.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$HERE/../../.." && pwd)"

# The devenv browser image (make build-images), and the Alpine image the
# screenshots target uses for oxipng. The Makefile exports both versions.
NODE_VERSION="${NODE_VERSION:-25}"
ALPINE_VERSION="${ALPINE_VERSION:-3.23}"
BROWSER_IMAGE="${BROWSER_IMAGE:-ghcr.io/m00qek/luci-sso-browser:node${NODE_VERSION}-alpine${ALPINE_VERSION}}"
ALPINE_IMAGE="alpine:${ALPINE_VERSION}"

OUT_DIR="${OUT_DIR:-$PROJECT_ROOT/docs/assets/screenshots/idp}"

# Set by the IdP script before it calls setup: IDP (a short name) and HOST
# (the IdP's example host name).
: "${IDP:?IDP must be set}" "${HOST:?HOST must be set}"

NET="luci-sso-shots-$IDP"
LABEL="luci-sso-shots=$IDP"
WORK=""

log() { echo "[$IDP] $*" >&2; }

# A random string of [A-Za-z0-9], for passwords and keys that exist only for
# one run.
secret() {
	local len="${1:-32}"
	LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$len" || true
}

cleanup() {
	local status=$?
	set +e
	local ids
	ids="$(docker ps -aq --filter "label=$LABEL")"
	if [ -n "$ids" ]; then
		# shellcheck disable=SC2086
		docker rm -f -v $ids >/dev/null
	fi
	docker volume ls -q --filter "label=$LABEL" | xargs -r docker volume rm >/dev/null
	docker network rm "$NET" >/dev/null 2>&1
	if [ -n "$WORK" ] && [ -d "$WORK" ]; then
		# Containers write some files as root: remove them from a container.
		docker run --rm -v "$WORK:/w" "$ALPINE_IMAGE" sh -c 'rm -rf /w/* /w/.[!.]*' >/dev/null 2>&1
		rm -rf "$WORK"
	fi
	[ "$status" -eq 0 ] && log "done" || log "failed (exit $status)"
	exit "$status"
}

# Creates the work directory, the network and the certificates, and arms the
# cleanup. Extra names for the certificate can be passed as arguments.
setup() {
	trap cleanup EXIT INT TERM
	WORK="$(mktemp -d "${TMPDIR:-/tmp}/luci-sso-shots-$IDP.XXXXXX")"
	chmod 755 "$WORK"
	mkdir -p "$WORK/certs" "$WORK/shots"
	chmod 777 "$WORK/shots"

	docker network create --label "$LABEL" "$NET" >/dev/null
	make_certs "$@"
}

# A throwaway CA (certs/ca.crt) and a certificate for $HOST and any extra
# names given (certs/tls.crt, certs/tls.key, certs/chain.crt), valid 2 days.
make_certs() {
	local sans="DNS:$HOST"
	local name
	for name in "$@"; do sans="$sans,DNS:$name"; done
	log "certificates for $HOST"
	docker run --rm -v "$WORK/certs:/c" -e SANS="$sans" -e HOST="$HOST" "$ALPINE_IMAGE" sh -ec '
		apk add -q --no-cache openssl >/dev/null
		cd /c
		openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
			-keyout ca.key -out ca.crt -days 2 -subj "/CN=luci-sso screenshots CA" 2>/dev/null
		openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
			-keyout tls.key -out tls.csr -subj "/CN=$HOST" 2>/dev/null
		printf "subjectAltName=%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n" "$SANS" > ext.cnf
		openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
			-out tls.crt -days 2 -extfile ext.cnf 2>/dev/null
		cat tls.crt ca.crt > chain.crt
		chmod 644 *
	'
}

# docker run with the run's label and network. Arguments: a container name
# suffix, then docker run options and the image and command.
start() {
	local name="$1"
	shift
	docker run -d --name "luci-sso-shots-$IDP-$name" --label "$LABEL" --network "$NET" "$@" >/dev/null
}

# Waits until a URL answers on the network with an HTTP status matching a
# shell pattern (default: any status below 500), trying every 2 seconds.
wait_for() {
	local url="$1" tries="${2:-120}" codes="${3:-[1-4]??}"
	log "waiting for $url"
	docker run --rm --label "$LABEL" --network "$NET" -v "$WORK/certs:/certs:ro" \
		--entrypoint sh "$BROWSER_IMAGE" -c '
			for i in $(seq '"$tries"'); do
				code=$(curl -s -o /dev/null -w "%{http_code}" --cacert /certs/ca.crt "'"$url"'" || true)
				case "$code" in '"$codes"') exit 0 ;; esac
				sleep 2
			done
			echo "timed out waiting for '"$url"'" >&2
			exit 1'
}

# Runs a Playwright script from this directory in the browser image. The
# script reads the environment passed with -e, finds the CA in /certs and
# writes PNGs to /shots. The browser profile and caches stay in memory.
capture() {
	local script="$1"
	shift
	docker run --rm --label "$LABEL" --network "$NET" --tmpfs /root --tmpfs /tmp --shm-size 1g \
		-v "$HERE:/scripts:ro" -v "$WORK/certs:/certs:ro" -v "$WORK/shots:/shots" \
		-e NODE_PATH=/app/node_modules -e NODE_EXTRA_CA_CERTS=/certs/ca.crt \
		-e IDP="$IDP" -e HOST="$HOST" "$@" \
		--entrypoint sh "$BROWSER_IMAGE" -c '
			mkdir -p /root/.pki/nssdb
			certutil -d sql:/root/.pki/nssdb -N --empty-password
			certutil -d sql:/root/.pki/nssdb -A -t "C,," -n shots-ca -i /certs/ca.crt
			exec node --no-warnings "/scripts/$0"' "$script"
}

# Compresses the captured PNGs losslessly (as `make screenshots` does) and
# copies them into $OUT_DIR, owned by the invoking user.
publish() {
	mkdir -p "$OUT_DIR"
	docker run --rm -v "$WORK/shots:/shots" "$ALPINE_IMAGE" sh -c \
		"apk add -q --no-cache oxipng >/dev/null && oxipng -q -o 4 --strip safe /shots/*.png && chown $(id -u):$(id -g) /shots/*.png"
	cp "$WORK/shots/"*.png "$OUT_DIR/"
	log "wrote $(cd "$WORK/shots" && ls ./*.png | sed 's|^\./||' | tr '\n' ' ')to ${OUT_DIR#"$PROJECT_ROOT"/}"
}
