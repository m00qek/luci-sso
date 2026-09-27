#!/bin/bash
# Captures the Authelia screenshot for docs/how-to/providers/authelia.md.
#
# Authelia is configured by file, so the guide is text; the one image is the
# consent page a user sees on their first SSO login. This starts Authelia
# (HTTPS on 443 as auth.example.com) with the client block from the guide,
# generated secrets and one test user, then signs that user in with the
# authorization request luci-sso sends (authelia.js). Everything is removed
# afterwards. Usage: authelia.sh (or `make idp-screenshots IDP=authelia`).

IDP=authelia
HOST=auth.example.com
AUTHELIA_IMAGE="authelia/authelia:4.39.28"

# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

setup

CLIENT_SECRET="$(secret 48)"
USER_PASSWORD="$(secret 24)"

authelia() {
	docker run --rm "$AUTHELIA_IMAGE" authelia "$@"
}
digest() {
	sed -n 's/^Digest: //p'
}

log "hashing the generated secrets"
CLIENT_DIGEST="$(authelia crypto hash generate pbkdf2 --variant sha512 --password "$CLIENT_SECRET" | digest)"
USER_DIGEST="$(authelia crypto hash generate argon2 --password "$USER_PASSWORD" | digest)"

mkdir -p "$WORK/config"
docker run --rm -v "$WORK/config:/c" "$ALPINE_IMAGE" sh -c \
	'apk add -q --no-cache openssl >/dev/null && openssl genrsa -out /c/jwks.pem 2048 2>/dev/null && chmod 644 /c/jwks.pem'

cat >"$WORK/config/users.yml" <<EOF
users:
  alice:
    displayname: 'Alice Example'
    password: '$USER_DIGEST'
    email: alice@example.com
    groups:
      - router-admins
EOF

# The client block is the one in the guide (step 1), with the optional
# consent_mode lines, so the consent page offers "Remember Consent".
cat >"$WORK/config/configuration.yml" <<EOF
server:
  address: 'tcp://0.0.0.0:443/'
  tls:
    certificate: /certs/chain.crt
    key: /certs/tls.key
authentication_backend:
  file:
    path: /config/users.yml
access_control:
  default_policy: one_factor
identity_validation:
  reset_password:
    jwt_secret: '$(secret 64)'
session:
  secret: '$(secret 64)'
  cookies:
    - domain: 'example.com'
      authelia_url: 'https://$HOST'
storage:
  encryption_key: '$(secret 64)'
  local:
    path: /data/db.sqlite3
notifier:
  filesystem:
    filename: /data/notification.txt
identity_providers:
  oidc:
    hmac_secret: '$(secret 64)'
    jwks:
      - key: {{ secret "/config/jwks.pem" | mindent 10 "|" | msquote }}
    claims_policies:
      luci_sso:
        id_token: ['email', 'name', 'groups']
    clients:
      - client_id: luci-router
        client_name: OpenWrt Router
        client_secret: '$CLIENT_DIGEST'
        public: false
        authorization_policy: one_factor
        redirect_uris:
          - https://router.example.com/cgi-bin/luci-sso/callback
        scopes:
          - openid
          - profile
          - email
          - groups
        userinfo_signed_response_alg: none
        token_endpoint_auth_method: client_secret_post
        claims_policy: luci_sso
        consent_mode: pre-configured
        pre_configured_consent_duration: 1y
EOF
chmod 644 "$WORK/config/users.yml" "$WORK/config/configuration.yml"

log "starting $AUTHELIA_IMAGE"
start app --network-alias "$HOST" --tmpfs /data \
	-e X_AUTHELIA_CONFIG_FILTERS=template \
	-v "$WORK/config:/config:ro" -v "$WORK/certs:/certs:ro" \
	"$AUTHELIA_IMAGE"
wait_for "https://$HOST/.well-known/openid-configuration"

capture authelia.js -e USER_PASSWORD="$USER_PASSWORD"
publish
