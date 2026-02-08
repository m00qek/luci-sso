#!/bin/sh
# setup-uci.sh: Programmatic Router Configuration
echo "⚙️  Applying UCI configuration..."

# Ensure config files exist to prevent "Entry not found"
rm -f /etc/config/system /etc/config/network /etc/config/uhttpd /etc/config/luci-sso
touch /etc/config/system /etc/config/network /etc/config/uhttpd /etc/config/luci-sso

# --- SYSTEM ---
# Try to set, if fails (e.g. no system section), add one
if ! uci -q get system.@system[0] >/dev/null; then
  uci -q add system system
fi
uci -q set system.@system[0].hostname="${FQDN_LUCI%%.*}"
uci -q set system.@system[0].timezone="UTC"
uci commit system

# --- NETWORK ---
uci -q set network.loopback=interface
uci -q set network.loopback.device="lo"
uci -q set network.loopback.proto="static"
uci -q set network.loopback.ipaddr="127.0.0.1"
uci -q set network.loopback.netmask="255.0.0.0"
uci commit network

# --- UHTTPD ---
uci -q set uhttpd.main=uhttpd
uci -q del uhttpd.main.listen_https
uci -q add_list uhttpd.main.listen_https="0.0.0.0:443"
uci -q set uhttpd.main.home="/www"
uci -q set uhttpd.main.rpc_prefix="/ubus"
uci -q set uhttpd.main.cert="/etc/uhttpd.crt"
uci -q set uhttpd.main.key="/etc/uhttpd.key"
uci -q set uhttpd.main.cgi_prefix="/cgi-bin"
uci commit uhttpd

# --- LUCI-SSO ---
# Use the variables passed from docker-compose
uci -q set luci-sso.default=oidc
uci -q set luci-sso.default.enabled="1"
uci -q set luci-sso.default.issuer_url="${ISSUER_URL}"
[ -n "${ISSUER_INTERNAL_URL}" ] && uci -q set luci-sso.default.internal_issuer_url="${ISSUER_INTERNAL_URL}"
uci -q set luci-sso.default.redirect_uri="${REDIRECT_URL}/cgi-bin/luci-sso/callback"
uci -q set luci-sso.default.client_id="luci-router"
uci -q set luci-sso.default.client_secret="secret-key-123"
uci -q set luci-sso.default.scope="openid profile email"
uci -q set luci-sso.default.clock_tolerance="300"

uci -q add luci-sso user
uci -q set luci-sso.@user[0].rpcd_user="root"
uci -q set luci-sso.@user[0].rpcd_password="admin"
uci -q add_list luci-sso.@user[0].email="admin@example.com"

uci commit luci-sso

echo "✅ UCI configuration applied."

# Signal services to reload (unless we are booting)
if [ -z "$BOOTING" ]; then
  /sbin/reload_config 2>/dev/null || true
fi

