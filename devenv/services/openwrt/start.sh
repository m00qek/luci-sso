#!/bin/sh
set -e

# Source the shared orchestration library
. /usr/local/bin/base-startup.sh

# 1. Parse Arguments
parse_args "$@"

# Disable standard background uhttpd to prevent "Address in use"
if [ -f /etc/init.d/uhttpd ]; then
  /etc/init.d/uhttpd stop 2>/dev/null || true
  /etc/init.d/uhttpd disable 2>/dev/null || true
fi

# 2. Essential runtime directories
mkdir -p /var/run/ubus /var/run/luci-sso /tmp/sessions /tmp/luci-modulecache /www /etc/config

# 3. Dynamic board.json generation
cat <<EOF >/etc/board.json
{
	"model": { "id": "generic", "name": "OpenWrt Container" },
	"network": { "lan": { "ifname": "eth0", "protocol": "static" } },
	"credentials": { "ssh_authorized_keys": {} },
	"release": { "distribution": "OpenWrt", "version": "${SDK_VERSION:-24.10}" }
}
EOF

# 4. Initial UCI Setup (skip reload_config on boot)
BOOTING=1 /bin/sh /usr/local/bin/setup-uci.sh

# 5. Hot Reload Watcher (Background)
watch_setup() {
  echo "👀 Starting setup-uci watcher..."
  while inotifywait -e close_write /usr/local/bin/setup-uci.sh 2>/dev/null; do
    echo "🔄 Setup script change detected, re-applying..."
    /bin/sh /usr/local/bin/setup-uci.sh
  done
}
watch_setup &

# 6. SSO Permissions
chmod +x /www/cgi-bin/luci-sso 2>/dev/null || true
mkdir -p /usr/sbin
cp /usr/share/luci-sso/test/../files/usr/sbin/luci-sso-cleanup /usr/sbin/ 2>/dev/null || true
chmod +x /usr/sbin/luci-sso-cleanup 2>/dev/null || true

# 6a. Link native crypto backend to the path ucode expects
: ${CRYPTO_LIB:?CRYPTO_LIB must be set}
mkdir -p /usr/lib/ucode/luci_sso
ln -sf /luci_sso/backends/${CRYPTO_LIB}/luci_sso/native.so /usr/lib/ucode/luci_sso/native.so

# 7. Core Daemons
# procd is not this container's init, but it runs as a service manager all
# the same: not PID 1, it only connects to ubus and offers its `service` and
# `system` objects. That gives the devenv what a router has: rpcd as a procd
# instance (so /etc/init.d/rpcd reload works), and the config triggers that
# run /etc/init.d/luci-sso on every apply of /etc/config/luci-sso.
/sbin/ubusd &
sleep 1
/sbin/logd -S 64 &
/sbin/procd &
for i in 1 2 3 4 5 6 7 8 9 10; do
  ubus -t 1 list service >/dev/null 2>&1 && break
  sleep 1
done
/etc/init.d/rpcd start
for i in 1 2 3 4 5 6 7 8 9 10; do
  ubus -t 1 list session >/dev/null 2>&1 && break
  sleep 1
done

# 8. One-time Setup
echo "🔄 Running setup..."
mkdir -p /etc/uci-defaults
cp -r /usr/share/luci-sso/uci-defaults/* /etc/uci-defaults/ 2>/dev/null || true
for f in /etc/uci-defaults/*; do
  [ -e "$f" ] && (. "$f") && rm -f "$f" 2>/dev/null || true
done
# What the package's postinst does after the uci-defaults: start the init
# script, which registers its procd trigger.
/etc/init.d/luci-sso enable
/etc/init.d/luci-sso start
# reload_config sends a config.change event only for files whose checksum
# changed since its last run: record the first checksums now.
/sbin/reload_config >/dev/null 2>&1 || true

# 9. Root Password
printf "admin\nadmin\n" | passwd root >/dev/null 2>&1

# 10. Execution Mode
if [ "$SHOULD_FOREGROUND" = "true" ]; then
  echo "🚀 Starting LuCI..."
  exec /usr/sbin/uhttpd -f \
    $(for addr in $(uci -q get uhttpd.main.listen_https); do printf -- "-s %s " "$addr"; done) \
    -C "$(uci -q get uhttpd.main.cert)" \
    -K "$(uci -q get uhttpd.main.key)" \
    -u "$(uci -q get uhttpd.main.rpc_prefix)" \
    -x "$(uci -q get uhttpd.main.cgi_prefix)" \
    -h /www
fi

# Fallback to idle
stay_alive
