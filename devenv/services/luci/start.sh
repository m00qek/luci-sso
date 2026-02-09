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

# 4. Minimal rpcd mock
mkdir -p /usr/libexec/rpcd
cat <<'EOF' >/usr/libexec/rpcd/system
#!/bin/sh
case "$1" in
	list) echo '{"info":{},"board":{}}' ;;
	call) cat /etc/board.json ;;
esac
EOF
chmod +x /usr/libexec/rpcd/system

# 5. Initial UCI Setup (skip reload_config on boot)
BOOTING=1 /bin/sh /usr/local/bin/setup-uci.sh

# 6. Hot Reload Watcher (Background)
watch_setup() {
  echo "👀 Starting setup-uci watcher..."
  while inotifywait -e close_write /usr/local/bin/setup-uci.sh 2>/dev/null; do
    echo "🔄 Setup script change detected, re-applying..."
    /bin/sh /usr/local/bin/setup-uci.sh
  done
}
watch_setup &

# 7. SSO Permissions
chmod +x /www/cgi-bin/luci-sso 2>/dev/null || true

# 8. Core Daemons
/sbin/ubusd &
sleep 1
/sbin/logd -S 64 &
/sbin/rpcd &

# 9. One-time Setup
echo "🔄 Running setup..."
mkdir -p /etc/uci-defaults
cp -r /usr/share/luci-sso/uci-defaults/* /etc/uci-defaults/ 2>/dev/null || true
for f in /etc/uci-defaults/*; do
  [ -e "$f" ] && (. "$f") && rm -f "$f" 2>/dev/null || true
done

# 10. Root Password
printf "admin\nadmin\n" | passwd root >/dev/null 2>&1

# 11. Execution Mode
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
