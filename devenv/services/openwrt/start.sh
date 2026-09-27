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
# A container runs no procd, so this stands in for its `system` ubus object.
# It answers the two calls LuCI makes, board and info, in the shape procd
# uses, so the header shows the hostname and Status > Overview has its values.
mkdir -p /usr/libexec/rpcd
cat <<'EOF' >/usr/libexec/rpcd/system
#!/bin/sh
. /usr/share/libubox/jshn.sh

meminfo() { sed -n "s/^$1: *\([0-9]*\) kB/\1/p" /proc/meminfo | awk '{ printf "%.0f", $1 * 1024 }'; }

case "$1" in
	list) echo '{"info":{},"board":{}}' ;;
	call)
		json_init
		case "$2" in
			board)
				. /etc/openwrt_release
				json_add_string kernel "$(sed -n 's/^Version: \([0-9.]*\).*/\1/p' /usr/lib/opkg/info/kernel.control)"
				json_add_string hostname "$(uci -q get system.@system[0].hostname || echo OpenWrt)"
				json_add_string system "$DISTRIB_ARCH"
				json_add_string model "$(jsonfilter -i /etc/board.json -e '@.model.name')"
				json_add_string board_name "$(jsonfilter -i /etc/board.json -e '@.model.id')"
				json_add_object release
				json_add_string distribution "$DISTRIB_ID"
				json_add_string version "$DISTRIB_RELEASE"
				json_add_string revision "$DISTRIB_REVISION"
				json_add_string target "$DISTRIB_TARGET"
				json_add_string description "$DISTRIB_DESCRIPTION"
				json_close_object
				;;
			info)
				json_add_int localtime "$(date +%s)"
				json_add_int uptime "$(cut -d. -f1 /proc/uptime)"
				json_add_array load
				for l in $(cut -d' ' -f1-3 /proc/loadavg); do
					json_add_int "" "$(awk -v l="$l" 'BEGIN { printf "%d", l * 65536 }')"
				done
				json_close_array
				json_add_object memory
				for f in total:MemTotal free:MemFree shared:Shmem buffered:Buffers available:MemAvailable cached:Cached; do
					json_add_int "${f%%:*}" "$(meminfo "${f#*:}")"
				done
				json_close_object
				;;
		esac
		json_dump
		;;
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
mkdir -p /usr/sbin
cp /usr/share/luci-sso/test/../files/usr/sbin/luci-sso-cleanup /usr/sbin/ 2>/dev/null || true
chmod +x /usr/sbin/luci-sso-cleanup 2>/dev/null || true

# 7a. Link native crypto backend to the path ucode expects
: ${CRYPTO_LIB:?CRYPTO_LIB must be set}
mkdir -p /usr/lib/ucode/luci_sso
ln -sf /luci_sso/backends/${CRYPTO_LIB}/luci_sso/native.so /usr/lib/ucode/luci_sso/native.so

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
