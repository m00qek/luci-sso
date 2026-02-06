#!/bin/sh

# LuCI SSO Development Orchestrator
# This script prepares the simulated OpenWrt environment and starts services.

# Use SDK_VERSION from environment or fallback to a default
VERSION="${SDK_VERSION:-24.10.5}"

# CLEANUP FUNCTION for graceful but FAST exit
cleanup() {
    echo "Shutting down services..."
    kill $(jobs -p) 2>/dev/null
    exit 0
}

trap cleanup INT TERM

# 1. Ensure runtime directories exist
mkdir -p /var/run/ubus /var/lock /var/state /tmp/sessions /tmp/luci-modulecache /etc/luci-sso/certs
chmod 700 /etc/luci-sso

# 2. Mock Hardware Environment (board.json) - Dynamic Version
if [ ! -f /etc/board.json ]; then
    cat <<EOF > /etc/board.json
{
  "model":{"id":"generic","name":"OpenWrt Container"},
  "board":{},
  "release":{"distribution":"OpenWrt","version":"$VERSION"}
}
EOF
fi

# 3. Setup rpcd plugins for system info - Dynamic Version
if [ ! -f /usr/libexec/rpcd/system ]; then
    cat <<EOF > /usr/libexec/rpcd/system
#!/bin/sh
case "\$1" in
    list) echo '{"info":{},"board":{}}' ;;
    call) echo '{"model":"Docker","release":{"distribution":"OpenWrt","version":"$VERSION"}}' ;;
esac
EOF
    cat <<'EOF' > /usr/libexec/rpcd/board
#!/bin/sh
case "$1" in
    list) echo '{"info":{}}' ;;
    call) echo '{"model":{"name":"OpenWrt Container"}}' ;;
esac
EOF
    chmod +x /usr/libexec/rpcd/system /usr/libexec/rpcd/board
fi

# 4. Map "idp" to internal IP
IDP_IP=$(awk '/idp/ {print $1; exit}' /etc/hosts)
if [ -n "$IDP_IP" ]; then
    grep -q "idp.local" /etc/hosts || echo "$IDP_IP idp.local" >> /etc/hosts
fi

# 5. Fix permissions for project files
chmod +x /www/cgi-bin/luci-sso 2>/dev/null
chmod +x /etc/uci-defaults/* 2>/dev/null

# 6. Setup SSL for uhttpd
if [ -f /etc/ssl/certs/luci.crt ]; then
    cp /etc/ssl/certs/luci.crt /etc/uhttpd.crt
    cp /etc/ssl/certs/luci.key /etc/uhttpd.key
elif [ ! -f /etc/uhttpd.crt ]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/uhttpd.key.pem -out /etc/uhttpd.crt.pem -subj "/CN=localhost" >/dev/null 2>&1
    openssl x509 -in /etc/uhttpd.crt.pem -outform DER -out /etc/uhttpd.crt
    openssl rsa -in /etc/uhttpd.key.pem -outform DER -out /etc/uhttpd.key
fi

# 7. Start Base Services
/sbin/logd -S 16 &
ubusd &
sleep 1

# 8. Run uci-defaults
if [ -d /etc/uci-defaults ]; then
    for i in /etc/uci-defaults/*; do
        if [ -f "$i" ]; then
            ( . "$i" )
        fi
    done
fi

# 9. Start RPCD
rpcd &
sleep 1

# 10. Trigger LuCI cache refresh
/usr/bin/luci-reload 2>/dev/null || true

echo "--------------------------------------------------------"
echo " LuCI SSO Dev Stack Ready ($VERSION)"
echo " HTTPS: https://localhost:8443/cgi-bin/luci"
echo "--------------------------------------------------------"

# 11. Start uhttpd in background
uhttpd -f -p 80 -s 443 -C /etc/uhttpd.crt -K /etc/uhttpd.key -h /www -x /cgi-bin &

# 12. Tail logs in foreground
logread -f &
wait $!