#!/bin/sh
set -e

# Source shared library
. /usr/local/bin/base-startup.sh

# 1. Parse Arguments
parse_args "$@"

echo "🔧 Setting up browser trust store..."
# Initialize NSS database for Chromium
mkdir -p $HOME/.pki/nssdb
[ -f $HOME/.pki/nssdb/cert9.db ] || certutil -d sql:$HOME/.pki/nssdb -N --empty-password

# Import CA if provided
if [ -f /usr/local/share/ca-certificates/CA.crt ]; then
    echo "📜 Importing Dev CA into NSS database..."
    # -A: Add, -n: nickname, -t: trust (C=CA, T=Trusted, u=User)
    certutil -d sql:$HOME/.pki/nssdb -A -t "CT,C,C" -n "LuCI-SSO-Dev-CA" -i /usr/local/share/ca-certificates/CA.crt
    # Also update system store for node/wget
    update-ca-certificates >/dev/null 2>&1 || true
fi

# 3. Execution Mode
if [ "$SHOULD_FOREGROUND" = "true" ]; then
    echo "🚀 Running E2E tests..."
    ./node_modules/.bin/playwright test
fi

# Fallback to idle
stay_alive