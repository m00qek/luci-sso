#!/bin/sh

# Source shared library
. /usr/local/bin/base-startup.sh

# 1. Parse Arguments
parse_args "$@"

# 2. Setup CA Trust for system tools
if [ -f /usr/local/share/ca-certificates/CA.crt ]; then
    echo "📜 Importing Dev CA..."
    cp /usr/local/share/ca-certificates/CA.crt /usr/local/share/ca-certificates/dev-ca.crt
    update-ca-certificates >/dev/null 2>&1 || true
fi

# 3. Execution Mode
if [ "$SHOULD_FOREGROUND" = "true" ]; then
    echo "🚀 Starting IdP (with Hot Reload)..."
    # We use nodemon to monitor index.js
    exec nodemon --watch index.js index.js
fi

# Fallback to idle
stay_alive
