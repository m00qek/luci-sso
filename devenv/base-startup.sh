#!/bin/sh

# base-startup.sh: Shared library for LuCI SSO service orchestration.
# Sourcing this file provides access to unified argument parsing.

# Global State
SHOULD_FOREGROUND=false

show_help() {
    cat <<EOF
Usage:
  start.sh [options]

Options:
  --foreground        Run the primary application in the foreground (locks terminal).
  --help              Show this screen.
EOF
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --foreground)
                SHOULD_FOREGROUND=true
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                shift
                ;;
        esac
    done
}

stay_alive() {
    echo "😴 Setup complete. Entering idle mode..."
    exec tail -f /dev/null
}