#!/bin/bash
set -e

# test.sh: Smart Test Orchestrator for LuCI SSO
# Responsibilities: Validation, Path Translation, Execution, Watching.
# Environment variables that MUST be passed from the Makefile:
#   COMPOSE_FLAGS, INFRA_COMPOSE_FLAGS — docker compose project/file flags
#   CRYPTO_LIB                         — crypto backend to link (mbedtls|wolfssl|openssl)
#   SDK_ARCH, SDK_VERSION              — used when creating the bin/lib staging dir
#   VERBOSE                            — set to "1" to enable verbose build/test output

# --- CONFIGURATION ---
BASE_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

# Colors
RED='\033[1;31m'
GREEN='\033[1;32m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
RESET='\033[0m'

# --- HELPERS ---

log_info() { echo -e " ${BLUE}ℹ️${RESET}  $1"; }
log_warn() { echo -e " ${YELLOW}⚠️${RESET}  $1"; }
log_error() { echo -e " ${RED}⛔${RESET}  $1"; }

translate_unit_paths() {
  local modules=$1
  local translated=""
  for mod in $modules; do
    # test/tier2/crypto_test.uc -> tier2.crypto_test
    local t=$(echo "$mod" | sed -E 's|^(\.\./)?test/||' | sed 's|\.uc$||' | tr '/' '.')
    if [ -z "$translated" ]; then
      translated="$t"
    else
      translated="$translated $t"
    fi
  done
  echo "$translated"
}

translate_e2e_paths() {
  local modules=$1
  local translated=""
  for mod in $modules; do
    # test/e2e/01-login.spec.js -> tests/01-login.spec.js
    local t=$(echo "$mod" | sed -E 's|^(\.\./)?test/e2e/|tests/|')
    if [ -z "$translated" ]; then
      translated="$t"
    else
      translated="$translated $t"
    fi
  done
  echo "$translated"
}

# --- OPENWRT LIFECYCLE ---

start_openwrt() {
  mkdir -p "$BASE_DIR/bin/lib/${SDK_ARCH}/${SDK_VERSION}"
  log_info "🚀 Starting openwrt..."
  docker compose $COMPOSE_FLAGS up -d --wait openwrt
}

guard_single_openwrt() {
  local running
  running=$(docker ps --format "{{.Names}}" --filter "network=luci-sso-net" 2>/dev/null | grep '\-openwrt$' || true)
  if [ -n "$running" ]; then
    log_error "Another openwrt container is already running: $running"
    log_error "E2E tests require exclusive access to the network. Only one run at a time."
    log_error "Wait for it to finish, or stop it manually: docker stop $running"
    exit 1
  fi
}

stop_openwrt() {
  log_info "🛑 Stopping openwrt..."
  docker compose $COMPOSE_FLAGS down
}

# --- EXECUTION ---

link_crypto_backend() {
  docker compose $COMPOSE_FLAGS exec openwrt \
    sh -c "ln -sfn '/luci_sso/backends/${CRYPTO_LIB}/luci_sso' '/usr/lib/ucode/luci_sso'"
}

run_unit() {
  local modules=$1
  local filter=$2

  log_info "🧪 Running unit tests in openwrt container..."
  link_crypto_backend
  docker compose $COMPOSE_FLAGS exec -e MODULES="$(translate_unit_paths "$modules")" -e FILTER="$filter" -e VERBOSE="$VERBOSE" openwrt ucode \
    -L /usr/share/ucode \
    -L /usr/lib/ucode \
    -L /usr/share/ucode/luci_sso \
    -L /usr/share/luci-sso/test \
    /usr/share/luci-sso/test/runner.uc
}

run_e2e() {
  local modules=$1
  local filter=$2

  log_info "🧪 Running E2E tests (${CRYPTO_LIB}) in browser container..."
  local grep_flag=""
  [ -n "$filter" ] && grep_flag="-g $filter"

  link_crypto_backend
  docker compose $INFRA_COMPOSE_FLAGS exec -e VERBOSE="$VERBOSE" browser ./node_modules/.bin/playwright test $(translate_e2e_paths "$modules") $grep_flag
}

# --- MAIN ---

COMMAND=$1
if [ -z "$COMMAND" ]; then
  echo "Usage: $0 {unit|e2e|watch} [--modules \"paths\"] [--filter \"string\"]"
  exit 1
fi
shift

MODULES=""
FILTER=""

while [[ "$#" -gt 0 ]]; do
  case $1 in
  --modules)
    MODULES="$2"
    shift
    ;;
  --filter)
    FILTER="$2"
    shift
    ;;
  *)
    echo "Unknown parameter: $1"
    exit 1
    ;;
  esac
  shift
done

case "$COMMAND" in
unit)
  start_openwrt
  trap "stop_openwrt || true" EXIT
  run_unit "$MODULES" "$FILTER"
  ;;

e2e)
  guard_single_openwrt
  start_openwrt
  trap "stop_openwrt || true" EXIT
  run_e2e "$MODULES" "$FILTER"
  ;;

watch)
  if ! command -v inotifywait >/dev/null 2>&1; then
    log_error "'inotifywait' not found. Please install 'inotify-tools'."
    exit 1
  fi
  guard_single_openwrt
  start_openwrt
  trap "stop_openwrt || true" EXIT
  WATCH_PATHS="$BASE_DIR/files $BASE_DIR/src ${MODULES:-$BASE_DIR/test}"
  log_info "Watching for changes in $WATCH_PATHS..."
  while true; do
    run_unit "$MODULES" "$FILTER" || true
    run_e2e "$MODULES" "$FILTER" || true
    inotifywait -r -q -e modify,move,create,delete $WATCH_PATHS
    echo -e "\n ${YELLOW}🔄${RESET} Change detected. Re-running...\n"
  done
  ;;

*)
  echo "Usage: $0 {unit|e2e|watch} [--modules \"paths\"] [--filter \"string\"]"
  exit 1
  ;;
esac
