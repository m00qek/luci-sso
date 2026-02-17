#!/bin/bash
set -e

# test.sh: Smart Test Orchestrator for LuCI SSO
# Responsibilities: Validation, Path Translation, Execution, Watching.

# --- CONFIGURATION ---
BASE_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
DEVENV_DIR="$BASE_DIR/devenv"
# COMPOSE_FLAGS MUST be passed from the environment (Makefile)

# Colors
RED='\033[1;31m'
GREEN='\033[1;32m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
RESET='\033[0m'

# --- HELPERS ---

log_info() { echo -e " ${BLUE}ℹ️${RESET}  $1"; }
log_success() { echo -e " ${GREEN}✅${RESET} $1"; }
log_warn() { echo -e " ${YELLOW}⚠️${RESET}  $1"; }
log_error() { echo -e " ${RED}⛔${RESET}  $1"; }

translate_unit_paths() {
  local modules=$1
  local translated=""
  for mod in $modules; do
    # test/tier2/crypto_test.uc -> tier2.crypto_test
    translated="$translated $(echo "$mod" | sed -E 's|^(\.\./)?test/||' | sed 's|\.uc$||' | tr '/' '.')"
  done
  echo "$translated"
}

translate_e2e_paths() {
  local modules=$1
  local translated=""
  for mod in $modules; do
    # test/e2e/01-login.spec.js -> tests/01-login.spec.js
    translated="$translated $(echo "$mod" | sed -E 's|^(\.\./)?test/e2e/|tests/|')"
  done
  echo "$translated"
}

# --- EXECUTION ---

run_unit() {
  local modules=$1
  local filter=$2

  log_info "🧪 Running unit tests in openwrt container..."
  docker compose $COMPOSE_FLAGS exec openwrt \
    sh -c "rm -rf /usr/lib/ucode/luci_sso && ln -sf '/luci_sso/backends/${CRYPTO_LIB}/luci_sso' '/usr/lib/ucode/luci_sso'"
  docker compose $COMPOSE_FLAGS exec -e MODULES="$modules" -e FILTER="$filter" -e VERBOSE="$VERBOSE" openwrt ucode \
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

  docker compose $COMPOSE_FLAGS exec openwrt \
    sh -c "rm -rf /usr/lib/ucode/luci_sso && ln -sf '/luci_sso/backends/${CRYPTO_LIB}/luci_sso' '/usr/lib/ucode/luci_sso'"
  docker compose $COMPOSE_FLAGS exec -e VERBOSE="$VERBOSE" browser ./node_modules/.bin/playwright test $(translate_e2e_paths "$modules") $grep_flag
}

# --- MAIN ---

COMMAND=$1
if [ -z "$COMMAND" ]; then
  echo "Usage: $0 {unit|e2e|watch} [--modules \"paths\"] [--filter \"string\"] [--watch]"
  exit 1
fi
shift

MODULES=""
FILTER=""
WATCH=false

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
  --watch) WATCH=true ;;
  *)
    echo "Unknown parameter: $1"
    exit 1
    ;;
  esac
  shift
done

case "$COMMAND" in
unit)
  if [ "$WATCH" = true ]; then
    if ! command -v inotifywait >/dev/null 2>&1; then
      log_error "'inotifywait' not found. Please install 'inotify-tools'."
      exit 1
    fi
    WATCH_PATHS="$BASE_DIR/files $BASE_DIR/src ${MODULES:-$BASE_DIR/test}"
    log_info "Watching for changes in $WATCH_PATHS..."
    while true; do
      run_unit "$MODULES" "$FILTER" || true
      inotifywait -r -q -e modify,move,create,delete $WATCH_PATHS
      echo -e "\n ${YELLOW}🔄${RESET} Change detected. Re-running...\n"
    done
  else
    run_unit "$MODULES" "$FILTER"
  fi
  ;;

e2e)
  run_e2e "$MODULES" "$FILTER"
  ;;

watch)
  if ! command -v inotifywait >/dev/null 2>&1; then
    log_error "'inotifywait' not found. Please install 'inotify-tools'."
    exit 1
  fi
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
  echo "Usage: $0 {unit|e2e|watch} [--modules \"paths\"] [--filter \"string\"] [--watch]"
  exit 1
  ;;
esac

