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

# MODULES is a whitespace-separated list of paths. split_modules splits it into
# the array named by $2 without glob expansion, so a pattern reaches the
# container's runner as written instead of being matched on the host.
split_modules() {
  local -n _out=$2
  read -r -a _out <<<"$1"
}

# test/unit/luci_sso/crypto_test.uc -> /usr/share/luci-sso/test/unit/luci_sso/crypto_test.uc
translate_unit_path() {
  echo "/usr/share/luci-sso/${1#../}"
}

# test/e2e/01-login.spec.js -> tests/01-login.spec.js
translate_e2e_path() {
  echo "$1" | sed -E 's|^(\.\./)?test/e2e/|tests/|'
}

# --- EXECUTION ---

run_unit() {
  local modules=$1
  local filter=$2

  log_info "🧪 Running unit tests in openwrt container..."
  docker compose $COMPOSE_FLAGS exec openwrt \
    sh -c "rm -rf /usr/lib/ucode/luci_sso && ln -sf '/luci_sso/backends/${CRYPTO_LIB}/luci_sso' '/usr/lib/ucode/luci_sso'"

  local reporter
  [ "$VERBOSE" = "1" ] && reporter="detailed" || reporter="compact"

  # One array element per argument: a filter with spaces stays one argument.
  local filter_args=()
  [ -n "$filter" ] && filter_args=(-f "$filter")

  local bundles=() mods=() mod
  if [ -n "$modules" ]; then
    split_modules "$modules" mods
    for mod in "${mods[@]}"; do
      bundles+=("$(translate_unit_path "$mod")")
    done
  else
    bundles=(
      /usr/share/luci-sso/test/native
      /usr/share/luci-sso/test/integration
      /usr/share/luci-sso/test/unit/luci_sso
      /usr/share/luci-sso/test/unit/luci_sso/components
      /usr/share/luci-sso/test/unit/luci_sso/crypto
      /usr/share/luci-sso/test/unit/luci_sso/session
      /usr/share/luci-sso/test/system
    )
  fi

  docker compose $COMPOSE_FLAGS exec openwrt \
    utest \
    -c /usr/share/luci-sso/test/utest.config.uc \
    -r "$reporter" \
    "${filter_args[@]}" \
    "${bundles[@]}"
}

run_e2e() {
  local modules=$1
  local filter=$2

  log_info "🧪 Running E2E tests (${CRYPTO_LIB}) in browser container..."
  local grep_args=()
  [ -n "$filter" ] && grep_args=(-g "$filter")

  docker compose $COMPOSE_FLAGS exec openwrt \
    sh -c "rm -rf /usr/lib/ucode/luci_sso && ln -sf '/luci_sso/backends/${CRYPTO_LIB}/luci_sso' '/usr/lib/ucode/luci_sso'"
  # Every browser request comes from one address, so the per-client rate limit
  # (10 login initiations per 5 minutes) would apply to the whole suite, which
  # makes more logins than that. Production limits stay as they are: each spec
  # file runs as its own Playwright invocation, preceded by a reset of the
  # rate-limit state, so every file starts with a full budget. The limiter
  # itself is covered by the unit and integration tests.
  local specs=() mods=() mod
  if [ -n "$modules" ]; then
    split_modules "$modules" mods
    for mod in "${mods[@]}"; do
      specs+=("$(translate_e2e_path "$mod")")
    done
  else
    for mod in "$BASE_DIR"/test/e2e/*.spec.js; do
      specs+=("tests/${mod##*/}")
    done
  fi

  local failed=0 spec
  for spec in "${specs[@]}"; do
    docker compose $COMPOSE_FLAGS exec openwrt rm -f /var/run/luci-sso/ratelimit.json
    docker compose $COMPOSE_FLAGS exec -e VERBOSE="$VERBOSE" browser ./node_modules/.bin/playwright test "$spec" "${grep_args[@]}" --pass-with-no-tests || failed=1
  done
  return $failed
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

