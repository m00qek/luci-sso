#!/bin/bash
# sanitizer-test.sh: run the native and crypto unit buckets against a native
# module built with AddressSanitizer + UndefinedBehaviorSanitizer.
#
# Runs INSIDE the fuzzer container (make sanitizer-test), whose ucode and
# utest are themselves built with the same sanitizers (see
# devenv/services/fuzzer/Dockerfile). The repo is mounted at /work.
#
#   CRYPTO_LIB    mbedtls | wolfssl | openssl
#   DETECT_LEAKS  1 (default) to enable LeakSanitizer, 0 to disable
#   REPORTER      utest reporter, default compact
set -uo pipefail

CRYPTO_LIB="${CRYPTO_LIB:?CRYPTO_LIB must be set (mbedtls, wolfssl or openssl)}"
DETECT_LEAKS="${DETECT_LEAKS:-1}"
REPORTER="${REPORTER:-compact}"
ROOT=/work

case "$CRYPTO_LIB" in
  mbedtls) LIBS="-lmbedtls -lmbedx509 -lmbedcrypto" ;;
  wolfssl) LIBS="-lwolfssl" ;;
  openssl) LIBS="-lcrypto" ;;
  *) echo "Unknown CRYPTO_LIB: $CRYPTO_LIB" >&2; exit 2 ;;
esac

# Same three layers as the shipped module (mod/CMakeLists.txt), instrumented.
mkdir -p /usr/lib/ucode/luci_sso
# shellcheck disable=SC2086
"${CC:-clang-19}" $SANITIZE_FLAGS -fPIC -shared -I"$ROOT/mod" \
  -o /usr/lib/ucode/luci_sso/native.so \
  "$ROOT/mod/native_ucode.c" "$ROOT/mod/native_api.c" "$ROOT/mod/native_$CRYPTO_LIB.c" \
  -lucode $LIBS || exit 1

export ASAN_OPTIONS="detect_leaks=$DETECT_LEAKS:abort_on_error=1"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"

log=$(mktemp)
utest -c "$ROOT/test/utest.config.uc" -r "$REPORTER" \
  "$ROOT/test/native" "$ROOT/test/unit/luci_sso/crypto" 2>&1 | tee "$log"
status=${PIPESTATUS[0]}

# utest's exit code covers failures and crashes inside a test. It does NOT
# cover LeakSanitizer, which reports when each worker process exits, after
# its results are in. Fail on any sanitizer report in the output as well.
if grep -qE 'ERROR: [A-Za-z]+Sanitizer|runtime error:' "$log"; then
  echo "sanitizer-test: sanitizer report found ($CRYPTO_LIB)" >&2
  status=1
fi
rm -f "$log"
exit "$status"
