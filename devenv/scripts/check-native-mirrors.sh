#!/bin/bash
# The ucode copies of the native module's key rules must equal the C ones.
#
# The connection test (src/luci_sso/connection.uc) judges the provider's keys
# as a login does, with the rules the native backends enforce. The minimum RSA
# modulus is a C constant, so src/luci_sso/crypto/jwk.uc mirrors it:
#
#   C:     #define NATIVE_RSA_MIN_BITS <n>      mod/native.h
#   ucode: export const RSA_MIN_BITS = <n>;     src/luci_sso/crypto/jwk.uc
#
# CI runs this via .github/workflows/lint.yml.

set -euo pipefail
cd "$(dirname "$0")/../.."

c_bits=$(grep -oP '^#define\s+NATIVE_RSA_MIN_BITS\s+\K[0-9]+' mod/native.h || true)
uc_bits=$(grep -oP '^export const RSA_MIN_BITS\s*=\s*\K[0-9]+(?=;)' src/luci_sso/crypto/jwk.uc || true)

[ -z "$c_bits" ] && { echo "ERROR: NATIVE_RSA_MIN_BITS not found in mod/native.h"; exit 1; }
[ -z "$uc_bits" ] && { echo "ERROR: RSA_MIN_BITS not found in src/luci_sso/crypto/jwk.uc"; exit 1; }

if [ "$c_bits" != "$uc_bits" ]; then
    echo "FAIL: NATIVE_RSA_MIN_BITS is $c_bits in mod/native.h, but RSA_MIN_BITS is $uc_bits in src/luci_sso/crypto/jwk.uc"
    printf '\nKeep the two equal: the connection test must judge a key as a login does.\n'
    exit 1
fi
echo "OK: native key rules — mod/native.h ↔ src/luci_sso/crypto/jwk.uc"
