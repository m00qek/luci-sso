#!/bin/bash
set -e

ACTION=$1
CRYPTO_LIB=${CRYPTO_LIB:-mbedtls}
PKG_NAME="luci-sso"
ARTIFACTS_DIR="/artifacts"

case "$ACTION" in
compile)
  echo "🔨 Compiling native components ($SDK_ARCH/$SDK_VERSION)..."
  [ -f .config ] || make defconfig
  [ "$VERBOSE" = "1" ] && V_FLAG="V=s" || V_FLAG=""
  make package/$PKG_NAME/compile -j$(nproc) $V_FLAG QUICK=1 CHECK_KEY=0 IGNORE_ERRORS=m
  for lib in mbedtls wolfssl openssl; do
    src="build_dir/target-*/$PKG_NAME-*/.pkgdir/$PKG_NAME-crypto-$lib/usr/lib/ucode/luci_sso/native.so"
    dst="$ARTIFACTS_DIR/$SDK_ARCH/$SDK_VERSION/$lib/luci_sso/native.so"
    mkdir -p "$ARTIFACTS_DIR/$SDK_ARCH/$SDK_VERSION/$lib/luci_sso"
    # shellcheck disable=SC2086
    if cp -v $src "$dst" 2>/dev/null; then
      echo "✓ $lib"
    else
      echo "⚠ $lib not built (skipping)"
    fi
  done
  ;;

package)
  echo "📦 Building IPK package for $SDK_ARCH/$SDK_VERSION..."
  [ -f .config ] || make defconfig
  make package/$PKG_NAME/compile V=s QUICK=1 CHECK_KEY=0

  # Copy IPKs to artifacts
  mkdir -p "$ARTIFACTS_DIR/$SDK_ARCH/$SDK_VERSION/packages"
  find bin/ -name "*.ipk" -exec cp -v {} "$ARTIFACTS_DIR/$SDK_ARCH/$SDK_VERSION/packages/" \;
  ;;

test)
  echo "🧪 Running unit tests inside SDK..."
  # Add ucode testing logic here
  ucode -L /sdk/package/$PKG_NAME/test/mocks \
    -L "$ARTIFACTS_DIR/$CRYPTO_LIB" \
    -L /sdk/package/$PKG_NAME/files/usr/share/ucode \
    -L /sdk/package/$PKG_NAME/test \
    /sdk/package/$PKG_NAME/test/runner.uc
  ;;

*)
  echo "Usage: $0 {compile|package|test}"
  exit 1
  ;;
esac
