#!/bin/bash
set -e

# build.sh: Orchestrates the OpenWrt SDK build process for LuCI SSO components.
# This script runs INSIDE the SDK container.

ACTION=$1
CRYPTO_LIB=${CRYPTO_LIB:-mbedtls}
PKG_NAME="luci-sso"
SDK_DIR="/sdk"
ARTIFACTS_DIR="/artifacts"

case "$ACTION" in
    compile)
        echo "🔨 Compiling native components for $CRYPTO_LIB..."
        mkdir -p "$ARTIFACTS_DIR/$CRYPTO_LIB/luci_sso"
        
        # Ensure SDK is configured
        [ -f .config ] || make defconfig
        
        # Build the specific package
        make package/$PKG_NAME/compile -j$(nproc) QUICK=1 CHECK_KEY=0 IGNORE_ERRORS=m
        
        # Copy the .so to artifacts
        # Note: The path might vary slightly depending on the SDK version
        cp -v build_dir/target-*/$PKG_NAME-*/.pkgdir/$PKG_NAME-crypto-$CRYPTO_LIB/usr/lib/ucode/luci_sso/native.so \
           "$ARTIFACTS_DIR/$CRYPTO_LIB/luci_sso/native.so"
        ;;

    package)
        echo "📦 Building IPK package..."
        [ -f .config ] || make defconfig
        make package/$PKG_NAME/compile V=s QUICK=1 CHECK_KEY=0
        
        # Copy IPKs to artifacts
        find bin/targets -name "*.ipk" -exec cp -v {} "$ARTIFACTS_DIR/" \;
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
