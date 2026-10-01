#!/bin/bash
set -e

ACTION=$1
CRYPTO_LIB=${CRYPTO_LIB:-mbedtls}
PKG_NAME="luci-sso"
ARTIFACTS_DIR="/artifacts"

case "$ACTION" in
compile)
  echo "🔨 Compiling native components for $CRYPTO_LIB ($SDK_ARCH/$SDK_VERSION)..."
  mkdir -p "$ARTIFACTS_DIR/$SDK_ARCH/$SDK_VERSION/$CRYPTO_LIB/luci_sso"

  # Ensure SDK is configured
  [ -f .config ] || make defconfig

  # Build the specific package
  [ "$VERBOSE" = "1" ] && V_FLAG="V=s" || V_FLAG=""
  make package/$PKG_NAME/compile -j$(nproc) $V_FLAG QUICK=1 CHECK_KEY=0 IGNORE_ERRORS=m

  # Copy the .so to artifacts
  cp -v build_dir/target-*/$PKG_NAME-*/.pkgdir/$PKG_NAME-crypto-$CRYPTO_LIB/usr/lib/ucode/luci_sso/native.so \
    "$ARTIFACTS_DIR/$SDK_ARCH/$SDK_VERSION/$CRYPTO_LIB/luci_sso/native.so"
  ;;

package)
  echo "📦 Building $PKG_NAME packages for $SDK_ARCH/$SDK_VERSION..."
  [ -f .config ] || make defconfig
  make package/$PKG_NAME/compile V=s QUICK=1 CHECK_KEY=0

  # Copy only this project's packages: luci-sso and luci-sso-crypto-<lib>, as
  # .ipk (opkg, OpenWrt 24.10) or .apk (apk, OpenWrt 25.12+). bin/ also holds
  # every package the SDK built as a dependency, which must not be copied.
  #   ipk: luci-sso_0.10.0-r1_all.ipk      luci-sso-crypto-mbedtls_0.10.0-r1_x86_64.ipk
  #   apk: luci-sso-0.10.0-r1.apk          luci-sso-crypto-mbedtls-0.10.0-r1.apk
  # luci-sso itself is PKGARCH:=all (noarch for apk); only the crypto
  # backends carry the architecture.
  OUT="$ARTIFACTS_DIR/$SDK_ARCH/$SDK_VERSION/packages"
  PKG_RE="^$PKG_NAME(-crypto-[a-z0-9]+)?(_[^_]+_[^/]+\.ipk|-[0-9][^/]*\.apk)\$"
  mkdir -p "$OUT"

  # Drop this project's packages from an earlier build so an old version
  # cannot linger next to the new one. Nothing else in $OUT is touched.
  for f in "$OUT"/*; do
    if [ -f "$f" ] && [[ "$(basename "$f")" =~ $PKG_RE ]]; then
      rm -v "$f"
    fi
  done

  found=0
  while IFS= read -r f; do
    if [[ "$(basename "$f")" =~ $PKG_RE ]]; then
      cp -v "$f" "$OUT/"
      found=$((found + 1))
    fi
  done < <(find bin/ -type f \( -name "*.ipk" -o -name "*.apk" \))

  if [ "$found" -eq 0 ]; then
    echo "No $PKG_NAME packages found under bin/" >&2
    exit 1
  fi
  echo "Copied $found $PKG_NAME package(s) to $OUT"
  ;;

*)
  echo "Usage: $0 {compile|package}"
  exit 1
  ;;
esac
