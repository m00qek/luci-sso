#!/bin/bash

# Multi-Architecture Resolver for Luci-SSO
# 1. Mode --host: Return default SDK_ARCH for current machine.
# 2. Mode --platform <SDK_ARCH>: Return Docker platform string (linux/arm64, etc).
# 3. Mode <SDK_ARCH>: Return compatible ROOTFS_ARCH.

ARG1=$1

if [ "$ARG1" == "--platform" ]; then
    case "$2" in
        "x86-64")
            echo "linux/amd64"
            ;;
        *)
            echo "linux/$2"
            ;;
    esac
    exit 0
fi

if [ "$ARG1" == "--host" ]; then
    HOST_ARCH=$(uname -m)
    case "$HOST_ARCH" in
        "x86_64")
            echo "x86-64"
            ;;
        "aarch64"|"arm64")
            echo "aarch64_generic"
            ;;
        *)
            # Standard OpenWrt SDK fallback
            echo "x86-64"
            ;;
    esac
    exit 0
fi

# Mapping Mode (SDK_ARCH -> ROOTFS_ARCH)
SDK_ARCH=$ARG1
case "$SDK_ARCH" in
    "x86-64")
        echo "x86-64"
        ;;
    "aarch64_generic")
        echo "aarch64_generic"
        ;;
    "aarch64_cortex-a53")
        # Direct pass-through for forced specific overrides
        echo "aarch64_cortex-a53"
        ;;
    "mips_24kc")
        echo "mips_24kc"
        ;;
    "armsr-armv7")
        echo "armsr-armv7"
        ;;
    "mipsel_24kc")
        echo "mipsel_24kc"
        ;;
    *)
        # Default: Fallback to matching SDK_ARCH
        echo "$SDK_ARCH"
        ;;
esac
