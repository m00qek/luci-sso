# Building from Source

In this tutorial, we will build the `luci-sso` packages for an OpenWrt 24.10 router. By the end, we will have the two `.ipk` files the router needs: `luci-sso` itself and one crypto backend.

---

## Prerequisites

*   **Docker** (or Podman) installed on your machine.
*   **make** utility.
*   SSH access to the router, to look up its architecture.

## Step 1: Identify your architecture

First, we need the router's package architecture. On the router, run:

```bash
grep DISTRIB_ARCH /etc/openwrt_release
```

The output looks like this:

```text
DISTRIB_ARCH='aarch64_cortex-a53'
```

`opkg print-architecture` shows the same value on the line with the highest priority. We will pass this value as `SDK_ARCH`. If we leave `SDK_ARCH` out, the build uses `x86-64` on an x86 machine and `aarch64_generic` on an ARM one.

## Step 2: Build the package

Now, let's run the build, with the architecture from Step 1:

```bash
make package SDK_ARCH=aarch64_cortex-a53
```

The build runs inside a container based on the OpenWrt SDK image for that architecture and OpenWrt version (`ghcr.io/openwrt/sdk:<SDK_ARCH>-<SDK_VERSION>`; the version defaults to `24.10.5`). The first run takes a while: it downloads the SDK and prepares its feeds.

The build starts with this line, followed by a long compiler log:

```text
📦 Building IPK package for aarch64_cortex-a53/24.10.5...
```

## Step 3: Find the packages

Once the build completes, the packages are in `bin/lib/<SDK_ARCH>/<SDK_VERSION>/packages/`. That directory also holds every other package the SDK built, so we list only ours:

```bash
ls bin/lib/aarch64_cortex-a53/24.10.5/packages/luci-sso*.ipk
```

We should see four files: `luci-sso` and the three crypto backends.

```text
luci-sso_0.9.1-r1_aarch64_cortex-a53.ipk
luci-sso-crypto-mbedtls_0.9.1-r1_aarch64_cortex-a53.ipk
luci-sso-crypto-openssl_0.9.1-r1_aarch64_cortex-a53.ipk
luci-sso-crypto-wolfssl_0.9.1-r1_aarch64_cortex-a53.ipk
```

The router needs `luci-sso` plus exactly one backend.

!!! note "OpenWrt 25.12"
    `make package SDK_VERSION=25.12.3` builds `.apk` packages inside the SDK container, but the build script only copies `.ipk` files out, so `bin/lib/<SDK_ARCH>/25.12.3/packages/` stays empty.

---

## Next steps

We now have the packages. Proceed to [How to Install luci-sso](../how-to/sysadmin/installation.md) to put them on the router.
