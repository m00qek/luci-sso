# How to Build the Packages from Source

This guide builds the `luci-sso` packages for a router whose architecture the package feed does not serve, or builds a version you have changed. If the router is `x86_64`, `aarch64_generic` or `aarch64_cortex-a53`, you do not need to build: [install from the package feed](installation.md#3-install-from-the-package-feed) instead.

The build runs the OpenWrt SDK in a container, so it needs:

*   Docker with the Compose plugin (the `Makefile` calls `docker compose`);
*   `make`;
*   a checkout of this repository;
*   SSH access to the router, to read its architecture and OpenWrt version.

---

## 1. Read the router's architecture and release

On the router, run:

```bash
grep -E 'DISTRIB_(ARCH|RELEASE)' /etc/openwrt_release
```

```text
DISTRIB_RELEASE='24.10.5'
DISTRIB_ARCH='aarch64_cortex-a53'
```

`DISTRIB_ARCH` becomes `SDK_ARCH`. `DISTRIB_RELEASE` tells you which SDK series to use:

| Router release | `SDK_VERSION` | Package format |
| :--- | :--- | :--- |
| 24.10.x | `24.10.5` (the default) | `.ipk`, for `opkg` |
| 25.12.x | `25.12.3` | `.apk`, for `apk` |

If you leave `SDK_ARCH` out, the build uses `x86-64` on an x86 machine and `aarch64_generic` on an ARM one, which is only right if the router matches.

---

## 2. Build

From the repository root, pass both values.

=== "OpenWrt 24.10"

    ```bash
    make package SDK_ARCH=aarch64_cortex-a53
    ```

=== "OpenWrt 25.12"

    ```bash
    make package SDK_ARCH=aarch64_cortex-a53 SDK_VERSION=25.12.3
    ```

The build runs in a container image built on the SDK image `ghcr.io/openwrt/sdk:<SDK_ARCH>-<SDK_VERSION>`. The first build for a given architecture and version downloads it and prepares its feeds, which takes a while; later builds reuse it. If Docker cannot find the image, check that `SDK_ARCH` and `SDK_VERSION` name an SDK that OpenWrt publishes.

The build compiles `luci-sso` and all three crypto backends, and ends with:

```text
Copied 4 luci-sso package(s) to /artifacts/<SDK_ARCH>/<SDK_VERSION>/packages
```

`/artifacts` is the container's view of `bin/lib/` in the repository.

---

## 3. Collect the packages

The packages are in `bin/lib/<SDK_ARCH>/<SDK_VERSION>/packages/`. Only `luci-sso`'s own packages are copied there, not the libraries the SDK built along the way.

=== "OpenWrt 24.10"

    ```bash
    ls bin/lib/aarch64_cortex-a53/24.10.5/packages/
    ```

    ```text
    luci-sso_0.9.1-r1_aarch64_cortex-a53.ipk
    luci-sso-crypto-mbedtls_0.9.1-r1_aarch64_cortex-a53.ipk
    luci-sso-crypto-openssl_0.9.1-r1_aarch64_cortex-a53.ipk
    luci-sso-crypto-wolfssl_0.9.1-r1_aarch64_cortex-a53.ipk
    ```

=== "OpenWrt 25.12"

    ```bash
    ls bin/lib/aarch64_cortex-a53/25.12.3/packages/
    ```

    ```text
    luci-sso-0.9.1-r1.apk
    luci-sso-crypto-mbedtls-0.9.1-r1.apk
    luci-sso-crypto-openssl-0.9.1-r1.apk
    luci-sso-crypto-wolfssl-0.9.1-r1.apk
    ```

The router needs `luci-sso` and exactly one backend. Each build first deletes the `luci-sso` packages an earlier build left in that directory, so only the current version is there.

---

## Next steps

*   To install the packages, see [How to Install luci-sso](installation.md#4-install-from-a-local-package).
*   To replace an installed version, see [How to Upgrade luci-sso](upgrade.md).
*   To choose a backend, see [About Crypto Backends](../../explanation/crypto-backends.md).
*   For the build's other variables, see [Makefile Targets](../../reference/devenv-targets.md).
