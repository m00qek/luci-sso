# Building from Source

In this tutorial, we will build a `luci-sso` `.ipk` package ready to install on your OpenWrt router. By the end, we'll have a compiled package file in the `bin/` directory.

---

## Prerequisites

*   **Docker** (or Podman) installed on your machine.
*   **make** utility.

## Step 1: Identify your architecture

First, we need to know our router's CPU architecture. On the router, navigate to **System > Overview** — the architecture is listed under "Architecture" (for example, `aarch64_generic`, `x86-64`, or `mipsel_24kc`).

## Step 2: Build the package

Now, let's run the build. Replace `SDK_ARCH` with the architecture we found in Step 1:

```bash
make -C devenv package SDK_ARCH=aarch64_generic
```

The build system will automatically pull the correct OpenWrt SDK container for our target and compile the package inside it. The first run may take a few minutes to download the SDK image.

You should see output similar to:

```
[SDK] Building luci-sso for aarch64_generic...
[SDK] Package built successfully.
```

Common architecture values:

| Router type | SDK_ARCH value |
| :--- | :--- |
| Raspberry Pi 4, NanoPi (ARM64) | `aarch64_generic` |
| x86 routers (Intel/AMD) | `x86-64` |
| MIPS routers (GL.iNet, Ubiquiti) | `mipsel_24kc` |

## Step 3: Find the package

Once the build completes, the compiled package is in the `bin/` directory:

```text
bin/lib/<ARCH>/packages/luci-sso*.ipk
```

We can verify it's there:

```bash
ls bin/lib/*/packages/luci-sso*.ipk
```

You should see one `.ipk` file listed.

---

## Next steps

We now have a compiled package ready to deploy. Proceed to [How to Install luci-sso](../how-to/sysadmin/installation.md) to put it on the router.
