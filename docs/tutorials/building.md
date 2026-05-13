# Building from Source

This tutorial will guide you through building the `luci-sso` `.ipk` package for your specific router architecture using our Dockerized toolchain.

---

## 🛠️ Prerequisites
*   **Docker** (or Podman) installed on your machine.
*   **make** utility.

## Step 1: Identify your Architecture
Find your target architecture (e.g., `x86_64`, `aarch64_generic`, `mips_24kc`). You can find this in OpenWrt under **System > Overview**.

## Step 2: Build via Docker
Run the following command in the project root. Replace `SDK_ARCH` with your target.

### For Raspberry Pi 4 / NanoPi (ARM64):
```bash
make package SDK_ARCH=aarch64_generic
```

### For x86 routers (Intel/AMD):
```bash
make package SDK_ARCH=x86-64
```

### For MIPS routers (e.g., GL.iNet, Ubiquiti):
```bash
make package SDK_ARCH=mips_24kc
```

*The build system will automatically download the correct OpenWrt SDK container and compile the package.*

## Step 3: Retrieve Artifacts
Once the build completes, the compiled packages will be available in the `bin/` directory:

```text
bin/lib/<ARCH>/packages/luci-sso*.ipk
```

---

## 🎓 Next Steps
Now that you have your package, proceed to the [Installation Guide](../how-to/sysadmin/installation.md).
