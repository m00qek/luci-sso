# LuCI SSO Development Environment

This directory contains a fully containerized OIDC/OAuth2 stack for developing and testing `luci-sso` without a physical router.

## 🏗️ Environment Stacks

The environment is split into two distinct **suites** (Docker Compose projects). While you can run one of each simultaneously, you cannot run two instances of the same suite.

### 1. Local Stack (`DOCKER_SUITE=local`)
*   **Purpose:** Manual development, hot-reloading code, and interactive debugging.
*   **Ports:** Maps services to `localhost` (e.g., 8443, 5556).
*   **Commands:** `make local-up`, `make local-down`, `make local-shell`.

### 2. CI Stack (`DOCKER_SUITE=ci`)
*   **Purpose:** Automated browser testing and CI simulation.
*   **Isolation:** Uses internal DNS names (e.g., `luci.luci-sso.test`) and does not map ports to the host.
*   **Commands:** `make up`, `make down`, `make test`, `make ps`.

> **Note on Concurrency:** You **CAN** have the Local stack running while you execute CI tests. However, you **CANNOT** run `make up` twice simultaneously.

## 🌐 Accessing Services

The environment is designed to work via `localhost` using specific ports. All TLS certificates are generated with `localhost` in the Subject Alternative Name (SAN).

| Service | Local URL | Description |
| :--- | :--- | :--- |
| **OpenWrt** | [https://localhost:8443](https://localhost:8443) | The target OpenWrt web interface (LuCI). |
| **Mock IdP** | [https://localhost:5556](https://localhost:5556) | The OIDC Identity Provider. |

## 🧪 Manual Testing & Debugging

Manual verification is highly encouraged during development to inspect token contents and redirection flows.

### 1. Verify OIDC Discovery
Check if the Mock IdP is serving its configuration correctly:
```bash
curl -k https://localhost:5556/.well-known/openid-configuration
```

### 2. Inspect Issued Tokens & Keys
The Mock IdP stores its runtime state (including generated signing keys) in:
*   `devenv/.pki/idp/signing_key.pem`
*   `devenv/.pki/idp/tokens.json` (if persistent storage is enabled in `index.js`)

### 3. Log Inspection
To follow logs for a specific component:
```bash
docker logs -f local-idp     # Mock IdP logs (Node.js)
docker logs -f local-openwrt # uhttpd and ucode logs
```

### 4. Interactive Shell
If you need to inspect the LuCI state (UCI configs, UBUS) directly:
```bash
make local-shell
```

## 🏗️ Multi-Architecture Support

The environment follows an **Authoritative SDK** model. You define the SDK you want to build with, and the environment automatically selects a compatible Rootfs for metadata mapping.

### Beta Limitation: Build vs. Test
*   **Cross-Compilation (Supported):** You can build IPKs for any architecture (e.g., `make package SDK_ARCH=aarch64_generic`).
*   **Local Testing (Host-Only):** Running the full environment (`make up`) is currently restricted to your host's native architecture. Cross-architecture emulation is not supported in the beta phase.

### Architecture Support Matrix

| SDK Architecture (`SDK_ARCH`) | Runtime Rootfs (`ROOTFS_ARCH`) | Compatible Hardware Examples |
| :--- | :--- | :--- |
| **`x86-64`** | `x86-64` | Proxmox VMs, Intel NUC, PC Engines APU |
| **`aarch64_generic`** | `aarch64_generic` | Raspberry Pi 4/5, Yuncore AX835, NanoPi R4S |

*   **Variables:**
    *   **`CRYPTO_LIB`**: The backend to use (`mbedtls` or `wolfssl`).
    *   `SDK_ARCH`: The build authority (must match a tag in `ghcr.io/openwrt/sdk`).
    *   `ROOTFS_ARCH`: The runtime target (derived automatically from `SDK_ARCH`).
*   **Auto-detection:** The `Makefile` automatically detects your host architecture and selects the matching `SDK_ARCH` for testing.
*   **Artifact Segregation:** Binaries are stored in `bin/lib/${SDK_ARCH}/${CRYPTO_LIB}/`.
*   **Manual Override (Building Only):**
    Force a specific SDK or backend for packaging:
    ```bash
    make package SDK_ARCH=aarch64_generic CRYPTO_LIB=wolfssl
    ```

## 🔐 PKI & Trust

The `pki` service automatically generates a development CA and per-service certificates on startup.
*   **CA Certificate:** Located at `devenv/.pki/CA.crt`.
*   **Trust:** To avoid browser TLS warnings, you can manually import `CA.crt` into your browser's trust store.
*   **Reset:** To regenerate all certificates, run `make local-down` and delete the `devenv/.pki` directory.

## 🛠 Troubleshooting

*   **Permission Denied on `bin/`:** The `Makefile` is designed to create the necessary subdirectories (e.g., `bin/lib/${SDK_ARCH}`) on the host before starting Docker. If you manually deleted `bin/` and encounter issues, ensure your host user has write permissions to the project root. If Docker still creates a directory as root, run `sudo chown -R $USER:$USER bin/`.
*   **Port Conflicts:** If ports 8443 or 5556 are in use, you can override them in `devenv/Makefile` or via environment variables.
*   **`native.so` is a directory:** If you see an error like `Error loading shared library ... native.so: Is a directory`, it means the environment was started before the native components were compiled. Docker automatically creates a directory when a volume source file is missing. To fix this:
    1.  Stop the environment: `make down` (or `make local-down`)
    2.  Compile the components: `make compile`
    3.  Restart the environment: `make up` (or `make local-up`)