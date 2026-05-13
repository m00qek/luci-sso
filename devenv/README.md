# Development Environment

A fully containerized OIDC/OAuth2 stack for developing and testing `luci-sso` without a physical router.

For a full walkthrough, see [Development Workflow](https://m00qek.github.io/luci-sso/how-to/developer/development-workflow/).

---

## Two stacks

| Stack | Purpose | Start | Stop |
| :--- | :--- | :--- | :--- |
| **Local** (`DOCKER_SUITE=local`) | Manual dev, hot-reload, interactive shell | `make local-up` | `make local-down` |
| **CI** (`DOCKER_SUITE=ci`) | Automated browser tests, CI simulation | `make up` | `make down` |

You can run Local and CI simultaneously. You cannot run two instances of the same stack.

## Services (local stack)

| Service | URL |
| :--- | :--- |
| OpenWrt / LuCI | https://localhost:8443 |
| Mock IdP | https://localhost:5556 |

All TLS certificates are generated with `localhost` in the SAN. Import `devenv/.pki/CA.crt` into your browser to avoid TLS warnings.

## Common commands

```bash
make local-up          # Start local stack
make local-shell       # SSH into the OpenWrt container
make unit-test         # Run unit tests (no stack needed)
make up && make e2e-test  # Start CI stack and run browser tests
make package SDK_ARCH=x86-64  # Build IPK for x86-64
```

## Architecture support

| `SDK_ARCH` | Example hardware |
| :--- | :--- |
| `x86-64` | Proxmox VMs, Intel NUC, PC Engines APU |
| `aarch64_generic` | Raspberry Pi 4/5, NanoPi R4S |

`CRYPTO_LIB` selects the backend: `mbedtls` (default) or `wolfssl`.

## Troubleshooting

**`Permission denied` on `bin/`** — Docker created `bin/lib` as root before compilation. Fix:
```bash
make down && sudo rm -rf bin && make compile && make up
```

**`native.so` is a directory** — Same root cause. Same fix as above.
