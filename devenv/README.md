# Development Environment

A fully containerized OIDC/OAuth2 stack for developing and testing `luci-sso` without a physical router.

For a full walkthrough, see [Development Workflow](https://m00qek.github.io/luci-sso/latest/how-to/developer/development-workflow/).

---

## Two stacks

| Stack | Purpose | Start | Stop |
| :--- | :--- | :--- | :--- |
| **Local** (`DOCKER_SUITE=local`) | Manual dev, hot-reload, interactive shell | `make local-up` | `make local-down` |
| **CI** (`DOCKER_SUITE=ci`) | Automated unit and browser tests, CI simulation | `make up` | `make down` |

You can run Local and CI simultaneously. You cannot run two instances of the same stack for the same `SDK_ARCH` and `SDK_VERSION`.

## Services (local stack)

| Service | URL |
| :--- | :--- |
| OpenWrt / LuCI | https://localhost:8443 |
| Mock IdP | https://localhost:5556 |

All TLS certificates are generated with `localhost` in the SAN. Import `devenv/.pki/CA.crt` into your browser to avoid TLS warnings.

## Common commands

```bash
make compile          # Build the native module (needed before any stack runs tests or logins)
make local-up          # Start local stack
make local-shell       # Open a shell in the OpenWrt container
make up && make unit-test  # Start the CI stack; run native, unit, integration and system tests
make up && make e2e-test  # Start CI stack and run browser tests
make package SDK_ARCH=x86-64  # Build the luci-sso packages (.ipk on 24.10, .apk with SDK_VERSION=25.12.3)
```

## Architecture support

| `SDK_ARCH` | Example hardware |
| :--- | :--- |
| `x86-64` | Proxmox VMs, Intel NUC, PC Engines APU |
| `aarch64_generic` | Raspberry Pi 4/5, NanoPi R4S |

`CRYPTO_LIB` selects the backend: `mbedtls` (default), `wolfssl` or `openssl`.

## Troubleshooting

**`Permission denied` on `bin/`** — Docker created `bin/lib` as root before compilation. Fix:
```bash
make down && sudo rm -rf bin && make compile && make up
```

**`native.so` is a directory** — Same root cause. Same fix as above.

**Disk fills up with unnamed Docker volumes of about 1.3 GB each** — The OpenWrt SDK image declares `VOLUME /builder`. Before the `sdk` service mounted a `tmpfs` over `/builder`, every `sdk` container got an anonymous volume that `make down` did not remove. The build no longer creates them, and `make down` and `make local-down` now remove the anonymous volumes of the stack's containers. To reclaim space from older runs, list the dangling volumes, check that they are yours, and remove them one by one:
```bash
docker volume ls -f dangling=true
docker system df -v             # sizes, under "Local Volumes space usage"
docker volume rm <volume-name>
```
`docker volume prune` also removes the dangling volumes of every other project on the host.
