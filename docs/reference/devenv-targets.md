# devenv Makefile Reference

All development commands run through `devenv/Makefile`. Invoke them as `make -C devenv <target> [VARIABLE=value ...]` from the project root.

---

## Architecture

The devenv runs two independent Docker Compose projects:

| Project | Compose files | Contents | Lifetime |
| :--- | :--- | :--- | :--- |
| **Infra** (`luci-sso-infra`) | `docker-compose.infra.yaml` + `docker-compose.infra.<DOCKER_SUITE>.yaml` | PKI, IdP, Browser (CI only) | Long-lived: start once per session |
| **OpenWrt** (`<SDK_ARCH>-<SDK_VERSION>`) | `docker-compose.yaml` + `docker-compose.<DOCKER_SUITE>.yaml` | OpenWrt, SDK, Fuzzer | Short-lived: started/stopped per test run |

Both projects share the `luci-sso-net` Docker network. Infra must be running before tests are executed. Test targets (`test`, `e2e`, `watch-tests`) start and stop the OpenWrt container automatically.

---

## Modes

The `DOCKER_SUITE` variable controls which overlay is applied to both projects:

| Mode | `DOCKER_SUITE` | IdP ISSUER | OpenWrt ports | Browser container |
| :--- | :--- | :--- | :--- | :--- |
| **Local** (default) | `local` | `https://localhost:5556` | `8443` exposed | No — you are the browser |
| **CI** | `ci` | `https://idp.luci-sso.test` | None | Yes — Playwright runs headlessly |

Test targets (`test`, `e2e`, `watch-tests`) always use CI mode regardless of the environment variable.

---

## Targets

### Infrastructure management

| Target | Description |
| :--- | :--- |
| `infra-up` | Start shared infrastructure (PKI, IdP, and Browser in CI mode). |
| `infra-down` | Stop shared infrastructure. Pass the same `DOCKER_SUITE` used when starting. |

### Environment management

| Target | Description |
| :--- | :--- |
| `up` | Start the full local stack (infra + OpenWrt). Defaults to local mode — use `DOCKER_SUITE=ci` for headless test browsing. |
| `down` | Stop and remove all stack containers (OpenWrt + infra). Pass the same `DOCKER_SUITE` used when starting. |
| `ps` | List running containers in the OpenWrt project and their status. |
| `shell` | Open an interactive shell in the `openwrt` container. |
| `build-images` | Build Docker images from local Dockerfiles without pulling. |
| `pull` | Pull the latest pre-built images from the registry. |

### Testing

Test targets use CI mode and start/stop the OpenWrt container automatically. Start CI infrastructure first with `make infra-up DOCKER_SUITE=ci`.

| Target | Description |
| :--- | :--- |
| `test` | Run unit and integration tests (Tiers 0–4). Starts and stops OpenWrt automatically. |
| `e2e` | Run browser-based end-to-end tests via Playwright. Starts and stops OpenWrt automatically. |
| `watch-tests` | Re-run tests automatically when files change in `files/`, `src/`, or `test/`. Starts OpenWrt at launch and stops it on exit. |
| `fuzz` | Run coverage-guided fuzzing (libFuzzer + AddressSanitizer) on native C code. |
| `lint` | Run the three documentation lint checks (error codes, request limits, cookies). No stack required. |

### Build

| Target | Description |
| :--- | :--- |
| `compile` | Compile native C components for the target architecture. Skipped if the sentinel file is current. |
| `package` | Build the `.ipk` package for the target architecture. |

### Utilities

| Target | Description |
| :--- | :--- |
| `sync-headers` | Copy C headers from the SDK container into `devenv/.include/` for LSP support. |
| `print-env` | Print the value of a Makefile variable. Usage: `make -C devenv print-env VAR=SDK_ARCH` |

---

## Variables

Variables are passed on the command line as `KEY=value` after the target name.

### Mode

| Variable | Default | Description |
| :--- | :--- | :--- |
| `DOCKER_SUITE` | `local` | Stack mode. `local` exposes ports for browser access; `ci` runs headlessly with a Playwright container. |

### Architecture and build

| Variable | Default | Description |
| :--- | :--- | :--- |
| `SDK_ARCH` | Host architecture | Target CPU architecture. Determines which OpenWrt SDK container is used and where build output goes. |
| `CRYPTO_LIB` | `mbedtls` | Cryptographic backend to **test against**. Does not affect compilation — all available backends are always built. Accepted values: `mbedtls`, `wolfssl`, `openssl`. Applies to: `test`, `e2e`, `watch-tests`, `fuzz`. |

Common `SDK_ARCH` values:

| Router type | Value |
| :--- | :--- |
| Raspberry Pi 4, NanoPi (ARM64) | `aarch64_generic` |
| x86 routers (Intel/AMD) | `x86-64` |
| MIPS routers (GL.iNet, Ubiquiti) | `mipsel_24kc` |

### Test filtering

| Variable | Applies to | Description |
| :--- | :--- | :--- |
| `FILTER` | `test`, `e2e`, `watch-tests` | Regex matched against test names. Only matching tests run. Example: `FILTER='oidc.*discovery'` |
| `MODULES` | `test`, `e2e`, `watch-tests` | Path to a specific test file or directory. Example: `MODULES='test/tier2/oidc_logic_test.uc'` |
| `VERBOSE` | `test`, `e2e` | Set to `1` for detailed per-test output. |

### Fuzzer

| Variable | Default | Description |
| :--- | :--- | :--- |
| `TIME` | `60` | Fuzzer run duration in seconds. |
| `DETECT_LEAKS` | `0` | Set to `1` to enable AddressSanitizer leak detection. Disabled by default to speed up initial coverage runs. |

### Container

| Variable | Default | Description |
| :--- | :--- | :--- |
| `CONTAINER` | `openwrt` | Container name used by `shell` and `run` targets. |

---

## Examples

```bash
# Start the local stack and open the router in a browser at https://localhost:8443
make -C devenv up

# Open a shell in the running openwrt container
make -C devenv shell

# Start CI infrastructure and run all tests
make -C devenv infra-up DOCKER_SUITE=ci
make -C devenv test
make -C devenv e2e
make -C devenv infra-down DOCKER_SUITE=ci

# Watch tests (infrastructure must be started first)
make -C devenv infra-up DOCKER_SUITE=ci
make -C devenv watch-tests
make -C devenv infra-down DOCKER_SUITE=ci

# Run only OIDC discovery tests, with verbose output
make -C devenv test FILTER='oidc.*discovery' VERBOSE=1

# Run a single test file
make -C devenv test MODULES='test/tier2/oidc_logic_test.uc'

# Run tests against the wolfssl backend (compile always builds all backends)
make -C devenv test CRYPTO_LIB=wolfssl

# Build an IPK for a MIPS router
make -C devenv package SDK_ARCH=mipsel_24kc

# Fuzz the mbedtls backend for 10 minutes with leak detection
make -C devenv fuzz CRYPTO_LIB=mbedtls TIME=600 DETECT_LEAKS=1
```
