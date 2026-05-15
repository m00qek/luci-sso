# devenv Makefile Reference

All development commands run through `devenv/Makefile`. Invoke them as `make -C devenv <target> [VARIABLE=value ...]` from the project root.

---

## Modes

The devenv runs in one of two modes, controlled by the `DOCKER_SUITE` variable:

| Mode | `DOCKER_SUITE` | Ports exposed | Includes browser container |
| :--- | :--- | :--- | :--- |
| **Local** (default) | `local` | `8443` (router), `5556` (IdP) | No — you are the browser |
| **CI** | `ci` | None | Yes — Playwright runs headlessly |

Local mode is the default. Test targets (`unit-test`, `e2e-test`, `watch-tests`, `fuzzer-test`) always run in CI mode regardless of what is currently up.

---

## Targets

### Environment management

| Target | Description |
| :--- | :--- |
| `up` | Start the stack (mock IdP + simulated router). Defaults to local mode — pass `DOCKER_SUITE=ci` for the headless test stack. |
| `down` | Stop and remove stack containers. Pass the same `DOCKER_SUITE` used when starting. |
| `ps` | List running containers and their status. |
| `shell` | Open an interactive shell in the `openwrt` container. |
| `run` | Run a one-shot interactive shell (container is removed on exit). |
| `build-images` | Build Docker images from local Dockerfiles without pulling. |
| `pull` | Pull the latest pre-built images from the registry. |

### Testing

Test targets always use CI mode — start the CI stack with `make -C devenv up DOCKER_SUITE=ci` first.

| Target | Description |
| :--- | :--- |
| `unit-test` | Run unit and integration tests (Tiers 0–4). |
| `e2e-test` | Run browser-based end-to-end tests via Playwright. |
| `test` | Alias for `unit-test` followed by `e2e-test`. |
| `watch-tests` | Re-run tests automatically when files change in `files/`, `src/`, or `test/`. |
| `fuzzer-test` | Run coverage-guided fuzzing (libFuzzer + AddressSanitizer) on native C code. |
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
| `CRYPTO_LIB` | `mbedtls` | Cryptographic backend to build and test against. Accepted values: `mbedtls`, `wolfssl`, `openssl`. |

Common `SDK_ARCH` values:

| Router type | Value |
| :--- | :--- |
| Raspberry Pi 4, NanoPi (ARM64) | `aarch64_generic` |
| x86 routers (Intel/AMD) | `x86-64` |
| MIPS routers (GL.iNet, Ubiquiti) | `mipsel_24kc` |

### Test filtering

| Variable | Applies to | Description |
| :--- | :--- | :--- |
| `FILTER` | `unit-test`, `e2e-test`, `watch-tests` | Regex matched against test names. Only matching tests run. Example: `FILTER='oidc.*discovery'` |
| `MODULES` | `unit-test`, `e2e-test`, `watch-tests` | Path to a specific test file or directory. Example: `MODULES='test/tier2/oidc_logic_test.uc'` |
| `VERBOSE` | `unit-test`, `e2e-test` | Set to `1` for detailed per-test output. |

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

# Start the CI stack and run all tests
make -C devenv up DOCKER_SUITE=ci
make -C devenv unit-test
make -C devenv down DOCKER_SUITE=ci

# Run only OIDC discovery tests, with verbose output
make -C devenv unit-test FILTER='oidc.*discovery' VERBOSE=1

# Run a single test file
make -C devenv unit-test MODULES='test/tier2/oidc_logic_test.uc'

# Build and test with the wolfssl backend
make -C devenv compile CRYPTO_LIB=wolfssl
make -C devenv unit-test CRYPTO_LIB=wolfssl

# Build an IPK for a MIPS router
make -C devenv package SDK_ARCH=mipsel_24kc

# Fuzz the mbedtls backend for 10 minutes with leak detection
make -C devenv fuzzer-test CRYPTO_LIB=mbedtls TIME=600 DETECT_LEAKS=1
```
