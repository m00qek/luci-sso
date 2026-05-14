# devenv Makefile Reference

All development commands run through `devenv/Makefile`. Invoke them as `make -C devenv <target> [VARIABLE=value ...]` from the project root.

---

## Stacks

`luci-sso` has two Docker Compose stacks. Most targets operate on one of them:

| Stack | Purpose | Ports |
| :--- | :--- | :--- |
| **CI** (`up`) | Automated tests — no ports exposed to the host | None |
| **Local** (`local-up`) | Browser interaction — router accessible at `https://localhost:8443` | `8443` |

---

## Targets

### Environment management

| Target | Stack | Description |
| :--- | :--- | :--- |
| `up` | CI | Start the CI stack (mock IdP + simulated router). Required before running tests. |
| `down` | CI | Stop and remove CI stack containers. |
| `ps` | CI | List running CI containers and their status. |
| `shell` | CI | Open an interactive shell in the `openwrt` container. |
| `run` | CI | Run a one-shot interactive shell (container is removed on exit). |
| `local-up` | Local | Start the local stack with ports exposed at `localhost:8443`. |
| `local-down` | Local | Stop and remove local stack containers. |
| `local-ps` | Local | List running local containers. |
| `local-shell` | Local | Open an interactive shell in the local `openwrt` container. |
| `local-run` | Local | Run a one-shot interactive shell in the local stack. |
| `build-images` | CI | Build Docker images from local Dockerfiles without pulling. |
| `pull` | CI | Pull the latest pre-built images from the registry. |

### Testing

| Target | Stack | Description |
| :--- | :--- | :--- |
| `unit-test` | CI | Run unit and integration tests (Tiers 0–4). Requires `up`. |
| `e2e-test` | CI | Run browser-based end-to-end tests via Playwright. Requires `up`. |
| `test` | CI | Alias for `unit-test` followed by `e2e-test`. |
| `watch-tests` | CI | Re-run tests automatically when files change in `files/`, `src/`, or `test/`. Requires `inotify-tools` on the host. |
| `fuzzer-test` | CI | Run coverage-guided fuzzing (libFuzzer + AddressSanitizer) on native C code. |
| `lint` | — | Run the three documentation lint checks (error codes, request limits, cookies). No stack required. |

### Build

| Target | Stack | Description |
| :--- | :--- | :--- |
| `compile` | CI | Compile native C components for the target architecture. Skipped if the sentinel file is current. |
| `package` | CI | Build the `.ipk` package for the target architecture. |

### Utilities

| Target | Stack | Description |
| :--- | :--- | :--- |
| `sync-headers` | CI | Copy C headers from the SDK container into `devenv/.include/` for LSP support. |
| `print-env` | — | Print the value of a Makefile variable. Usage: `make -C devenv print-env VAR=SDK_ARCH` |

---

## Variables

Variables are passed on the command line as `KEY=value` after the target name.

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
# Start the CI stack and run all tests
make -C devenv up
make -C devenv unit-test

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

# Open a shell in the running openwrt container
make -C devenv shell

# Start the local stack and open the router in a browser at https://localhost:8443
make -C devenv local-up
```
