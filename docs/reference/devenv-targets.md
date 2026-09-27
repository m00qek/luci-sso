# Makefile Targets

All development commands run through `Makefile`. Invoke them as `make <target> [VARIABLE=value ...]` from the project root.

---

## Stacks

`luci-sso` has two Docker Compose stacks. Most targets operate on one of them:

| Stack | Purpose | Ports |
| :--- | :--- | :--- |
| **CI** (`up`) | Automated tests — no ports exposed to the host | None |
| **Local** (`local-up`) | Browser interaction — router at `https://localhost:8443`, mock IdP at `https://localhost:5556` | `8443`, `5556` |

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
| `local-shell` | Local | Open an interactive shell in the local `openwrt` container. |
| `local-run` | Local | Run a one-shot interactive shell in the local stack. |
| `build-images` | CI | Build Docker images from local Dockerfiles without pulling. |
| `pull` | CI | Pull the latest pre-built images from the registry. |

### Testing

| Target | Stack | Description |
| :--- | :--- | :--- |
| `unit-test` | CI | Run the native, unit, integration and system test buckets. Requires `compile` and `up`. |
| `e2e-test` | CI | Run browser-based end-to-end tests via Playwright. Requires `compile` and `up`. |
| `test` | CI | Alias for `unit-test` followed by `e2e-test`. |
| `watch-tests` | CI | Re-run tests automatically when files change in `files/`, `src/`, or `test/`. Requires `inotify-tools` on the host. |
| `fuzzer-test` | CI | Run coverage-guided fuzzing (libFuzzer + AddressSanitizer) on native C code. Needs no running stack. |
| `sanitizer-test` | CI | Run `test/native` and `test/unit/luci_sso/crypto` against the native module built with AddressSanitizer + UndefinedBehaviorSanitizer, in an interpreter built the same way. Fails on any sanitizer report, including leaks found at process exit. Needs no running stack. |
| `lint` | — | Run the three documentation lint checks (error codes, request limits, cookies). No stack required. |

### Build

| Target | Stack | Description |
| :--- | :--- | :--- |
| `compile` | — | Compile native C components for the target architecture. Skipped if the sentinel file is current. Runs a one-shot `sdk` container; needs no running stack. |
| `package` | — | Build the `luci-sso` and `luci-sso-crypto-*` packages for `SDK_ARCH`/`SDK_VERSION` into `bin/lib/<SDK_ARCH>/<SDK_VERSION>/packages/`: `.ipk` for 24.10, `.apk` for 25.12. Replaces the previous build's `luci-sso` packages there. Runs a one-shot `sdk` container; needs no running stack. |

### Utilities

| Target | Stack | Description |
| :--- | :--- | :--- |
| `sync-headers` | — | Copy C headers from the SDK container into `devenv/.include/` for LSP support. |
| `print-env` | — | Print the value of a Makefile variable. Usage: `make print-env VAR=SDK_ARCH` |

---

## Variables

Variables are passed on the command line as `KEY=value` after the target name.

### Architecture and build

| Variable | Default | Description |
| :--- | :--- | :--- |
| `SDK_ARCH` | Host architecture | Target CPU architecture. Determines which OpenWrt SDK container is used and where build output goes. |
| `SDK_VERSION` | `24.10.5` | OpenWrt release of the SDK and `openwrt` images. `24.10.x` builds `.ipk` packages, `25.12.x` builds `.apk`. |
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
| `FILTER` | `unit-test`, `e2e-test`, `watch-tests` | Regex matched against test names. Only matching tests run. Example: `FILTER='discovery'` |
| `MODULES` | `unit-test`, `e2e-test`, `watch-tests` | Path to a specific test file or directory. Example: `MODULES='test/unit/luci_sso/oidc_test.uc'` |
| `VERBOSE` | `unit-test`, `e2e-test`, `watch-tests` | Set to `1` for detailed per-test output. |

### Fuzzer

| Variable | Default | Description |
| :--- | :--- | :--- |
| `TIME` | `60` | Fuzzer run duration in seconds. |
| `DETECT_LEAKS` | `0` | Set to `1` to enable AddressSanitizer leak detection. Disabled by default to speed up initial coverage runs. |
| `SANITIZER_LEAKS` | `1` | `sanitizer-test` only. Set to `0` to disable LeakSanitizer. |

### Container

| Variable | Default | Description |
| :--- | :--- | :--- |
| `CONTAINER` | `openwrt` | Container name used by `shell` and `run` targets. |

---

## Examples

```bash
# Build the native module, start the CI stack and run the ucode tests
make compile
make up
make unit-test

# Run only discovery tests, with verbose output
make unit-test FILTER='discovery' VERBOSE=1

# Run a single test file
make unit-test MODULES='test/unit/luci_sso/oidc_test.uc'

# Build and test with the wolfssl backend
make compile CRYPTO_LIB=wolfssl
make unit-test CRYPTO_LIB=wolfssl

# Build the packages for a MIPS router (24.10, .ipk)
make package SDK_ARCH=mipsel_24kc

# Build the packages for OpenWrt 25.12 (.apk)
make package SDK_VERSION=25.12.3

# Fuzz the mbedtls backend for 10 minutes with leak detection
make fuzzer-test CRYPTO_LIB=mbedtls TIME=600 DETECT_LEAKS=1

# Run the native and crypto buckets under ASan + UBSan (leak detection on by default)
make sanitizer-test CRYPTO_LIB=wolfssl
make sanitizer-test CRYPTO_LIB=wolfssl SANITIZER_LEAKS=0

# Open a shell in the running openwrt container
make shell

# Start the local stack and open the router in a browser at https://localhost:8443
make local-up
```
