# How to Run Tests

`luci-sso` uses a multi-tiered testing strategy. See [Testing Architecture](../../reference/testing-architecture.md) for how the tiers are structured and how to write new tests.

All test targets require the shared CI infrastructure to be running first. Start it once per session and leave it up:

```bash
make -C devenv infra-up DOCKER_SUITE=ci
```

Each test target manages its own OpenWrt container — it starts one, runs the tests, and removes it automatically.

---

## Unit & Integration Tests (Tiers 0–4)

These tests run inside the `openwrt` container using the `ucode` interpreter. No real router or network access is required.

```bash
# Run all tests
make -C devenv test

# Run with detailed output
make -C devenv test VERBOSE=1

# Run tests matching a pattern (regex on test name)
make -C devenv test FILTER='oidc.*discovery'

# Run a specific test file or directory
make -C devenv test MODULES='test/tier2/oidc_logic_test.uc'

# Select the crypto backend to test (mbedtls, wolfssl, openssl)
make -C devenv test CRYPTO_LIB=wolfssl
```

Multiple `make test` runs can execute in parallel — each targets its own container by project name and does not conflict with other versions or crypto backends.

---

## End-to-End (E2E) Tests

These tests run in a headless Playwright container and verify the full browser login flow against the mock Identity Provider.

```bash
# Execute all browser tests
make -C devenv e2e

# Run tests matching a pattern
make -C devenv e2e FILTER='login'

# Run a specific spec file
make -C devenv e2e MODULES='test/e2e/01-login.spec.js'
```

Only one `make e2e` can run at a time locally — the browser container resolves `luci.luci-sso.test` by DNS and cannot distinguish between two simultaneous OpenWrt containers. The command will refuse to start if another e2e run is already in progress.

---

## Automated Watcher

Re-runs both unit and E2E tests automatically when a file changes in `files/`, `src/`, or `test/`. Requires `inotify-tools` on the host.

```bash
make -C devenv watch-tests

# Watch with filters
make -C devenv watch-tests FILTER='oidc' MODULES='test/tier2'
```

`watch-tests` starts an OpenWrt container when launched and stops it when it exits (Ctrl+C). It is subject to the same single-run constraint as `e2e`.

---

## Fuzz Testing

Coverage-guided fuzzing (libFuzzer) hardens the native C components against malformed inputs. No infrastructure required.

```bash
# Run the fuzzer for the mbedtls backend
make -sC devenv fuzz CRYPTO_LIB=mbedtls
```

Multiple `make fuzz` runs can execute in parallel across different backends or versions.

See [Fuzz Testing](fuzzing.md) for how to analyze crashes and interpret results.

---

## Tear down

When done for the session:

```bash
make -C devenv infra-down DOCKER_SUITE=ci
```
