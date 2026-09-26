# How to Run Tests

`luci-sso` sorts its tests into four buckets: **native**, **unit**, **integration** and **e2e**. See [Testing Architecture](../../reference/testing-architecture.md) for what each bucket covers and how to write new tests.

---

## Native, Unit & Integration Tests

`make unit-test` runs three buckets inside the `openwrt` container using the `ucode` interpreter: `test/native` (the compiled crypto module), `test/unit` (one module at a time) and `test/integration` (orchestrators and wiring). No real router or network access is required, but the CI stack must be running:

```bash
make up
```

Then run the tests:

```bash
# Run all tests
make unit-test

# Run with detailed output
make unit-test VERBOSE=1

# Run tests matching a pattern (regex on test name)
make unit-test FILTER='discovery'

# Run a specific test file or directory
make unit-test MODULES='test/unit/luci_sso/oidc_test.uc'
make unit-test MODULES='test/integration'

# Select the crypto backend to test (mbedtls, wolfssl, openssl)
make unit-test CRYPTO_LIB=wolfssl
```

---

## End-to-End (E2E) Tests

These tests run in a Playwright-enabled Docker container and verify the full browser login flow against a Mock Identity Provider.

```bash
# Start the test stack
make up

# Execute all browser tests
make e2e-test

# Run tests matching a pattern
make e2e-test FILTER='login'

# Run a specific spec file
make e2e-test MODULES='test/e2e/01-login.spec.js'
```

---

## Automated Watcher

You can run tests automatically whenever a file is changed in the `files/`, `src/`, or `test/` directories. This requires `inotify-tools` installed on your host machine.

```bash
# Watch and re-run both unit and E2E tests
make watch-tests

# Watch with a filter (applied to both the unit and the E2E run)
make watch-tests FILTER='login'
```

`watch-tests` passes `MODULES` to both runners, so a path only makes sense for one of them. Filter by name instead.

---

## Fuzz Testing

Coverage-guided fuzzing (libFuzzer) hardens our native C components against malformed inputs.

```bash
# Run the fuzzer for the mbedtls backend
make fuzzer-test CRYPTO_LIB=mbedtls
```

See [Fuzz Testing](fuzzing.md) for how to analyze crashes and interpret results.

## Sanitizer Testing

The fuzzer drives the native module with random input. `sanitizer-test` complements it with the real test suites that exercise the module (`test/native` and `test/unit/luci_sso/crypto`), run against a copy built with AddressSanitizer and UndefinedBehaviorSanitizer, so every known-answer and boundary case also runs with memory checks.

```bash
make sanitizer-test CRYPTO_LIB=mbedtls
```

It runs in the fuzzer container, not the OpenWrt one. OpenWrt's ucode is built with gcc, and gcc's sanitizer runtime does not support musl. So the container builds ucode and utest from source with clang's, at the same versions the devenv ships. The target fails on a test failure, a crash, or any sanitizer report. That includes leaks, which LeakSanitizer reports only when a worker process exits, after utest has already recorded a pass. Set `SANITIZER_LEAKS=0` to skip leak detection.

The unit and integration buckets beyond crypto need `uci`, `ubus` and `lucihttp`, which that container does not build, so they are not covered.
