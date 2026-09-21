# How to Run Tests

`luci-sso` uses a multi-tiered testing strategy. See [Testing Architecture](../../reference/testing-architecture.md) for how the tiers are structured and how to write new tests.

---

## Unit & Integration Tests (Tiers 0–4)

These tests run inside the `openwrt` container using the `ucode` interpreter. No real router or network access is required, but the CI stack must be running:

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
make unit-test FILTER='oidc.*discovery'

# Run a specific test file or directory
make unit-test MODULES='test/tier2/oidc_logic_test.uc'

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

# Watch with filters
make watch-tests FILTER='oidc' MODULES='test/tier2'
```

---

## Fuzz Testing

Coverage-guided fuzzing (libFuzzer) hardens our native C components against malformed inputs.

```bash
# Run the fuzzer for the mbedtls backend
make -sC devenv fuzzer-test CRYPTO_LIB=mbedtls
```

See [Fuzz Testing](fuzzing.md) for how to analyze crashes and interpret results.
