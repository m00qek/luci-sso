# How to Run Tests

`luci-sso` uses a multi-tiered testing strategy. See [Testing Architecture](../../reference/testing-architecture.md) for how the tiers are structured and how to write new tests.

---

## Unit & Integration Tests (Tiers 0–4)

These tests run natively using the `ucode` interpreter. No network or router hardware required.

```bash
# Run all tests
make -C devenv unit-test

# Run with detailed output
make -C devenv unit-test VERBOSE=1

# Run tests matching a pattern
make -C devenv unit-test FILTER='oidc.*discovery'
```

---

## End-to-End (E2E) Tests

These tests run in a Playwright-enabled Docker container and verify the full browser login flow against a Mock Identity Provider.

```bash
# Start the test stack
make -C devenv up

# Execute browser tests
make -C devenv e2e-test
```

---

## Fuzz Testing

Coverage-guided fuzzing (libFuzzer) hardens our native C components against malformed inputs.

```bash
# Run the fuzzer for the mbedtls backend
make -sC devenv fuzzer-test CRYPTO_LIB=mbedtls
```

See [Fuzz Testing](fuzzing.md) for how to analyze crashes and interpret results.
