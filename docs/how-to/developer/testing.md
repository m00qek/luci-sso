# Running Tests

`luci-sso` uses a multi-tiered testing strategy to ensure security, protocol compliance, and environment resilience.

---

## 🏗️ Testing Architecture

Tests are organized into five tiers, moving from low-level crypto to full system simulation:

| Tier | Scope | Target |
| :--- | :--- | :--- |
| **Tier 0** | Native Backend | Cryptographic primitives (SHA, HMAC, ECC) and memory safety in C. |
| **Tier 1** | Crypto Plumbing | Low-level ucode logic and constant-time comparisons. |
| **Tier 2** | Business Logic | OIDC state machines, role mapping, and configuration parsing. |
| **Tier 3** | Integration | Full system simulation (CGI headers, UBUS, I/O) using mocks. |
| **Tier 4** | Framework | Self-tests for the testing library itself. |

---

## 🚀 How to Run Tests

### 1. Unit & Integration Tests (Tiers 0-4)
These tests run natively in the project environment using the `ucode` interpreter.

```bash
# Run all tests
make unit-test

# Run with detailed output
make unit-test VERBOSE=1

# Run specific tests matching a pattern
make unit-test FILTER='oidc.*discovery'
```

### 2. End-to-End (E2E) Tests
These tests run in a Playwright-enabled Docker container and verify the full browser login flow against a Mock Identity Provider.

```bash
# Start the test stack
make up

# Execute browser tests
make e2e-test
```

### 3. Fuzz Testing
We use coverage-guided fuzzing (**libFuzzer**) to harden our native C components against malformed inputs.

```bash
# Run the fuzzer for the mbedtls backend
make -sC devenv fuzzer-test CRYPTO_LIB=mbedtls
```

---

## 🧪 Writing Tests & Mocking

We use a custom mocking library (`test/mock.uc`) to simulate the OpenWrt environment (Filesystem, Network, UBUS).

### Basic Mock Example
```javascript
import * as mock from 'mock';

let factory = mock.create();

// Create an isolated reality with specific files
factory.with_files({ "/etc/config/luci-sso": "..." }, (io) => {
    // Your code uses 'io' instead of the real system
    let config = load_config(io);
    assert_eq(config.enabled, 1);
});
```

### Verifying Side-Effects (Spying)
You can verify that your code performed specific actions, like logging a security warning or calling a UBUS method:

```javascript
let data = factory.with_ubus({ "session:destroy": {} }).spy((io) => {
    perform_logout(io);
});

// Verify the side-effect occurred
assert(data.called("ubus", "session", "destroy"));
assert(data.called("log", "warn"));
```
