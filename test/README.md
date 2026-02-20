# Testing Standards and Verification

This project adheres to a strict testing architecture designed for security, resilience, and predictability in an embedded environment.

## 1. Architecture

The testing framework is a custom, modular library built natively in ucode to ensure zero external dependencies in the target runtime.

### Directory Structure
Tests are organized into **Suites** corresponding to architectural layers:

*   **`tier0/` (Backend Compliance):** Native C binding tests. Verifies cryptographic primitives (SHA, HMAC, ECC) and memory safety.
*   **`tier1/` (Cryptographic Plumbing):** Low-level ucode logic. Verifies the binding layer and core utilities (including constant-time comparisons).
*   **`tier2/` (Business Logic):** The core application logic. Verifies OIDC state machines (including split-horizon path preservation), role mapping, and configuration parsing.
*   **`tier3/` (Integration Tests):** Full system simulation. Verifies CGI headers, UBUS session management, and end-to-end flows using mocks.
*   **`tier4/` (Meta Tests):** Self-tests for the framework itself.

### Core Components
*   **`test/runner.uc`**: The CLI orchestrator. Handles environment variables (`VERBOSE`, `FILTER`, `MODULES`) and invokes the library.
*   **`test/testing.uc`**: The public facade. Manages global state and exports the DSL (`test`, `assert`).
*   **`test/testing/`**: Implementation modules (Loader, Matcher, Runner, Reporters).

---

## 2. Running Tests

### Standard Run
Executes all suites in order (Tier 0 -> Tier 4).
```bash
make unit-test
```

### Verbose Mode
Use `VERBOSE=1` to see a detailed, line-by-line report of every test case.
```bash
make unit-test VERBOSE=1
```

### Filtered Run (Regex)
Use `FILTER` to run only tests whose names match a regular expression.
```bash
# Run only compliance tests regarding SHA256
make unit-test FILTER='compliance.*SHA256'
```

### Targeted Run (Modules)
Use `MODULES` to run specific test files (whitelist). This bypasses the full suite execution but still reports "ignored" tests from the same suite for context.
```bash
# Run only specific files (comma or space separated)
make unit-test MODULES='test/tier0/native_compliance_test.uc,test/tier2/oidc_logic_test.uc'
```

### End-to-End (E2E)
These tests run in a separate Playwright container (`browser`) and verify the full OIDC flow against the Mock IdP and LuCI.
```bash
# Start the E2E stack
make e2e-up

# Run the browser tests
make e2e-test
```

---

## 3. Writing Tests

### The DSL
Tests are defined using the `test` function exported by the `testing` module.

```javascript
import { test, test_skip, assert, assert_eq, assert_throws, assert_match } from 'testing';

test('feature: success scenario', () => {
    let result = 1 + 1;
    assert_eq(result, 2, "Math should work");
});

test_skip('feature: broken scenario', () => {
    // This will be reported as [SKIP] or ○
    assert(false); 
});
```

### Assertions
*   `assert(cond, [msg])`: Fails if condition is falsy.
*   `assert_eq(actual, expected, [msg])`: Deep equality check (objects/arrays).
*   `assert_match(actual, regex, [msg])`: Fails if string does not match regex.
*   `assert_throws(fn, [msg])`: Fails if function does not throw.
*   `assert_fail([msg])`: Unconditional failure.

### Isolation & State
*   **File Isolation:** Each file is loaded independently.
*   **Test Isolation:** Tests within a suite are **shuffled** before execution to detect side-effect leakage.
*   **Mocking:** Use `test/mock.uc` to create isolated realities.

---

## 4. Mocking Strategy

The `mock` module provides a fluent DSL for building isolated test environments.

### Basic Usage
```javascript
import * as mock from 'mock';

let factory = mock.create();

factory.with_env({ PATH_INFO: "/logout" }, (io) => {
    // 'io' is a self-contained object implementing the system interface
    let req = web.request(io);
    assert_eq(req.path, "/logout");
});
```

### Surgical State Inheritance (`using`)
If a test requires sequential operations with accumulating state, use `using(io)` to derive a new reality from a previous one.

```javascript
factory.with_files({ "/etc/key": "123" }, (io) => {
    // 1. First function only gets files
    let handshake = session.create_state(io);

    // 2. Second function needs Files + Network (Chain surgically)
    factory.using(io).with_responses({ "https://idp/jwks": {...} }).spy((spying_io) => {
        router.handle(spying_io, ...);
    });
});
```

### Spying
The `spy()` method returns a **Query Handle** to verify side-effects (logging, UBUS calls).

```javascript
let data = factory.with_ubus({ "session:destroy": {} }).spy((io) => {
    router.handle(io, ...);
});

// Predicate Engine: .called(type, arg1, arg2, ...)
assert(data.called("ubus", "session", "destroy"));
assert(data.called("log", "warn"));
```

---

## 5. Coding Standards

1.  **NO Globals:** Tests must not rely on or modify `global` scope outside of the `testing` framework itself.
2.  **Explicit Imports:** All test files must import `testing` and `mock` explicitly.
3.  **Fixture Localization:** Fixtures (static data) should be placed in `test/tierX/fixtures.uc` and imported only by tests in that tier to prevent coupling.
4.  **No Top-Level Side Effects:** Test files should only register tests at the top level. Execution logic must be inside the `test()` closure.
