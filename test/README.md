# Testing Gold Standard (Platinum Tier)

This project adheres to a strict testing architecture designed for security, resilience, and predictability in an embedded environment.

## 1. Running Tests

### Unit & Integration (Tiers 0-4)
These tests run inside the OpenWrt runtime container (`luci`) to ensure accurate ABI and ucode behavior.
```bash
# Run all ucode tests
make unit-test
```

### End-to-End (E2E)
These tests run in a separate Playwright container (`browser`) and verify the full OIDC flow against the Mock IdP and LuCI.
```bash
# Start the E2E stack
make e2e-up

# Run the browser tests
make e2e-test
```
*See [devenv/README.md](../devenv/README.md) for detailed environment setup.*

## 2. Testing Tiers

| Tier | Name | Scope | Goal |
| :--- | :--- | :--- | :--- |
| **0** | **Backend Compliance** | C Native Modules | Verify cryptographic primitives (SHA, HMAC, ECC) against test vectors. |
| **1** | **Plumbing** | `crypto.uc` | Verify the ucode-to-C binding layer. |
| **2** | **Business Logic** | `oidc.uc`, `session.uc` | **Core Logic.** Verify OIDC state machines, validation rules, and error handling (Offline). |
| **3** | **Integration** | CGI + UBUS | Verify system wiring, HTTP headers, and UBUS session creation. |
| **4** | **Meta** | `mock.uc` | Verify the test harness itself ensures the mocks behave correctly. |
| **E2E** | **Full Stack** | Browser ↔ IdP ↔ Router | Verify the end-to-end user experience and redirection flows. |

## 3. Testing Philosophy

1.  **Functional Core, Imperative Shell**: Most logic lives in pure modules (`crypto.uc`, `oidc.uc`) that take an injectable `io` provider.
2.  **Temporal Isolation**: Tests must never leak state. Every mock reality exists only for the duration of a closure.
3.  **Minimal Mock Context**: **Mandatory Principle.** An `io` provider must contain *only* the mocks strictly required by the function under test. Do not provide a "fat" mock handle just because it is convenient.
4.  **Minimal State Capture**: The mock only records interactions when wrapped in a `spy()` block. This prevents memory leaks and ensures no 'ghost data' leaks between tests.

## 2. Assertion Hierarchy (Stability Rules)

To keep tests robust and refactor-friendly, always follow this priority when writing assertions:

### Tier 1: Return Values (Primary)
Always assert on the function's return value first. This verifies the **Public Contract**.
*   **Target**: `assert(res.ok)`, `assert_eq(res.data.sid, "...")`.

### Tier 2: Observable State (Secondary)
If the function has side-effects (like writing a file), verify the **final state** of the mock reality rather than the call itself.
*   **Target**: `assert(io.read_file("/etc/config/pkg"))`.
*   **Avoid**: Using `spy()` to check if `write_file` was called, unless the specific arguments or frequency are the target of the test.

### Tier 3: Spies (Last Resort)
Use `spy()` ONLY for interactions that leave no persistent state in the mock, or where the protocol sequence is a security requirement.
*   **Target**: UBUS calls, Log messages, or verifying that a file was *deleted* (if it didn't exist before).
*   **Target**: `assert(data.called("ubus", "session", "login"))`.

---

## 3. Mocking with `mock.uc`

The `mock` module provides a fluent DSL for building mock realities.

### Basic Usage
```javascript
import * as mock from 'mock';

let factory = mock.create();

factory.with_env({ PATH_INFO: "/logout" }, (io) => {
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

### Spying and Interaction Queries
The `spy()` method returns a **Query Handle**. Interaction assertions should read like English sentences.

```javascript
let data = factory.with_ubus({ "session:destroy": {} }).spy((io) => {
    router.handle(io, ...);
});

// Predicate Engine: .called(type, arg1, arg2, ...)
assert(data.called("ubus", "session", "destroy"));
assert(data.called("log", "warn"));
```

---

## 3. Supported Scopes

| Scope | Description |
| :--- | :--- |
| `with_files(data, cb)` | Simulates filesystem (`read_file`, `write_file`, `lsdir`). |
| `with_uci(data, cb)` | Simulates UCI configuration packages. |
| `with_env(data, cb)` | Simulates CGI environment variables. |
| `with_responses(data, cb)` | Simulates HTTP network responses. |
| `with_ubus(data, cb)` | Simulates UBUS object/method calls. |
| `with_read_only(cb)` | Simulates a read-only filesystem (fails `write_file`, `mkdir`). |
| `spy(cb)` | Enables interaction recording and returns a Query Handle. |
| `get_stdout(cb)` | Executes a block and returns the raw captured `stdout`. |

---

## 4. ucode Syntax Gotchas

To ensure cross-version compatibility and parser stability, strictly follow these rules:

1.  **NO Optional Chaining (`?.`)**: It returns an "empty" type that crashes during evaluation.
2.  **NO Destructuring (`let {a} = obj`)**: Use explicit property assignment.
3.  **Hybrid Arrow Functions**: Use arrow functions for logic and passthroughs. Use traditional `function` when returning an object literal directly to avoid brace ambiguity.
4.  **NaN Equality**: Always use `type(x) != "int"` to detect failed integer conversions.
