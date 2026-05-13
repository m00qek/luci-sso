# Design Philosophy

`luci-sso` is built around a small set of principles that reflect the constraints of its environment: a security-critical authentication plugin running on resource-constrained embedded hardware, where failures have real consequences.

---

## Core Tenets

1. **Security First** — Authentication code must be paranoid. Fail closed. Never assume external input is benign.
2. **Minimal Dependencies** — The plugin must work within OpenWrt's constraints: 64MB RAM, 16MB flash, no Python/Node.js/Go runtime. Every dependency is a liability.
3. **Testability** — All logic must be unit-testable offline, without a real IdP, without a real network. This is non-negotiable in an embedded environment where you can't run integration tests on the target hardware.
4. **OpenWrt Native** — Follow OpenWrt and ucode conventions. This is not a Node.js project.
5. **Explicit Over Implicit** — Code should be obvious to a reader, not clever.

---

## Architecture Principles

### Dependency Injection for I/O

All I/O — network requests, filesystem access, timestamps, randomness — is injected through an `io` object rather than called directly. This allows every function to be tested offline with a mock environment.

```javascript
// Production: real I/O
let io = create_io();
discover(io, "https://idp.com");

// Test: controlled, offline I/O
let mock_io = create_mock_io();
discover(mock_io, "https://idp.com");
```

The alternative — calling `uclient`, `time()`, or filesystem functions directly — makes code untestable in the embedded target environment. OpenWrt routers can't run real network tests, so every external call must be mockable.

**What belongs in the `io` object** (non-deterministic or external state):
`time`, `random`, `log`, `http_get`, `http_post`, `read_file`, `write_file`

**What does not** (deterministic, pure functions):
string manipulation, JSON parsing, cryptographic hashes

The `log` function is mandatory in all `io` implementations. Logging is not optional in a security-critical application.

---

### Two-Dimensional Configuration (Policy Pattern)

Configuration has two dimensions: UCI (admin-controlled) and policy (logic-controlled). Security invariants — like the list of allowed JWT algorithms — live in policy, not UCI, so a misconfigured router cannot weaken the security model.

```javascript
export function verify(tokens, config, policy) {
    const DEFAULT_POLICY = { allowed_algs: ["RS256", "ES256"] };
    let p = policy || DEFAULT_POLICY;
    // p.allowed_algs is not user-editable
};
```

This prevents "Algorithm Confusion" and "Reflective Trust" attacks where an attacker manipulates configuration to bypass validation.

---

### Minimal C Code

Cryptographic primitives belong in C (MbedTLS/WolfSSL via PSA Crypto API). Everything else — business logic, state machines, role mapping, string parsing — belongs in ucode.

C code is harder to audit, harder to test, and harder to port. Every line of C should justify its existence. If it can be done in ucode, do it in ucode.

---

### Backend Abstraction

Cryptographic backends must be swappable. Code must never import a backend directly. All crypto goes through the `luci_sso.native` wrapper, which resolves to the appropriate compiled backend at runtime.

```javascript
// Wrong: hard-codes a backend
import * as mbedtls from 'native_mbedtls';

// Correct: backend-agnostic
import * as native from 'luci_sso.native';
```

---

## Error Handling Philosophy

Two kinds of failure exist in this codebase, and they are handled differently.

**Contract bugs** (programming errors — wrong types, invalid state) use `die()`. These are bugs in calling code. Crashing fast prevents undefined behavior and makes the bug immediately visible.

**Runtime realities** (expected failures — expired token, network down, invalid signature) use `Result` objects. These are valid states the application handles. Returning a `Result.err("CODE")` lets the caller decide how to respond.

The reason to return `Result` objects rather than throwing everywhere: in a CGI environment, an unhandled exception produces a generic 500 error. Explicit `Result` errors allow the web layer to return meaningful HTTP responses and log useful diagnostics.

See `docs/reference/style-guide.md` for the specific error code format and `die()` vs result decision tree.
