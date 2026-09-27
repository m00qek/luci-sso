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

All I/O — network requests, filesystem access, ubus, UCI, timestamps, randomness and logging — is injected through a `deps` object rather than called directly. This allows every function to be tested offline with a fake environment.

```javascript
// Production (the CGI script): real modules, wired by deps.uc
let deps = create();                          // from luci_sso.deps
discover(deps, "https://idp.example.com");    // luci_sso.discovery

// Test: the same call with a deps object whose fields are fakes
discover(fake_deps, "https://idp.example.com");
```

The alternative — calling `uclient`, `time()`, or filesystem functions directly — makes code untestable in the embedded target environment. OpenWrt routers can't run real network tests, so every external call must be fakeable.

**What belongs in `deps`** (external or non-deterministic):
`fs`, `http`, `ubus`, `uci`, `clock`, `native` (the crypto bridge, which also supplies randomness) and `log`

**What does not** (deterministic, pure functions):
string manipulation, Base64URL and JSON handling, URL normalization

`log` is part of every `deps` object. Logging is not optional in a security-critical application.

---

### Security Invariants Live in Code, Not UCI

Configuration has two dimensions: UCI (admin-controlled) and code (fixed at build time). Security invariants — like the list of allowed JWT algorithms — are constants in code, not UCI options and not function parameters, so neither a misconfigured router nor a careless caller can weaken the security model.

```javascript
// oidc.uc
const ALLOWED_ALGS = ["RS256", "ES256"];
```

This prevents "Algorithm Confusion" and "Reflective Trust" attacks where an attacker manipulates configuration to bypass validation.

---

### Minimal C Code

Cryptographic primitives belong in C, delegated to a crypto library (mbedTLS, wolfSSL or OpenSSL). Everything else — business logic, state machines, role mapping, string parsing — belongs in ucode.

C code is harder to audit, harder to test, and harder to port. Every line of C should justify its existence. If it can be done in ucode, do it in ucode.

---

### Backend Abstraction

Cryptographic backends must be swappable. Code must never import a backend directly. Every backend package installs its build as `luci_sso/native.so`, so the name `luci_sso.native` always means the backend that is installed. Only `deps.uc` imports it; everything else receives it as `deps.native`.

```javascript
// Wrong: hard-codes a backend
import * as mbedtls from 'native_mbedtls';

// Correct: use the native module passed in through deps
let res = crypto.hash_sha256(deps.native, data);
```

---

## Error Handling Philosophy

Two kinds of failure exist in this codebase, and they are handled differently.

**Contract bugs** (programming errors — wrong types, invalid state) use `die()`. These are bugs in calling code. Crashing fast prevents undefined behavior and makes the bug immediately visible.

**Runtime realities** (expected failures — expired token, network down, invalid signature) use `Result` objects. These are valid states the application handles. Returning a `Result.err("CODE")` lets the caller decide how to respond.

The reason to return `Result` objects rather than throwing everywhere: in a CGI environment, an unhandled exception produces a generic 500 error. Explicit `Result` errors allow the web layer to return meaningful HTTP responses and log useful diagnostics.

See `docs/reference/style-guide.md` for the specific error code format and `die()` vs result decision tree.
