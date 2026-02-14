# LuCI SSO Style Guide

This document defines coding standards, architectural patterns, and design decisions for the luci-sso project.

---

## ⚠️ Important Notes

### About Code Examples

All code examples in this guide follow the style rules defined herein. Examples are formatted with:
- **Tabs for indentation** (may render as spaces in some viewers)
- **snake_case naming** (OpenWrt convention)
- **Trailing semicolons on exports** (ucode requirement)

For real-world implementations, see:
- [`files/usr/share/ucode/luci_sso/`](../files/usr/share/ucode/luci_sso/) - Production code
- [`test/unit/`](../test/unit/) - Test code

### Living Document

This guide evolves with the project. When you find inconsistencies or have questions:
1. Check existing code for precedent
2. Open an issue or PR with your question
3. Update this guide with the decision

---

## Table of Contents

1. [Philosophy](#philosophy)
2. [Terminology](#terminology)
3. [Architecture Principles](#architecture-principles)
4. [Error Handling](#error-handling)
5. [Testing Standards](#testing-standards)
6. [ucode Style](#ucode-style)
7. [C Code Style](#c-code-style)
8. [Module Organization](#module-organization)
9. [Security Guidelines](#security-guidelines)
10. [Documentation Standards](#documentation-standards)
11. [Commit Messages](#commit-messages)
12. [Code Review Checklist](#code-review-checklist)
13. [Development Workflow](#development-workflow)

---

## 1. Philosophy

### Core Tenets

1. **Security First** - All authentication/authorization code MUST be paranoid.
2. **Minimal Dependencies** - The footprint SHALL remain small for embedded systems.
3. **Testability** - All logic MUST be unit-testable without a real IdP.
4. **OpenWrt Native** - Code MUST follow OpenWrt/ucode conventions, NOT Node.js patterns.
5. **Explicit Over Implicit** - Code SHOULD be obvious, not clever.

### Design Goals

- ✅ Work on resource-constrained routers (64MB RAM, 16MB flash)
- ✅ Support major OIDC providers (Google, Microsoft, generic)
- ✅ Be auditable (security-critical code should be simple)
- ✅ Fail safely (reject invalid auth rather than allow)

---

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document and all other project documentation are to be interpreted as described in [RFC 2119](https://tools.ietf.org/html/rfc2119).

---

## 3. Architecture Principles

### 1. Dependency Injection for I/O

Developers MUST use dependency injection for all I/O operations to enable offline verification.

**✅ CORRECT:**

```javascript
export function discover(io, issuer, options) {
	let response = io.http_get(discovery_url);
	let now = io.time();
	// ...
};

// Production
let io = create_io();
discover(io, "https://idp.com");

// Test
let mock_io = create_mock_io();
discover(mock_io, "https://idp.com");
```

**❌ INCORRECT:**

```javascript
import * as fs from 'fs';

export function discover(issuer, options) {
	let response = uclient.new(discovery_url);  // Hard to mock
	let now = time();  // Hard to mock
};
```

**Rationale:** OpenWrt routers can't run real network tests. All tests must work offline with mocks.

---

### 2. What Belongs in IO Object

Methods representing non-deterministic or external state MUST be part of the `io` provider.

**MANDATORY Scopes (External State):**

```javascript
let io = {
	time: function() { return time(); },           // ✅ Current timestamp
	random: function(n) { return crypto.random(n); },  // ✅ Unpredictable
	log: function(level, msg) { /* ... */ },       // ✅ Mandatory Auditing
	http_get: function(url) { /* ... */ },         // ✅ Network I/O
	http_post: function(url, opts) { /* ... */ },  // ✅ Network I/O
	read_file: function(path) { /* ... */ },       // ✅ Filesystem I/O
	write_file: function(path, data) { /* ... */ } // ✅ Filesystem I/O
};
```

**DON'T include (pure functions, deterministic):**

```javascript
// Import as utilities, don't put in IO object
import { urlencode } from 'luci_sso.utils';  // ❌ String transformation
// Use built-ins directly
let parsed = json(str);     // ❌ String parsing
let hash = sha256(msg);     // ❌ Cryptographic hash (deterministic)
let result = replace(s, p, r);  // ❌ String manipulation
```

**Rule of Thumb:** If the function always returns the same output for the same input and has no side effects, it's NOT I/O.

**Contractual Obligation:** The `log` function MUST be present in all `io` provider implementations. Logs are NOT optional in this security-critical application.

---

### 3. Two-Dimensional Config (Policy Pattern)

**ALWAYS** use the policy dimension for internal security enforcement that should NOT be editable by the system administrator.

```javascript
// Dimension 1: config (UCI) - Admin controlled
// Dimension 2: policy (Internal) - Logic controlled
export function verify(tokens, config, policy) {
    const DEFAULT_POLICY = { allowed_algs: ["RS256"] };
    let p = policy || DEFAULT_POLICY;
    
    // Use p.allowed_algs for verification
};
```

**Rationale:** Prevents "Algorithm Confusion" and "Reflective Trust" vulnerabilities by keeping critical whitelists out of UCI.

---

### 4. Minimal C Code

Cryptographic operations SHALL be implemented in C. Higher-level business logic MUST remain in ucode.

**C code SHALL contain:**
- Cryptographic primitives (RSA/EC verification, HMAC, CSPRNG).
- Performance-critical code (if profiling identifies a bottleneck).

**C code MUST NOT contain:**
- Business logic (OAuth2 state machines, role merging).
- String manipulation or JSON parsing.
- Direct I/O operations (HTTP or File access).

### 5. Backend Abstraction

Cryptographic backends MUST be swappable. Code MUST NOT import a backend directly (e.g. `native_mbedtls`). All logic MUST utilize the `luci_sso.native` wrapper.

```javascript
// ❌ INCORRECT
import * as mbedtls from 'native_mbedtls';

// ✅ CORRECT
import * as native from 'luci_sso.native';
```

---

## 4. Error Handling

### Contract Bugs vs. Runtime Realities

We distinguish between errors caused by the programmer (Contract Bugs) and errors caused by the environment or user (Runtime Realities).

#### 1. Contract Bugs (Programming Errors)
**Action: Use `die()`**
If a function is called with the wrong types or in an invalid state, this is a bug in the calling code. The system should "fail fast" to prevent undefined behavior.

```javascript
export function sign_jws(payload, secret) {
	if (type(payload) != "object") die("CONTRACT_VIOLATION: payload must be an object");
	if (type(secret) != "string") die("CONTRACT_VIOLATION: secret must be a string");
	// ...
};
```

#### 2. Runtime Realities (Expected Failures)
**Action: Use Result Objects or Exceptions**
If an operation fails due to external factors (expired token, network down, invalid signature), this is a valid state that the application might want to handle.

- **Exceptions:** Use for "stop the world" failures where the caller likely can't recover easily (e.g., malformed discovery response).
- **Result Objects:** Use for common business logic branches (e.g., token expired vs. invalid signature).

```javascript
// Result Object Pattern
export function verify_session(io, token) {
	// ... logic ...
	if (expired) return { ok: false, error: "EXPIRED" };
	if (bad_sig) return { ok: false, error: "INVALID_SIGNATURE" };
	
	return { ok: true, data: payload };
}
```

### Exception vs. Result Object Decision Tree

```
Is the failure a programming error (wrong types, null pointer)?
├─ YES → Use die() (Fail Fast)
└─ NO  → Is it a common logic branch (e.g. Expired)?
   ├─ YES → Return Result Object { ok: false, error: "CODE" }
   └─ NO  → Throw/Die with "CODE: message"
```

---

### Error Code Format

**Structure:** `CATEGORY_SPECIFIC_REASON`

**Categories:**
- `INVALID_*` - Bad input (caller error)
- `*_FAILED` - Operation failed (transient)
- `*_MISMATCH` - Validation failed (security)
- `MISSING_*` - Required data absent
- `UNSUPPORTED_*` - Feature not implemented

**Examples:**

```javascript
"INVALID_ARGUMENT"      // Bad function argument
"DISCOVERY_FAILED"      // HTTP request failed
"ISSUER_MISMATCH"       // JWT iss claim doesn't match
"MISSING_ID_TOKEN"      // OAuth2 response lacks id_token
"UNSUPPORTED_ALGORITHM" // JWT alg not supported
```

---

### Never Silently Fail

**❌ INCORRECT:**

```javascript
let result = verify_jwt(token, key, opts);
// Forgot to check result.error
use(result.payload);  // Undefined if error occurred
```

**✅ CORRECT:**

```javascript
// With exceptions (automatic propagation)
let payload = verify_jwt(token, key, opts);
use(payload);  // Exception thrown if verification failed

// With result objects (explicit check)
let result = verify_session(io, token);
if (result.error) {
	return handle_error(result.error);
}
use(result.session);
```

---

## 5. Testing Standards

### Reference Implementation Tests

**All tests in `test/unit/` serve as reference implementations.**

Tests are not just validation—they are:
- ✅ **Documentation** - Show how to use the API
- ✅ **Specification** - Define correct behavior
- ✅ **Safety net** - Prevent regressions

### Test Requirements

1. **Mandatory Coverage:** Every exported function MUST have unit tests.
2. **Failure Verification:** Every error path MUST be verified by a corresponding test case.
3. **Attack Simulation:** Security-critical code MUST have specialized attack tests.
4. **Offline Purity:** All tests MUST be runnable offline without external network dependencies.

### Test Structure

```javascript
import { test, assert, assert_eq } from 'testing';
import * as module_under_test from 'luci_sso.module';
import { create_mock_io } from 'helpers';

test('Feature: Success case', () => {
	let io = create_mock_io();
	
	// Setup
	io._responses["https://idp.com/.well-known"] = {
		status: 200,
		body: "{}"
	};
	
	// Execute
	let result = module_under_test.function(io, args);
	
	// Assert
	assert(!result.error, "Should succeed");
	assert_eq(result.data, expected);
});

test('Feature: Error case', () => {
	let io = create_mock_io();
	io._responses["https://idp.com/.well-known"] = {
		status: 500,
		body: ""
	};
	
	try {
		module_under_test.function(io, args);
		assert(false, "Should have thrown");
	} catch (e) {
		assert(index(e, "EXPECTED_ERROR") >= 0);
	}
});
```

---

### Test Naming Convention

**Pattern:** `test('Module: Feature - Condition', () => { ... })`

**Examples:**

```javascript
test('JWT: Verify RS256 signature', () => { /* ... */ });
test('JWT: Reject expired token', () => { /* ... */ });
test('JWT: Handle missing algorithm', () => { /* ... */ });
test('OIDC: Discovery caching', () => { /* ... */ });
test('Security: Reject alg=none attack', () => { /* ... */ });
```

---

### Test Coverage Requirements

**Minimum coverage per function:**
- ✅ 1 success case (happy path)
- ✅ 1 error case per error type
- ✅ Edge cases (empty input, null, boundary values)
- ✅ Security cases (tampering, injection, bypass attempts)

**Example for `verify_jwt()`:**

```javascript
test('JWT: Valid token succeeds', () => { /* ... */ });
test('JWT: Expired token rejected', () => { /* ... */ });
test('JWT: Invalid signature rejected', () => { /* ... */ });
test('JWT: Malformed token rejected', () => { /* ... */ });
test('JWT: Wrong algorithm rejected', () => { /* ... */ });
test('JWT: Missing header rejected', () => { /* ... */ });
test('JWT: Tampered payload rejected', () => { /* ... */ });
test('Security: Alg=none attack rejected', () => { /* ... */ });
```

---

## 6. ucode Style

### General Formatting

```javascript
// Indentation: TABS (OpenWrt standard, matches C code)
function example() {
	let x = 1;
	if (x > 0) {
		print("positive\n");
	}
}

// Line length: 100 characters (soft limit)
// Exceptions allowed for URLs, long strings
```

---

### Function Declarations

**Exported functions need trailing semicolon:**

```javascript
export function function_name(arg1, arg2) {
	// body
};  // ← Note trailing semicolon
```

**Private functions don't:**

```javascript
function helper_function(arg) {
	// body
}  // ← No semicolon
```

**Rationale:** Export statements are expressions in ucode. Consistency with OpenWrt's ucode codebase.

---

### Variable Declarations

- **Mandatory Let:** All variables MUST be declared using `let` (never `var`).
- **Constants:** TRUE constants MUST use `UPPERCASE` naming.
- **Naming Convention:** All other variables and functions MUST use `snake_case`.

### String Formatting

- **Interpolation:** Logic SHOULD use template literals for string building.
- **Quotes:** Double quotes MUST be used for standard strings.

### Imports

- **Ordering:** Imports MUST follow the order: Standard Library, External Dependencies, Internal Modules.

---

### Comments

```javascript
// Single-line comments for inline notes
let x = compute();  // Cache for performance

/**
 * Multi-line JSDoc-style for exported functions.
 * 
 * @param {object} io - I/O provider { http_get, time, ... }
 * @param {string} issuer - IdP issuer URL
 * @param {object} [options] - Optional configuration
 * @returns {object} - Decoded payload
 * @throws {string} - Error code on failure
 */
export function discover(io, issuer, options) {
	// ...
};

// TODO comments for planned work
// TODO: Add support for P-384 curve
```

---

### Control Flow

```javascript
// Always use braces, even for single statements
if (condition) {
	do_something();
}

// NOT:
// if (condition) do_something();  // ❌

// Early returns for error cases
function validate(input) {
	if (!input) die("MISSING_INPUT");
	if (type(input) != "string") die("INVALID_TYPE");
	
	// Happy path at end
	return process(input);
}
```

---

## 7. C Code Style

### Standards: MbedTLS 3.x / PSA Crypto
This project exclusively uses **MbedTLS 3.x**. All new cryptographic operations MUST be implemented using the **PSA Crypto API** (`psa/crypto.h`).

**Requirements:**
- ✅ Call `psa_crypto_init()` in `uc_module_init`.
- ✅ Check `psa_status_t` for ALL operations.
- ✅ Use opaque handles (`psa_key_id_t`) where possible.
- ✅ Destroy keys (`psa_destroy_key`) on all return paths.
- ✅ Use `MBEDTLS_PRIVATE()` macro if direct structure access is unavoidable (deprecated).

---

### Minimize C Code

**Ask first:** "Can this be done in ucode?"
- If YES → Do it in ucode
- If NO (crypto/performance) → Write minimal C

---

### Function Naming

```c
// Pattern: uc_<backend>_<operation>
static uc_value_t *uc_mbedtls_verify_rs256(uc_vm_t *vm, size_t nargs);
static uc_value_t *uc_mbedtls_hmac_sha256(uc_vm_t *vm, size_t nargs);

// NOT generic names (backend might be swapped)
// ❌ uc_verify_rs256
```

---

### Error Handling in C

```c
// Return NULL for errors (ucode convention)
if (error_condition) {
	mbedtls_pk_free(&pk);
	return NULL;
}

// Return boolean for success/failure
return ucv_boolean_new(ret == 0);

// Return string for data
return ucv_string_new_length((const char *)output, 32);
```

---

### Memory Management

```c
// ALWAYS free resources on ALL paths
mbedtls_md_context_t md_ctx;
mbedtls_md_init(&md_ctx);

if (setup_fails) {
	mbedtls_md_free(&md_ctx);  // ✅ Cleanup on error
	return NULL;
}

// ... use md_ctx ...

mbedtls_md_free(&md_ctx);  // ✅ Cleanup on success
return result;
```

---

### Type Checking

```c
// ALWAYS validate input types
uc_value_t *v_key = uc_fn_arg(0);
uc_value_t *v_msg = uc_fn_arg(1);

if (ucv_type(v_key) != UC_STRING || ucv_type(v_msg) != UC_STRING) {
	return NULL;  // Fail gracefully
}
```

---

### Memory Hygiene

All stack or heap buffers containing sensitive cryptographic material (keys, nonces, intermediate hashes) MUST be zeroized immediately after use and before function return.

**Requirements:**
- Use `mbedtls_platform_zeroize()` for MbedTLS backends.
- Use `ForceZero()` or `memset_s()` equivalents for other backends.

---

### Documentation

```c
/**
 * Computes HMAC-SHA256 of a message.
 * 
 * @param key (string) - Secret key (binary)
 * @param message (string) - Message to authenticate (binary)
 * @return (string) - 32-byte HMAC digest, or NULL on error
 */
static uc_value_t *uc_mbedtls_hmac_sha256(uc_vm_t *vm, size_t nargs) {
	// Implementation
}
```

## ucode Syntax Limitations and Gotchas

This section lists syntax features that are either unsupported or behave unexpectedly in the target ucode environment.

### 1. Avoid Optional Chaining (`?.`)
**Status: DANGEROUS**
While the parser may accept it, the behavior is inconsistent. When used on a `null` object, it returns a value with an "empty" type that causes crashes (e.g., "left-hand side is not a function") when used in subsequent expressions.

**❌ INCORRECT:**
```javascript
let val = io?.getenv("PATH");
```

**✅ CORRECT:**
```javascript
let val = (io && io.getenv) ? io.getenv("PATH") : null;
```

### 2. No Destructuring (`let { a } = obj`)
**Status: NOT SUPPORTED**
ucode does not support object or array destructuring. Using this will result in a compile-time syntax error.

**❌ INCORRECT:**
```javascript
let { issuer_url, client_id } = config;
```

**✅ CORRECT:**
```javascript
let issuer_url = config.issuer_url;
let client_id = config.client_id;
```

### 3. Arrow Functions
**Status: PREFERRED**
Arrow functions are the preferred way to define functions and passthroughs. They should be used for both one-liners and multi-line logic.

**Exception:** Avoid using arrow functions when the function needs to return an **object literal** directly. This prevents parser ambiguity where the interpreter might confuse the object braces `{}` with a code block. Use traditional `function` for these cases.

**❌ INCORRECT (Ambiguous):**
```javascript
let get_data = () => { a: 1, b: 2 }; 
```

**✅ CORRECT (Explicit):**
```javascript
let get_data = function() {
    return { a: 1, b: 2 };
};
```

### 4. Shorthand Properties (`{ a }`)
**Status: SUPPORTED**
Shorthand property names are safe to use when building objects from existing local variables.

**✅ CORRECT:**
```javascript
let a = 1;
let obj = { a, b: 2 };
```

### 5. Handling `NaN`
**Status: Standard IEEE 754**
`NaN == NaN` is always `false`. When using `int()` or `double()` for conversion, check the resulting type to detect failure.

**✅ CORRECT:**
```javascript
let clock_tolerance = int(val);
if (type(clock_tolerance) != "int") {
    die("Invalid integer");
}
```

### 6. URL Encoding
**Status: MANDATORY FLAGS**
When using `lucihttp.urlencode()`, you MUST pass `1` as the second argument if the string contains characters like `/` or `:` (e.g., URLs). Failing to do so MUST be avoided as it results in unencoded characters which can break OIDC redirects.

**✅ CORRECT:**
```javascript
let enc = lucihttp.urlencode(url, 1);
```

**❌ INCORRECT:**
```javascript
let enc = lucihttp.urlencode(url);
```

---

## 8. Module Organization

### File Structure

```
luci-sso/
├── files/usr/share/ucode/luci_sso/
│   ├── crypto.uc      # High-level crypto API (wraps native)
│   ├── oidc.uc        # OIDC protocol (exchange, verification)
│   ├── discovery.uc   # OIDC metadata fetching and caching
│   ├── handshake.uc   # OIDC state machine and session orchestration
│   ├── session.uc     # Session management (JWS tokens)
│   ├── encoding.uc    # Pure data encoding and string logic
│   ├── jwk.uc         # JSON Web Key management
│   ├── config.uc      # UCI configuration loader
│   ├── web.uc         # CGI and HTTP request/response logic
│   ├── secure_http.uc # HTTPS client logic
│   ├── ubus.uc        # UBUS session integration
│   └── io.uc          # I/O abstraction (create_io helper)
├── src/
│   ├── native_mbedtls.c   # mbedtls backend
│   └── native_wolfssl.c   # wolfssl backend
├── test/
│   ├── unit/          # Unit tests for individual modules
│   │   ├── tier0_fixtures.uc # Minimal crypto/encoding fixtures
│   │   ├── tier1_fixtures.uc # OIDC/JWT logic fixtures
│   │   └── tier2_fixtures.uc # Complex handshake/session fixtures
│   ├── integration/   # Integration tests for router and UBUS
│   ├── e2e/           # Playwright browser tests
│   ├── mock.uc        # Mock I/O provider
│   └── runner.uc      # Test harness
└── ARCHITECTURE.md    # System architecture and security model
```

---

### Module Naming

- **Package:** `luci-sso` (hyphenated, OpenWrt convention)
- **Namespace:** `luci_sso.*` (underscored, ucode module system)
- **Files:** `snake_case.uc` (underscored, OpenWrt convention)

---

### Exports

**Export only public API:**

```javascript
// crypto.uc

// Private helpers (not exported)
function b64url_to_b64(str) {
	// ...
}

function constant_time_eq(a, b) {
	// ...
}

// Public API (exported)
export function verify_jwt(token, pubkey, options) {
	// ...
};

export function sign_jws(payload, secret) {
	// ...
};

export function pkce_pair(len) {
	// ...
};
```

---

## 9. Security Guidelines

### 1. Constant-Time Operations

Logic MUST use constant-time comparison for all secrets and signatures to prevent timing oracles.

### 2. Cryptographic Randomness

All random values MUST be sourced from a CSPRNG (e.g. `crypto.random`). Predictable sources like `time()` MUST NOT be used for security parameters.

### 3. Input Validation

The system MUST validate all external inputs. Contract violations MUST trigger `die()`, while runtime data errors MUST return a Result Object.

### 4. Fail-Safe Execution Order (Consumption First)

State handles and access tokens MUST be registered or consumed BEFORE performing expensive verification operations.

**Rationale:** Prevents brute-force signature or padding attacks by ensuring an attacker only gets one attempt per token.

---

### 6. No Secrets in Logs

**NEVER log secrets:**

```javascript
// ❌ INCORRECT
log("Secret key: " + secret);
log("ID token: " + id_token);

// ✅ CORRECT
log("Using secret key from " + SECRET_KEY_PATH);
log("ID token present: " + (id_token ? "yes" : "no"));
```

---

### 6. Algorithm Whitelisting

The system MUST only support `S256` for PKCE. The `plain` method MUST NOT be implemented or accepted.

---

## 10. Documentation Standards

### README.md

**Target audience:** Users (operators installing on routers)

**Must include:**
- What the project does
- How to install (opkg commands)
- How to configure (UCI examples)
- How to test it works

---

### API.md

**Target audience:** Developers (extending/integrating)

**Must include:**
- All exported functions
- Parameter types and meanings
- Return value formats
- Error codes
- Usage examples

---

### SECURITY.md

**Target audience:** Security auditors

**Must include:**
- Threat model
- Cryptographic primitives used
- Known limitations
- Security testing methodology
- Reporting vulnerabilities

---

### Inline Documentation

**Every exported function needs JSDoc:**

```javascript
/**
 * Verifies a JWT signature and validates claims.
 * 
 * Supports RS256 (RSA-SHA256) and ES256 (ECDSA-P256-SHA256).
 * 
 * @param {string} token - JWT string (header.payload.signature)
 * @param {string} pubkey - PEM-encoded public key
 * @param {object} options - Validation options
 * @param {string} options.alg - Required algorithm ("RS256" or "ES256")
 * @param {string} [options.iss] - Expected issuer (validates iss claim)
 * @param {string} [options.aud] - Expected audience (validates aud claim)
 * @param {number} [options.skew=300] - Clock skew tolerance (seconds)
 * 
 * @returns {object} - Decoded payload on success
 * @throws {string} - Error code on failure
 * 
 * @example
 * let payload = verify_jwt(token, pem_key, {
 *     alg: "RS256",
 *     iss: "https://accounts.google.com",
 *     aud: "my-client-id"
 * });
 */
export function verify_jwt(token, pubkey, options) {
	// ...
};
```

---

## 11. Commit Messages

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat` - New feature
- `fix` - Bug fix
- `refactor` - Code change (no behavior change)
- `test` - Adding/updating tests
- `docs` - Documentation only
- `style` - Formatting, naming (no code logic change)
- `perf` - Performance improvement
- `chore` - Build, CI, tooling

### Examples

```
feat(crypto): Add HMAC-SHA256 implementation

- Implement uc_mbedtls_hmac_sha256 in C
- Add sign_jws/verify_jws wrappers in ucode
- Add tests for JWS creation and verification

Closes #42
```

```
fix(oidc): Handle missing kid in JWT header

Previously, find_jwk() would return error if JWT lacked kid claim.
Now defaults to first key in JWKS (common for single-key IdPs).

Fixes #56
```

```
refactor(crypto): Rename jwk_es256_to_pem → jwk_ec_p256_to_pem

ES256 is an algorithm, P-256 is a curve. Function converts
EC keys (key type) not ES256 signatures (algorithm).

More accurate naming for future P-384 support.
```

---

## 12. Code Review Checklist

Before submitting PR, verify:

- [ ] All functions have tests
- [ ] All tests pass (`make test`)
- [ ] No secrets in code/logs
- [ ] Error handling follows guide (exceptions vs result objects)
- [ ] I/O uses dependency injection
- [ ] C code is minimal (only crypto primitives)
- [ ] Function names follow conventions (snake_case, trailing `;` on exports)
- [ ] Commit messages follow format
- [ ] Documentation updated (if API changed)
- [ ] No TODOs without issue number

---

## 13. Development Workflow

### Orchestration
The primary entry point for development is `devenv/Makefile`, which delegates complex logic to `devenv/scripts/test.sh`.
*   **`make compile`**: Triggers the SDK container to build native C components.
*   **`make up` / `make e2e-up`**: Lifts the local or E2E OIDC stack.
*   **`make unit-test` / `make e2e-test`**: Executes tests with support for `MODULES="..."` and `FILTER="..."`.
*   **`make watch-tests`**: Polyglot watcher that runs unit or E2E tests automatically on change.

### Source of Truth
Never hardcode environment-specific values (versions, domains) in Dockerfiles or Javascript tests. Always derive them from the `devenv/Makefile` variables, which are passed through as `ARG` or `ENV` via Docker Compose.

### Incremental C Builds
Native C compilation is guarded by a sentinel file in `bin/lib/.built`. If you modify `src/` files, the sentinel is invalidated, and the next `make compile` will trigger a rebuild.

---

## Questions and Improvements

### When You're Unsure

**Can't remember the formatting rule?**
→ Look at existing code in `files/usr/share/ucode/luci_sso/`

**Not sure if this should throw or return `{ error }`?**
→ Check the "Error Handling" decision tree

**Tests pass but code looks different from examples?**
→ Follow existing code style, update guide if needed

### Improving This Guide

If you find inconsistencies or have suggestions:

1. Open an issue or PR
2. Propose the change with rationale
3. Update affected code to match new rule
4. Update this guide

**When in doubt, favor:**
- Simplicity over cleverness
- Explicitness over brevity
- Security over performance

---

## Summary of Key Rules

| Area | Rule | Enforcement |
|------|------|-------------|
| **Error Handling** | Exceptions for most errors, result objects for fine-grained control | Code review |
| **I/O Abstraction** | Always inject `io` object for testability | Code review |
| **Virtual Identity** | Use OIDC role name as session label, no local passwords | Security review |
| **C Code** | Crypto primitives only, everything else in ucode | Architecture review |
| **PKCE** | S256 only, no `plain` method support | Security review |
| **RBAC Merging** | Aggregate role permissions using logical OR with deduplication | Logic review |
| **Indentation** | Tabs (OpenWrt standard) | Consistency review |
| **Naming** | snake_case for variables/functions | Style review |
| **Exports** | Trailing semicolon on `export` statements | Syntax requirement |
| **Testing** | Every function, every error path, security attacks | Test coverage review |

---

**Remember:** This guide exists to help you make consistent decisions, not to slow you down. When rules conflict with common sense, use judgment and document the decision.

---

**End of Style Guide**
