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
2. [Architecture Principles](#architecture-principles)
3. [Error Handling](#error-handling)
4. [Testing Standards](#testing-standards)
5. [ucode Style](#ucode-style)
6. [C Code Style](#c-code-style)
7. [Module Organization](#module-organization)
8. [Security Guidelines](#security-guidelines)
9. [Documentation Standards](#documentation-standards)
10. [Commit Messages](#commit-messages)
11. [Code Review Checklist](#code-review-checklist)

---

## Philosophy

### Core Tenets

1. **Security First** - All authentication/authorization code must be paranoid
2. **Minimal Dependencies** - Keep the footprint small for embedded systems
3. **Testability** - All code must be unit-testable without a real IdP
4. **OpenWrt Native** - Follow OpenWrt/ucode conventions, not Node.js patterns
5. **Explicit Over Implicit** - Code should be obvious, not clever

### Design Goals

- ✅ Work on resource-constrained routers (64MB RAM, 16MB flash)
- ✅ Support major OIDC providers (Google, Microsoft, generic)
- ✅ Be auditable (security-critical code should be simple)
- ✅ Fail safely (reject invalid auth rather than allow)

---

## Architecture Principles

### 1. Dependency Injection for I/O

**ALWAYS** use dependency injection for I/O operations to enable testing.

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

**DO include (non-deterministic, external state):**

```javascript
let io = {
	time: function() { return time(); },           // ✅ Current timestamp
	random: function(n) { return crypto.random(n); },  // ✅ Unpredictable
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

---

### 3. Minimal C Code

**Crypto operations ONLY in C.** Everything else in ucode.

**C code should contain:**
- ✅ Cryptographic primitives (RSA/EC verification, HMAC, random)
- ✅ Performance-critical code (if profiling shows bottleneck)
- ❌ Business logic (OAuth2 flows, session management)
- ❌ String manipulation (JSON parsing, URL building)
- ❌ I/O operations (HTTP requests, file access)

**Rationale:**
- C code is harder to test, audit, and modify
- ucode is "good enough" for 99% of operations
- Smaller C surface = fewer security vulnerabilities

---

### 4. Backend Abstraction

**Crypto backends are swappable** (mbedtls, wolfssl).

All backend-specific code goes in:
- `src/native_mbedtls.c`
- `src/native_wolfssl.c`

Wrapper layer exposes uniform API:
- `files/usr/share/ucode/luci_sso/crypto.uc` imports `luci_sso.native`

**Never** import backend directly:

```javascript
// ❌ INCORRECT
import * as mbedtls from 'native_mbedtls';

// ✅ CORRECT
import * as native from 'luci_sso.native';
```

---

## Error Handling

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

## Testing Standards

### Gold Standard Tests

**All tests in `test/unit/` are REFERENCE IMPLEMENTATIONS.**

Tests are not just validation—they are:
- ✅ **Documentation** - Show how to use the API
- ✅ **Specification** - Define correct behavior
- ✅ **Safety net** - Prevent regressions

### Test Requirements

1. **Every exported function MUST have tests**
2. **Every error path MUST have a test**
3. **Security-critical code MUST have attack tests** (see `test/unit/security_test.uc`)
4. **Tests MUST be runnable offline** (no real network calls)

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

## ucode Style

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

```javascript
// ALWAYS use let (never var)
let x = 1;
let name = "value";

// Constants: UPPERCASE for true constants
const SECRET_KEY_PATH = "/etc/luci-sso/secret.key";
const SESSION_DURATION = 3600;

// Multi-word names: snake_case (OpenWrt convention)
let session_token = create_session();
let discovery_url = issuer + "/.well-known";

// NOT camelCase (that's JavaScript, not OpenWrt)
// ❌ let sessionToken = ...
// ❌ let discoveryUrl = ...
```

---

### String Formatting

```javascript
// Template literals for interpolation
let url = `${base_url}/path?param=${value}`;

// Quote style: Double quotes (OpenWrt convention)
let message = "Hello, world";

// Exception: Single quotes for nested strings
let json = '{"key": "value"}';
```

---

### Imports

```javascript
// Import order:
// 1. Standard library
// 2. External dependencies
// 3. Internal modules (luci_sso.*)

import * as fs from 'fs';
import * as uclient from 'uclient';

import * as crypto from 'luci_sso.crypto';
import * as session from 'luci_sso.session';
```

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

## C Code Style

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

---

## Module Organization

### File Structure

```
luci-sso/
├── files/usr/share/ucode/luci_sso/
│   ├── crypto.uc      # High-level crypto API (wraps native)
│   ├── oidc.uc        # OIDC discovery, JWK fetching
│   ├── session.uc     # Session management (JWS tokens)
│   ├── utils.uc       # Pure utilities (urlencode, etc.)
│   └── io.uc          # I/O abstraction (create_io helper)
├── src/
│   ├── native_mbedtls.c   # mbedtls backend
│   └── native_wolfssl.c   # wolfssl backend
├── test/
│   ├── unit/
│   │   ├── crypto_test.uc
│   │   ├── oidc_test.uc
│   │   ├── session_test.uc
│   │   └── security_test.uc
│   ├── integration/
│   │   └── google_oidc_test.uc  # Real IdP tests (optional)
│   ├── fixtures.uc         # Shared test data
│   ├── helpers.uc          # create_mock_io, etc.
│   └── runner.uc           # Test harness
└── docs/
    ├── API.md              # Public API documentation
    ├── SECURITY.md         # Security considerations
    └── STYLE_GUIDE.md      # This file
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

## Security Guidelines

### 1. Constant-Time Operations

**ALWAYS use constant-time comparison for secrets:**

```javascript
// ✅ CORRECT
function constant_time_eq(a, b) {
	if (length(a) != length(b)) return false;
	
	let result = 0;
	for (let i = 0; i < length(a); i++) {
		result |= ord(a, i) ^ ord(b, i);
	}
	return result == 0;
}

// ❌ INCORRECT (timing attack vulnerable)
if (signature == expected_signature) {
	// ...
}
```

---

### 2. Cryptographic Randomness

**ALWAYS use crypto RNG, never predictable sources:**

```javascript
// ✅ CORRECT
let state = crypto.b64url_encode(crypto.random(16));

// ❌ INCORRECT (predictable!)
let state = sprintf("%d", time());
```

---

### 3. Input Validation

**Validate ALL external inputs:**

```javascript
export function verify_jwt(token, pubkey, options) {
	// Validate types
	if (type(token) != "string")
		die("INVALID_ARGUMENT: token not string");
	if (type(options) != "object")
		die("INVALID_ARGUMENT: options not object");
	
	// Validate structure
	let parts = split(token, ".");
	if (length(parts) != 3)
		die("MALFORMED_JWT: expected 3 parts");
	
	// Validate algorithm
	if (!options.alg)
		die("MISSING_ALGORITHM");
	if (header.alg != options.alg)
		die("ALGORITHM_MISMATCH");
	
	// ...
};
```

---

### 4. Fail Securely

**On any doubt, REJECT:**

```javascript
// ✅ CORRECT
if (signature_valid && !expired && issuer_match) {
	return payload;
}
die("INVALID_TOKEN");  // Reject by default

// ❌ INCORRECT
if (!signature_valid || expired || !issuer_match) {
	die("INVALID_TOKEN");
}
return payload;  // Accept if no explicit rejection
```

---

### 5. No Secrets in Logs

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

**Only support S256 for PKCE:**

```javascript
// ✅ CORRECT (S256 only)
let params = {
	code_challenge: pkce.challenge,
	code_challenge_method: "S256"  // Hardcoded
};

// ❌ INCORRECT (allowing 'plain' is a security risk)
let params = {
	code_challenge: pkce.challenge,
	code_challenge_method: options.method || "plain"
};
```

**Rationale:** RFC 7636 recommends S256 as mandatory. The `plain` method offers no security against interception attacks.

---

## Documentation Standards

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

## Commit Messages

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

## Code Review Checklist

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

## 12. Development Workflow

### Orchestration
The primary entry point for development is `devenv/Makefile`. 
*   **`make compile`**: Triggers the SDK container to build native C components.
*   **`make up`**: Lifts the full OIDC stack.
*   **`make unit-test`**: Executes ucode tests inside the active LuCI container.

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
| **C Code** | Crypto primitives only, everything else in ucode | Architecture review |
| **PKCE** | S256 only, no `plain` method support | Security review |
| **Indentation** | Tabs (OpenWrt standard) | Consistency review |
| **Naming** | snake_case for variables/functions | Style review |
| **Exports** | Trailing semicolon on `export` statements | Syntax requirement |
| **Testing** | Every function, every error path, security attacks | Test coverage review |

---

**Remember:** This guide exists to help you make consistent decisions, not to slow you down. When rules conflict with common sense, use judgment and document the decision.

---

**End of Style Guide**
