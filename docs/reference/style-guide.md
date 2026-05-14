# LuCI SSO Style Guide

This document is the technical reference for coding standards in the luci-sso project. For the reasoning behind these standards, see [Design Philosophy](../explanation/design-philosophy.md).

Code examples use tabs for indentation (OpenWrt standard), `snake_case` naming, and trailing semicolons on exported functions. For real-world implementations, see `files/usr/share/ucode/luci_sso/` (production) and `test/tier*/` (tests).

---

## Table of Contents

1. [Terminology](#terminology)
2. [Error Handling](#error-handling)
3. [Testing Standards](#testing-standards)
4. [ucode Style](#ucode-style)
5. [C Code Style](#c-code-style)
6. [Module Organization](#module-organization)
7. [Security Guidelines](#security-guidelines)
8. [Documentation Standards](#documentation-standards)
9. [Commit Messages](#commit-messages)
10. [Code Review Checklist](#code-review-checklist)
11. [Technical Debt & Known Exceptions](#technical-debt--known-exceptions)

---

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document and all other project documentation are to be interpreted as described in [RFC 2119](https://tools.ietf.org/html/rfc2119).

---

## Error Handling

### Contract Bugs vs. Runtime Realities

We distinguish between errors caused by the programmer (Contract Bugs) and errors caused by the environment or user (Runtime Realities).

#### 1. Contract Bugs (Programming Errors)
**Action: Use `die()`**
If a function is called with the wrong types or in an invalid state, this is a bug in the calling code. The system should "fail fast" to prevent undefined behavior.

```javascript
export function jws_sign(payload, secret) {
	if (type(payload) != "object") die("CONTRACT_VIOLATION: payload must be an object");
	if (type(secret) != "string") die("CONTRACT_VIOLATION: secret must be a string");
	// ...
};
```

#### 2. Runtime Realities (Expected Failures)
**Action: Use Result Objects or Exceptions**
If an operation fails due to external factors (expired token, network down, invalid signature), this is a valid state that the application might want to handle.

- **Exceptions:** Use for "stop the world" failures where the caller likely can't recover easily (e.g., malformed discovery response).
- **Result Objects:** Use for all runtime failures and common business logic branches (e.g., token expired vs. invalid signature). These MUST be created using the `luci_sso.result` module.

```javascript
import * as Result from 'luci_sso.result';

// Result Object Pattern (MANDATORY)
export function verify_session(io, token) {
	// ... logic ...
	if (expired) return Result.err("EXPIRED");
	if (bad_sig) return Result.err("INVALID_SIGNATURE");

	return Result.ok(payload);
}
```

### Exception vs. Result Object Decision Tree

```
Is the failure a programming error (wrong types, null pointer, invalid internal state)?
├─ YES → Use die() (Fail Fast - CONTRACT_VIOLATION)
└─ NO  → Is it a runtime failure (Expired token, network error, config error)?
   └─ ALWAYS → Return Result.err("CODE", context_object)
```

**Rationale:** In a CGI environment, `die()` causes a process crash which results in a generic 500 error. To provide a better user experience and robust error reporting, all runtime failures MUST return a `Result` object.

### Context Object Pattern

When returning an error, developers SHOULD use a "context object" for the `details` parameter if more than one piece of information is needed.

**Standard Fields:**
- `http_status`: The recommended HTTP status code for the web layer.
- `details`: A developer-friendly message or raw error from a sub-operation.

**✅ CORRECT:**
```javascript
return Result.err("DISCOVERY_FAILED", { 
    http_status: 502, 
    details: "Connection timed out" 
});
```

---

### Error Code Format

**Structure:** `CATEGORY_SPECIFIC_REASON` (MUST be SCREAMING_SNAKE_CASE)

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
let result = jwt_verify(token, key, opts);
// Forgot to check result.error
use(result.payload);  // Undefined if error occurred
```

**✅ CORRECT:**

```javascript
// With exceptions (automatic propagation)
let payload = jwt_verify(token, key, opts);
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

### Test Requirements

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

**Example for `jwt_verify()`:**

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

## C Code Style

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

### Memory Management & Safety

**1. ALWAYS free resources on ALL paths**
```c
mbedtls_md_context_t md_ctx;
mbedtls_md_init(&md_ctx);

if (setup_fails) {
	mbedtls_md_free(&md_ctx);  // ✅ Cleanup on error
	return NULL;
}
mbedtls_md_free(&md_ctx);  // ✅ Cleanup on success
```

**2. Explicit Length Validation (MANDATORY)**
C functions handling buffers passed from ucode MUST explicitly validate the length of those buffers against expected sizes BEFORE performing any memory operations (e.g., `memcpy`).

**✅ CORRECT:**
```c
if (key_len != 32) return -1;
memcpy(local, key, 32);
```

**❌ INCORRECT:**
```c
memcpy(local, key, 32); // Vulnerable if key_len < 32
```

---

### Memory Hygiene


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

### 7. Protocol Enforcement
**Status: MANDATORY CENTRALIZATION**
To ensure OIDC compliance and prevent case-manipulation bypasses, all HTTPS scheme checks MUST utilize the centralized `encoding.is_https()` utility. Local `substr()` or case-sensitive `===` checks are strictly FORBIDDEN.

**✅ CORRECT:**
```javascript
if (!encoding.is_https(url)) return Result.err("INSECURE");
```

**❌ INCORRECT:**
```javascript
if (substr(url, 0, 8) !== "https://") ...
```

---

## Module Organization

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
│   ├── result.uc      # Standard Result object pattern for error handling
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
│   ├── tier0/         # Native crypto compliance (MbedTLS/WolfSSL)
│   ├── tier1/         # Encoding/crypto logic tests
│   ├── tier2/         # Integration (handshake, session, config, ubus)
│   ├── tier3/         # Router / IO tests
│   ├── tier4/         # Mock system tests
│   ├── e2e/           # Playwright browser tests
│   ├── testing/       # Test framework
│   ├── lib/           # Test helpers
│   ├── mock.uc        # Mock I/O provider
│   └── runner.uc      # Test harness
└── docs/              # Documentation (Diátaxis framework)
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

// Public API (exported)
export function constant_time_eq(a, b) {
	// ...
}

export function jwt_verify(token, pubkey, options) {
	// ...
};

export function jws_sign(payload, secret) {
	// ...
};

export function pkce_pair(len) {
	// ...
};
```

---

## Security Guidelines

### 1. Constant-Time Operations

Logic MUST use constant-time comparison for all secrets and signatures to prevent timing oracles.

### 2. Cryptographic Randomness

All random values MUST be sourced from a CSPRNG (e.g. `crypto.random`). Predictable sources like `time()` MUST NOT be used for security parameters.

### 3. Input Validation

The system MUST validate all external inputs. Contract violations MUST trigger `die()`, while runtime data errors MUST return a Result Object.

### 4. Fail-Safe Execution Order (Consumption First)

State handles (handshake state) MUST be consumed BEFORE performing expensive verification operations. OIDC Access Tokens MUST be registered in the local session registry AFTER successful cryptographic verification of the ID Token.

See [Security Model](../explanation/security-model.md) and [Threat Model](../explanation/threat-model.md) for the reasoning behind this ordering.

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

### 7. Algorithm Whitelisting

The system MUST only support `S256` for PKCE. The `plain` method MUST NOT be implemented or accepted.

---

### 8. No Shell Execution (system() / popen())

Logic MUST NOT use `system()` or `popen()` for any operation.

- **Delays:** Use `io.sleep()` (which uses `uloop.timer()`) instead of `system("sleep X")`.
- **System Calls:** Use ucode built-ins or native C bindings for all system operations.

---

## Documentation Standards

### Philosophy
Documentation is code. It MUST be accurate, persona-aware (Diataxis), and accessible.

### 1. Diataxis Quadrants
All documentation must reside in the `docs/` directory and follow the Diataxis framework:

- `tutorials/`: Learning-oriented (Step-by-step success).
- `how-to/`: Goal-oriented (Task completion).
- `reference/`: Information-oriented (Technical machinery).
- `explanation/`: Understanding-oriented (The "Why").

### 2. Accessibility Mandates (WCAG 2.1 AA)
We prioritize accessibility for blind users, those with cognitive disabilities, and AI Agents.

*   **Alt-Text Mandate:** Every image MUST have a descriptive `alt` attribute. 
    *   *Bad:* `![Screenshot](image.png)`
    *   *Good:* `![LuCI interface showing the 'General Settings' tab with the 'OIDC Provider' dropdown set to 'Google'.](image.png)`
*   **Logical Hierarchy:** Heading levels (`#`, `##`, `###`) MUST be nested logically. Never skip a level (e.g., `#` followed by `###`).
*   **Diagram Fallbacks:** Every Mermaid diagram MUST be preceded or followed by a textual summary or a table describing the flow for screen readers and AI Agents.
*   **Plain Language:** Avoid jargon where possible. Use active voice and short sentences.

### 3. Machine-Readable Reference
Reference documentation must be high-density and unambiguous. Avoid narrative prose in reference quadrants — describe, don't explain.

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
- Add jws_sign/jws_verify wrappers in ucode
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
- [ ] All tests pass (`make -C devenv test`)
- [ ] No secrets in code/logs
- [ ] Error handling follows guide (exceptions vs result objects)
- [ ] I/O uses dependency injection
- [ ] C code is minimal (only crypto primitives)
- [ ] Function names follow conventions (snake_case, trailing `;` on exports)
- [ ] Commit messages follow format
- [ ] Documentation updated (if API changed)
- [ ] No TODOs without issue number

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

---

## Technical Debt & Known Exceptions

While the project strives for consistency, certain legacy patterns or "convenience" trade-offs exist that deviate from the primary rules. These are documented here to prevent confusion.

### `encoding.safe_json` — "Dual-Mode" Result Unwrapping
The `safe_json(data)` function in `encoding.uc` violates the principle of **Explicitness over Brevity**. It performs three distinct operations:
1.  **I/O unwrapping:** Calls `.read()` if given a stream object.
2.  **Result unwrapping:** Transparently extracts `.data` if given a `Result` object (passing through errors).
3.  **JSON decoding:** Safely decodes the resulting string into a `Result`.

**Why it exists:** To allow clean chaining like `safe_json(b64url_decode(jwt_part))`.
**Debt:** The dual-mode behavior is opaque. Future refactors should consider splitting this into explicit `read_json()` and `parse_json()` functions.

### API Return Type Consistency
The project is in the process of migrating all cryptographic and encoding functions to return `Result` objects.
- **Status:** `normalize_url`, `normalize_sub`, `sha256`, and `sha256_hex` have been migrated.
- **Debt:** Some low-level encoding functions (e.g., `b64url_encode`) still return raw strings. These should be migrated during the next major version update.

