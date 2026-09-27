# LuCI SSO Style Guide

This document is the technical reference for coding standards in the luci-sso project. For the reasoning behind these standards, see [About the Design Philosophy](../explanation/design-philosophy.md).

Code examples use tabs for indentation (OpenWrt standard), `snake_case` naming, and trailing semicolons on exported functions. For real-world implementations, see `src/luci_sso/` (production) and `test/` (tests).

---

## Table of Contents

1. [Terminology](#terminology)
2. [Design Rules](#design-rules)
3. [Error Handling](#error-handling)
4. [Testing Standards](#testing-standards)
5. [ucode Style](#ucode-style)
6. [C Code Style](#c-code-style)
7. [Module Organization](#module-organization)
8. [Security Guidelines](#security-guidelines)
9. [Documentation Standards](#documentation-standards)
10. [Commit Messages](#commit-messages)
11. [Summary of Key Rules](#summary-of-key-rules)
12. [Technical Debt & Known Exceptions](#technical-debt-known-exceptions)

For the steps to take before opening a pull request, see [How to Work on luci-sso Day to Day](../how-to/developer/development-workflow.md#prepare-a-pull-request).

---

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document and all other project documentation are to be interpreted as described in [RFC 2119](https://tools.ietf.org/html/rfc2119).

---

## Design Rules

The reasoning behind these rules is in [About the Design Philosophy](../explanation/design-philosophy.md).

### I/O Through `deps`

All I/O and nondeterminism MUST reach a module through the `deps` object: `fs`, `http`, `ubus`, `uci`, `clock`, `native` and `log`. Only `deps.uc` (which builds the production object) and `components/*` (which implement `http` and `clock`) MAY import `fs`, `uci`, `ubus`, `uclient`, `uloop`, `log` or `luci_sso.native`, or call `time()`.

- A function that needs I/O MUST take `deps` as its first argument and pass it on. The `crypto/*` wrappers take only `native`.
- Every `deps` object MUST include `log`.
- Deterministic, pure operations (string handling, Base64URL, JSON, URL normalization) MUST NOT go through `deps`.

```javascript
// Production (the CGI script): real modules, wired by deps.uc
let deps = create();                          // from luci_sso.deps
discover(deps, "https://idp.example.com");    // luci_sso.discovery

// Test: the same call with a deps object built from proxies
with_context({ fs: { data: {} }, http_client: { data: { … } }, clock: { data: { now: 1516239022 } } },
	(deps) => discover(deps, "https://idp.example.com"));
```

### Crypto Backend Independence

Code MUST NOT import a crypto backend directly. It MUST use the `native` module passed in through `deps` (or as the `native` argument of a `crypto/*` wrapper). New native operations MUST be added to all three backends (see [C Code Style](#c-code-style)).

**❌ INCORRECT:**
```javascript
import * as mbedtls from 'native_mbedtls';
```

**✅ CORRECT:**
```javascript
let res = crypto.hash_sha256(deps.native, data);
```

### Security Invariants in Code

Security invariants MUST be constants in code. They MUST NOT be UCI options or function parameters. Examples: the ID Token algorithm allow-list (`ALLOWED_ALGS` in `oidc.uc`), the PKCE method (`S256`), and the input size limits.

```javascript
// oidc.uc
const ALLOWED_ALGS = ["RS256", "ES256"];
```

### Minimal C

C code MUST be limited to cryptographic primitives. Everything else MUST be written in ucode. See [Minimize C Code](#minimize-c-code).

---

## Error Handling

### Contract Bugs vs. Runtime Realities

We distinguish between errors caused by the programmer (Contract Bugs) and errors caused by the environment or user (Runtime Realities).

#### 1. Contract Bugs (Programming Errors)
**Action: Use `die()`**
If a function is called with the wrong types or in an invalid state, this is a bug in the calling code. The system should "fail fast" to prevent undefined behavior.

```javascript
export function verify(native, token, pubkey, options) {
	if (type(token) != "string") die("CONTRACT_VIOLATION: jwt.verify expects string token");
	if (type(pubkey) != "string") die("CONTRACT_VIOLATION: jwt.verify expects string pubkey");
	// ...
};
```

#### 2. Runtime Realities (Expected Failures)
**Action: Return a Result Object**
If an operation fails due to external factors (expired token, network down, invalid signature, malformed IdP response), this is a valid state that the application must handle. Runtime failures MUST return a Result Object created with the `luci_sso.result` module (`Result.ok(data)`, `Result.err(code, details)`). They MUST NOT throw.

```javascript
import * as Result from 'luci_sso.result';

// deps: { http, log } — from luci_sso.oidc.fetch_userinfo, shortened
export function fetch_userinfo(deps, endpoint, access_token) {
	if (!encoding.is_https(endpoint)) return Result.err(INSECURE_USERINFO_ENDPOINT);

	let res_http = deps.http.get(endpoint, {
		headers: { "Authorization": `Bearer ${access_token}` }
	});
	if (!res_http.ok) return Result.err(USERINFO_NETWORK_ERROR);
	if (res_http.data.status != 200)
		return Result.err(USERINFO_FETCH_FAILED, { http_status: res_http.data.status });

	return encoding.safe_json(res_http.data.body);
};
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
return Result.err(ID_TOKEN_VERIFICATION_FAILED, {
	details: verify_res.error,
	http_status: 401
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

Every returned Result MUST be checked (`if (!res.ok)`) before its `data` is used.

**❌ INCORRECT:**

```javascript
let res = discovery.fetch_jwks(deps, jwks_uri);
// Forgot to check res.ok
let keys = res.data;  // null if the fetch failed
```

**✅ CORRECT:**

```javascript
let res = discovery.fetch_jwks(deps, jwks_uri);
if (!res.ok) {
	return Result.err(JWKS_FETCH_FAILED, { http_status: 500 });
}
let keys = res.data;
```

---

## Testing Standards

### Test Requirements

1. **Mandatory Coverage:** Every exported function MUST be tested, in the bucket the [placement rule](testing-architecture.md#placement-rule) assigns to its module.
2. **Failure Verification:** Every error path MUST be verified by a corresponding test case.
3. **Attack Simulation:** Security-critical code MUST have specialized attack tests (tampering, injection, replay, algorithm confusion, bypass attempts).
4. **Offline Purity:** All tests MUST be runnable offline without external network dependencies.
5. **Native Isolation:** Tests in `test/native/` MUST import only `luci_sso.native` and pure helpers. Tests of the `crypto/*` wrappers MUST fake `native`.
6. **Proxies Over Stubs:** The system boundary MUST be faked with `mock.inject_all`, `mock.inject` or `with_context`. A hand-written stub object MUST NOT be used where a proxy exists. Proxies SHOULD use `strict: true` and SHOULD prefer `data:` over `behavior:`.

### Test Structure

Tests use [utest](https://github.com/m00qek/utest): `describe` / `it` blocks, `assert.match` with matchers, and a `deps` object built from proxies. See [Testing Architecture](testing-architecture.md#mocking-the-proxy-dsl) for the proxy DSL and `with_context`.

```javascript
import { describe, it, assert, contains, truthy, falsy, spy } from 'utest';
import * as discovery from 'luci_sso.discovery';
import { with_context } from 'context';
import * as f from 'fixtures.oidc';

const ISSUER = "https://trusted.idp";

describe('discovery: discover — validation & security', () => {
	it('rejects an issuer mismatch', () => {
		let evil_doc = { ...f.MOCK_DISCOVERY, issuer: "https://evil.idp" };
		with_context({
			fs:          { data: {} },
			http_client: { data: { [`${ISSUER}/.well-known/openid-configuration`]: { status: 200, body: evil_doc } } },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			let res = discovery.discover(deps, ISSUER);
			assert.match(falsy(), res.ok);
			assert.match("DISCOVERY_ISSUER_MISMATCH", res.error);
		});
	});

	it('dies with CONTRACT_VIOLATION when keys is not an array', () => {
		assert.throws(() => discovery.find_jwk(null, 'key-1'), /CONTRACT_VIOLATION/);
	});
});
```

---

### Test Naming Convention

**Pattern:** `describe('<module>: <function>[ — <aspect>]', …)` containing `it('<expected behaviour>', …)`. The module name is its path under `luci_sso`, dotted (`crypto.jwt`, `session.handshake`).

**Examples:**

```javascript
describe('crypto.jwt: verify — claims', () => {
	it('returns TOKEN_EXPIRED for an expired token', () => { /* ... */ });
	it('rejects a token issued in the future', () => { /* ... */ });
});
describe('discovery: fetch_jwks — cache', () => { /* ... */ });
describe('web: parse_cookies', () => { /* ... */ });
```

---

### Test Coverage Requirements

**Minimum coverage per exported function:**
- ✅ 1 success case (happy path)
- ✅ 1 error case per error type or branch
- ✅ Edge cases (empty input, `null`, boundary values)
- ✅ Security cases where relevant (tampering, injection, replay, algorithm confusion, bypass attempts)

**Example for `crypto.jwt.verify()`:** a valid token succeeds; expired, not-yet-valid and future-issued tokens are rejected; a bad signature, a malformed token, a wrong or missing algorithm and a tampered payload are rejected; `alg: none` and HS256 algorithm confusion are rejected.

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
 * @param {object} deps - Injected dependencies; uses { fs, http, native, clock, log }
 * @param {string} issuer - IdP issuer URL
 * @param {object} [options] - Optional configuration
 * @returns {object} - Result Object {ok, data/error}
 */
export function discover(deps, issuer, options) {
	// ...
};

// TODO comments for planned work MUST name the issue that tracks it
// TODO(#123): Add support for P-384 curve
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

### Standards: Crypto Backends
The native bridge in `mod/` has three backends: `native_mbedtls.c` (mbedTLS 3.x), `native_wolfssl.c` (wolfSSL) and `native_openssl.c` (OpenSSL 3). Each implements the interface in `mod/native.h`; input checks shared by all of them live in `mod/native_api.c`. New operations MUST be added to all three. See [How to Add a New Crypto Backend](../how-to/developer/adding-crypto-backend.md).

**Requirements:**
- ✅ Initialize the library in `native_crypto_init()`, which `uc_module_init` calls; the functions are registered only when it succeeds.
- ✅ Check the return value of ALL library calls.
- ✅ Free keys and contexts on all return paths.
- ✅ mbedTLS: use the **PSA Crypto API** (`psa/crypto.h`) and check `psa_status_t`; use opaque handles (`psa_key_id_t`) where possible and destroy them (`psa_destroy_key`); use the `MBEDTLS_PRIVATE()` macro only if direct structure access is unavoidable.

---

### Minimize C Code

**Ask first:** "Can this be done in ucode?"
- If YES → Do it in ucode
- If NO (crypto/performance) → Write minimal C

---

### Function Naming

| Layer | File | Pattern | Example |
| :--- | :--- | :--- | :--- |
| ucode binding | `mod/native_ucode.c` | `uc_native_<operation>` | `uc_native_verify_rs256` |
| Input guards | `mod/native_api.c` | `native_api_<operation>` | `native_api_verify_rs256` |
| Backend interface | `mod/native.h`, `mod/native_<lib>.c` | `native_<operation>` | `native_verify_rs256` |

Every backend implements the same `native_<operation>` names, so no backend name appears in a function name.

---

### Error Handling in C

What a ucode binding in `mod/native_ucode.c` returns on failure depends on what it returns on success:

| Kind | Bindings | Success | Any failure |
| :--- | :--- | :--- | :--- |
| Value | `sha256`, `hmac_sha256`, `random`, `jwk_rsa_to_pem`, `jwk_ec_p256_to_pem` | the value (a string) | `null` |
| Predicate | `verify_rs256`, `verify_es256` | `true` | `false` |

- A value binding MUST return `null` on every failure, including wrong argument types, oversized input and backend errors.
- A predicate binding MUST return `true` only for a verified signature, and `false` for everything else: wrong argument types, oversized input, an unparsable key or a bad signature. It MUST NOT return `null`, and MUST NOT distinguish an error from an invalid signature. A check has exactly two outcomes, so no caller can treat "could not check" as anything other than a rejection.
- Callers MUST treat anything other than `true` from a predicate as a failure.

```c
// Value binding: null on any failure
if (ucv_type(arg) != UC_STRING) return NULL;
...
return ucv_string_new_length((const char *)output, NATIVE_SHA256_SIZE);

// Predicate binding: false on any failure, true only when verified
if (ucv_type(v_msg) != UC_STRING || ucv_type(v_sig) != UC_STRING || ucv_type(v_key) != UC_STRING)
	return ucv_boolean_new(false);
...
return ucv_boolean_new(native_api_verify_rs256(msg, msg_len, sig, sig_len, key, key_len));
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

### Input Type Validation

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
- Use `OPENSSL_cleanse()` for OpenSSL, and `ForceZero()` or an equivalent that cannot be optimized away for wolfSSL.

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
static uc_value_t *uc_native_hmac_sha256(uc_vm_t *vm, size_t nargs) {
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
let tol = config?.clock_tolerance;
```

**✅ CORRECT:**
```javascript
let tol = config ? config.clock_tolerance : null;
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
├── src/luci_sso/          # ucode modules, installed as luci_sso.*
│   ├── entry.uc           # CGI pipeline: request → config → router → response
│   ├── deps.uc            # Production dependency graph (fs, http, ubus, uci, clock, native, log)
│   ├── router.uc          # Endpoint dispatch, logout
│   ├── ratelimit.uc       # Per-client rate limits
│   ├── handshake.uc       # OIDC login orchestration
│   ├── oidc.uc            # Authorization URL, token exchange, ID-token checks, UserInfo
│   ├── discovery.uc       # Discovery document and JWKS fetching/caching
│   ├── config.uc          # UCI loading and role matching
│   ├── ubus.uc            # rpcd session creation and token replay registry
│   ├── web.uc             # CGI request parsing and response rendering
│   ├── encoding.uc        # Base64URL, JSON, URL normalisation
│   ├── result.uc          # Result object
│   ├── errors.uc          # Public error codes (documented in log-messages.md)
│   ├── crypto.uc          # Crypto façade over crypto/
│   ├── crypto/            # base, hash, jwk, jwt, pkce wrappers over native
│   ├── session.uc         # Façade over session/
│   ├── session/           # Handshake state files
│   └── components/        # http_client, clock
├── mod/                   # Native crypto module (C)
│   ├── native_ucode.c     # ucode binding
│   ├── native_api.c       # Input guards
│   ├── native.h           # Backend interface
│   └── native_<lib>.c     # mbedtls, wolfssl, openssl backends
├── files/                 # Installed as-is: CGI script, LuCI view, menu and controller, rpcd ACL, uci-defaults, luci-sso-repatch
├── openwrt/luci-sso/      # OpenWrt package Makefile
├── test/
│   ├── native/            # The compiled crypto module's contract
│   ├── unit/luci_sso/     # One module at a time (mirrors src/)
│   ├── integration/       # Orchestrators and wiring (handshake, router, logout, entry, bootstrap, LuCI logout)
│   ├── system/            # Checks against the container's real rpcd
│   ├── e2e/               # Playwright browser tests
│   ├── fixtures/          # Shared keys, tokens, discovery documents
│   ├── lib/               # Test helpers (signed JWTs)
│   ├── proxies/           # utest proxies for luci_sso components
│   ├── context.uc         # with_context(): full deps graph from proxies
│   └── fuzz_test.c        # libFuzzer harness
├── devenv/                # Docker services and scripts for tests and builds
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
// crypto/jwk.uc

// Private helpers (not exported)
function rsa_to_pem(native, jwk) {
	// ...
}

function ec_to_pem(native, jwk) {
	// ...
}

// Public API (exported)
export function to_pem(native, jwk) {
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

### 4. Fail-Safe Execution Order (Check, Then Claim)

State handles (handshake state) MUST be checked against the request (state parameter, expiry) and then claimed with a single atomic operation BEFORE performing expensive verification operations. A request that fails the check MUST NOT consume the handle. OIDC Access Tokens MUST be registered in the local session registry AFTER successful cryptographic verification of the ID Token.

See [Security Model](../explanation/security-model.md) and [Threat Model](../explanation/threat-model.md) for the reasoning behind this ordering.

---

### 5. No Secrets in Logs

**NEVER log secrets:**

```javascript
// ❌ INCORRECT
deps.log("info", `Client secret: ${config.client_secret}`);
deps.log("info", `ID token: ${id_token}`);

// ✅ CORRECT: claim names only, identifiers as a hashed prefix
deps.log("debug", `ID Token verified. Claims present: ${join(", ", claim_names)}`);
deps.log("info", `Session successfully created for user [sub_id: ${crypto.safe_id(deps.native, user_data.sub)}]`);
```

---

### 6. Algorithm Allow-Lists

The system MUST only support `S256` for PKCE. The `plain` method MUST NOT be implemented or accepted. ID Tokens MUST be verified with `RS256` or `ES256` only. Both lists are [security invariants in code](#security-invariants-in-code).

---

### 7. No Shell Execution (system() / popen())

Logic MUST NOT use `system()` or `popen()` for any operation.

- **Delays:** Use `deps.clock.sleep()` (which uses a `uloop` timer) instead of `system("sleep X")`.
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

Commits follow [Conventional Commits](https://www.conventionalcommits.org/).

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

- **Subject:** imperative mood, lowercase, no trailing period.
- **Scope:** the module or area changed (`oidc`, `crypto`, `ubus`, `router`, `docs` sub-areas such as `reference`).
- **Body:** what changed and why.
- **Footer:** issue references (`Closes #42`, `Fixes #56`).

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
feat(crypto): add HMAC-SHA256 implementation

- Implement native_hmac_sha256 in each backend
- Expose hmac_sha256 through the native module
- Add known-answer tests in test/native

Closes #42
```

```
fix(oidc): handle missing kid in JWT header

Previously, find_jwk() would return error if JWT lacked kid claim.
Now defaults to first key in JWKS (common for single-key IdPs).

Fixes #56
```

```
refactor(crypto): rename jwk_es256_to_pem to jwk_ec_p256_to_pem

ES256 is an algorithm, P-256 is a curve. Function converts
EC keys (key type) not ES256 signatures (algorithm).
```

---

## Summary of Key Rules

| Area | Rule | Enforcement |
|------|------|-------------|
| **Error Handling** | `die()` for contract bugs, `Result` objects for every runtime failure | Code review |
| **I/O Abstraction** | All I/O and nondeterminism goes through `deps` (`fs`, `http`, `ubus`, `uci`, `clock`, `native`, `log`) | Code review |
| **Virtual Identity** | Use OIDC role name as session label, no local passwords | Security review |
| **C Code** | Crypto primitives only, everything else in ucode | Architecture review |
| **PKCE** | S256 only, no `plain` method support | Security review |
| **RBAC Merging** | Aggregate role permissions using logical OR with deduplication | Logic review |
| **Indentation** | Tabs (OpenWrt standard) | Consistency review |
| **Naming** | snake_case for variables/functions | Style review |
| **Exports** | Trailing semicolon on `export` statements | Syntax requirement |
| **Testing** | Every function, every error path, security attacks | Test coverage review |
| **Error codes, limits, cookies** | Match the reference pages | `make lint` (CI) |

When a rule conflicts with common sense, use judgment and record the decision in the commit message or under [Technical Debt & Known Exceptions](#technical-debt-known-exceptions).

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

### Functions That Do Not Return a `Result`
Every fallible encoding and crypto function returns a `Result`. The exceptions return plain values by design:
- **Predicates** return booleans: `encoding.is_https`, `encoding.is_origin`, `crypto.constant_time_eq`.
- **`encoding.rebase_origin`** returns a string: `url` unchanged when it cannot be rebased.
- **`crypto.safe_id`** returns a string for log lines: a 16-character hex prefix, or `[INVALID]` / `[ERROR]`.
