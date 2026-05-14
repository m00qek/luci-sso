# Internal API Reference

This document describes the exported public API of each `luci-sso` module. It is intended for developers extending the system, writing tests, or implementing a new crypto backend.

For the rationale behind the architectural boundaries described here, see [About the Architecture](../explanation/architecture.md).

---

## The Result type

All fallible functions return a **Result object** rather than throwing. The shape is:

```javascript
{
    ok:      bool,    // true = success, false = failure
    data:    any,     // present when ok == true
    error:   string,  // error code from luci_sso.errors; present when ok == false
    details: any      // optional diagnostic context; present when ok == false
}
```

Check `result.ok` before using `result.data`. Never access `.data` on a failed result.

---

## `luci_sso.result`

Constructors for the Result type.

### `ok(data)` → `Result`

Creates a successful result.

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `data` | any | The success value. |

### `err(error, details?)` → `Result`

Creates a failed result.

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `error` | string | An error code constant from `luci_sso.errors`. |
| `details` | any | Optional. Additional context (string, object, or `{http_status: int}`). |

### `is(obj)` → `bool`

Returns `true` if `obj` is a Result instance. Use this before duck-typing `.ok`.

---

## `luci_sso.handshake`

The OIDC state machine. This is the top-level entry point for both legs of the authorization code flow.

### `initiate(io, config)` → `Result<{url, token}>`

Starts the login flow. Generates PKCE, state, and nonce; writes a handshake file; and returns the IdP redirect URL.

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `io` | io provider | The I/O provider from `luci_sso.io`. |
| `config` | object | Loaded UCI config from `luci_sso.config.load()`. |

On success, `result.data` contains:

| Field | Type | Description |
| :--- | :--- | :--- |
| `url` | string | Full redirect URL to the IdP's `authorization_endpoint`. |
| `token` | string | State token. Set this as the value of the `__Host-luci_sso_state` cookie. |

### `authenticate(io, config, request, policy?)` → `Result<{sid, email}>`

Processes the IdP callback. Verifies state and nonce, exchanges the code for tokens, validates the ID Token, maps claims to a role, and injects a UBUS session.

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `io` | io provider | The I/O provider. |
| `config` | object | Loaded UCI config. |
| `request` | object | Parsed request from `luci_sso.web.request()`. Contains `params` and `cookies`. |
| `policy` | object | Optional. Security policy overrides. Defaults to `{allowed_algs: ["RS256", "ES256"]}`. |

On success, `result.data` contains:

| Field | Type | Description |
| :--- | :--- | :--- |
| `sid` | string | UBUS session ID. Set this as the `sysauth_https` and `sysauth` cookie values. |
| `email` | string | Authenticated user's email address. |

---

## `luci_sso.crypto`

High-level cryptographic operations. Wraps the native C bridge — all calls go through the loaded `luci_sso.native` backend.

### `constant_time_eq(a, b)` → `bool`

Compares two strings in constant time. Use this for all security-sensitive comparisons (nonces, states, tokens).

### `jws_sign(payload, secret)` → `string`

Creates a JWS compact serialization (HS256) of `payload`. Returns the signed token string.

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `payload` | object | JSON-serializable object to sign. |
| `secret` | string | HMAC key (raw bytes). |

### `jws_verify(token, secret)` → `Result<object>`

Verifies a JWS token and returns the decoded payload.

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `token` | string | JWS compact serialization. |
| `secret` | string | HMAC key (raw bytes). |

### `jwt_verify(token, pubkey, options)` → `Result<object>`

Verifies a JWT using an asymmetric public key and returns the decoded claims object.

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `token` | string | JWT compact serialization. |
| `pubkey` | string | PEM-encoded public key (RSA or EC). |
| `options` | object | Options object. `options.alg` constrains the accepted algorithm. |

### `random(len)` → `string`

Returns `len` cryptographically random bytes (raw binary string) from the CSPRNG.

### `hash_sha256(str)` → `string`

Returns the SHA-256 digest of `str` as 32 raw bytes.

### `hash_sha256_hex(str)` → `string`

Returns the SHA-256 digest of `str` as a 64-character lowercase hex string.

### `pkce_pair(len)` → `{verifier, challenge}`

Generates a PKCE verifier and its S256 code challenge.

| Field | Type | Description |
| :--- | :--- | :--- |
| `verifier` | string | Base64URL-encoded random string of length `len` (43–128). |
| `challenge` | string | Base64URL-encoded SHA256 of the verifier. Send this to the IdP. |

### `jwk_to_pem(jwk)` → `Result<string>`

Converts a JSON Web Key object (RSA or EC P-256) to a PEM-encoded public key string.

### `safe_id(token)` → `string`

Returns the first 8 characters of the hex SHA-256 of `token`. Safe to include in log messages as a non-reversible token identifier.

### `set_native(n)` → `void`

Replaces the active native backend. **Testing use only** — allows tests to substitute a mock crypto implementation.

---

## `luci_sso.oidc`

Pure OIDC protocol logic. No I/O except where an `io` parameter is explicitly required. Also re-exports `discover`, `fetch_jwks`, and `find_jwk` from `luci_sso.discovery`.

### `get_auth_url(io, config, discovery_doc, params)` → `Result<string>`

Constructs the full authorization URL (including PKCE challenge, state, nonce, scope, and redirect URI).

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `io` | io provider | Used for logging only. |
| `config` | object | UCI config. |
| `discovery_doc` | object | Parsed OIDC discovery document. |
| `params` | object | Handshake state object from `luci_sso.session.create_state()`. |

### `exchange_code(io, config, discovery, code, verifier, session_id)` → `Result<{id_token, access_token, ...}>`

Exchanges an authorization code for tokens via the IdP's token endpoint (back-channel).

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `io` | io provider | Used for HTTP and logging. |
| `config` | object | UCI config. |
| `discovery` | object | Parsed OIDC discovery document. |
| `code` | string | Authorization code from the IdP callback. |
| `verifier` | string | PKCE code verifier generated at flow initiation. |
| `session_id` | string | Handshake session ID (for log correlation). |

### `verify_id_token(io, tokens, keys, config, handshake, discovery, now, policy)` → `Result<claims>`

Validates an ID Token against all OIDC Core §3.1.3.7 requirements: algorithm, signature, `iss`, `aud`, `exp`, `iat`, `nonce`, and `at_hash`.

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `io` | io provider | Used for JWKS refresh on signature failure and logging. |
| `tokens` | object | Token response object containing `id_token` and `access_token`. |
| `keys` | array | Array of JWK objects from `fetch_jwks()`. |
| `config` | object | UCI config. Provides `issuer_url`, `client_id`, `clock_tolerance`. |
| `handshake` | object | Handshake state. Provides the expected `nonce`. |
| `discovery` | object | Discovery document. Provides `jwks_uri` for refresh. |
| `now` | int | Current Unix timestamp (from `io.time()`). |
| `policy` | object | Security policy. `policy.allowed_algs` lists accepted algorithms. |

On success, `result.data` is the decoded JWT claims object.

### `fetch_userinfo(io, endpoint, access_token)` → `Result<object>`

Fetches user profile claims from the IdP's UserInfo endpoint. Called when the ID Token does not contain an `email` claim.

---

## `luci_sso.config`

UCI configuration loader and role mapper.

### `is_enabled(io)` → `Result<bool>`

Returns `Result.ok(true)` if the `enabled` option is `'1'` in UCI.

### `load(io)` → `Result<config_object>`

Reads and validates the full UCI configuration. Returns a config object suitable for passing to `handshake.initiate()` and `handshake.authenticate()`. Fails with `CONFIG_ERROR` if any required option is missing or invalid.

The returned config object shape:

| Field | Type | Source |
| :--- | :--- | :--- |
| `issuer_url` | string | `luci-sso.default.issuer_url` |
| `internal_issuer_url` | string \| null | `luci-sso.default.internal_issuer_url` |
| `client_id` | string | `luci-sso.default.client_id` |
| `client_secret` | string | `luci-sso.default.client_secret` |
| `redirect_uri` | string | `luci-sso.default.redirect_uri` |
| `scope` | string | `luci-sso.default.scope` |
| `clock_tolerance` | int | `luci-sso.default.clock_tolerance` |
| `roles` | array | All `config role` sections |

### `find_roles_for_user(config, claims)` → `Result<{role_name, read, write}>`

Matches a user's OIDC claims against the configured roles. Returns the merged permissions of all matching roles.

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `config` | object | Loaded config from `load()`. |
| `claims` | object | JWT claims object. Uses `claims.email` and `claims.groups`. |

On success, `result.data` contains:

| Field | Type | Description |
| :--- | :--- | :--- |
| `role_name` | string | Name of the first matched role. Used as the UBUS session label. |
| `read` | array | Merged list of LuCI access groups granted read access. |
| `write` | array | Merged list of LuCI access groups granted write access. |

---

## `luci_sso.discovery`

OIDC metadata fetching and caching. Also exported from `luci_sso.oidc`.

### `discover(io, issuer, options)` → `Result<discovery_doc>`

Fetches and validates the OIDC discovery document from `<issuer>/.well-known/openid-configuration`. Caches the result in `/var/run/luci-sso/` for 24 hours.

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `io` | io provider | Used for HTTP and filesystem. |
| `issuer` | string | The public OIDC issuer URL. |
| `options` | object | Optional. `options.internal_issuer_url` overrides the fetch origin for split-horizon setups. |

### `fetch_jwks(io, jwks_uri, options)` → `Result<{keys}>`

Fetches the JWK Set from the IdP. Caches in `/var/run/luci-sso/` for 24 hours.

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `io` | io provider | Used for HTTP and filesystem. |
| `jwks_uri` | string | The `jwks_uri` from the discovery document. |
| `options` | object | Optional. `options.force` bypasses the cache. |

On success, `result.data.keys` is an array of JWK objects.

### `find_jwk(keys, kid)` → `Result<jwk>`

Finds a JWK by `kid` (key ID). If `kid` is absent, returns the first key.

---

## Native C bridge (`src/native.h`)

The C interface that all crypto backends must implement. See [How to Add a New Crypto Backend](../how-to/developer/adding-crypto-backend.md) for the full walkthrough.

All input buffers are subject to the `NATIVE_MAX_INPUT_SIZE` (16 384 bytes) limit enforced by `web.uc` before data reaches the C layer.

### `native_crypto_init()` → `int`

Initializes the crypto backend (e.g., PSA Crypto for mbedTLS). Called once at startup. Returns `0` on success.

### `native_crypto_deinit()` → `void`

Releases backend resources. Called during test teardown and fuzzing cleanup.

### `native_verify_rs256(msg, msg_len, sig, sig_len, key_pem, key_len)` → `bool`

Verifies an RS256 signature. Rejects RSA keys shorter than `NATIVE_RSA_MIN_BITS` (2048 bits).

### `native_verify_es256(msg, msg_len, sig, sig_len, key_pem, key_len)` → `bool`

Verifies an ES256 (ECDSA P-256) signature using constant-time comparison.

### `native_sha256(input, input_len, output)` → `int`

Computes SHA-256. `output` must be at least `NATIVE_SHA256_SIZE` (32) bytes. Returns `0` on success.

### `native_hmac_sha256(key, key_len, msg, msg_len, output)` → `int`

Computes HMAC-SHA256. `output` must be at least 32 bytes. Returns `0` on success.

### `native_random(buf, len)` → `int`

Fills `buf` with `len` cryptographically random bytes from a CSPRNG. Returns `0` on success. **Must not use a predictable source.**

### `native_memzero(p, len)` → `void`

Zeroizes `len` bytes at `p` using a compiler-safe method (e.g., `explicit_bzero`) that cannot be optimized away.

### `native_jwk_rsa_to_pem(n, n_len, e, e_len, out, out_len)` → `int`

Converts RSA JWK modulus (`n`) and exponent (`e`) to a PEM-encoded public key. `out` must be at least `NATIVE_RSA_PEM_MAX` (4096) bytes.

### `native_jwk_ec_p256_to_pem(x, x_len, y, y_len, out, out_len)` → `int`

Converts EC P-256 JWK coordinates (`x`, `y`) to a PEM-encoded public key. Validates coordinate lengths against `NATIVE_EC_COORD_SIZE` (32 bytes) before use. `out` must be at least `NATIVE_EC_PEM_MAX` (2048) bytes.

---

## Testing utilities (`test/`)

The test framework lives in `test/` and is not part of the installed package.

| Module | Purpose |
| :--- | :--- |
| `test/testing/` | Test runner, `test()`, `assert()`, `assert_eq()` |
| `test/mock.uc` | Mock I/O provider factory — `mock.create()` |
| `test/lib/` | Shared fixtures (valid JWTs, JWKS, discovery docs) |

See [Testing Architecture](testing-architecture.md) for the tier structure and [How to Run Tests](../how-to/developer/testing.md) for usage.
