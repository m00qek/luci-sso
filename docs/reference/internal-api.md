# Internal API Reference

This document lists the exported API of every `luci-sso` module in `src/luci_sso/`, the functions of the compiled `luci_sso.native` module, and the C interface in `mod/native.h`. It is intended for developers extending the system, writing tests, or implementing a new crypto backend.

For the rationale behind the module boundaries, see [About the Architecture](../explanation/architecture.md).

| Module | Role |
| :--- | :--- |
| [`luci_sso.entry`](#luci_ssoentry) | The CGI pipeline. |
| [`luci_sso.web`](#luci_ssoweb) | HTTP request parsing and response rendering. |
| [`luci_sso.router`](#luci_ssorouter) | Dispatches one request by path. |
| [`luci_sso.handshake`](#luci_ssohandshake) | The OIDC orchestrator for both legs of the authorization code flow. |
| [`luci_sso.oidc`](#luci_ssooidc) | OIDC protocol steps. |
| [`luci_sso.discovery`](#luci_ssodiscovery) | Discovery document and JWK Set fetching, with a cache. |
| [`luci_sso.config`](#luci_ssoconfig) | UCI configuration loader and role mapper. |
| [`luci_sso.session`](#luci_ssosession) | The handshake state files. |
| [`luci_sso.ubus`](#luci_ssoubus) | The `rpcd` session and the access-token replay registry. |
| [`luci_sso.rpcd_login`](#luci_ssorpcd_login) | The roles' `rpcd` login entries and `rpcd`'s rules for them. |
| [`luci_sso.ratelimit`](#luci_ssoratelimit) | Per-client request budgets. |
| [`luci_sso.crypto`](#luci_ssocrypto) | Facade over the crypto wrappers. |
| [`luci_sso.encoding`](#luci_ssoencoding) | Pure encoding and URL helpers. |
| [`luci_sso.result`](#luci_ssoresult) | The Result constructors. |
| [`luci_sso.errors`](#luci_ssoerrors) | The public error code constants. |
| [`luci_sso.deps`](#luci_ssodeps) | Builds the production `deps` object. |
| [`luci_sso.components.http_client`](#luci_ssocomponentshttp_client) | The HTTPS client for back-channel requests. |
| [`luci_sso.components.clock`](#luci_ssocomponentsclock) | Time and sleep. |
| [`luci_sso.native`](#luci_ssonative) | The compiled crypto bridge. |
| [Native C bridge](#native-c-bridge-modnativeh) | The C interface every crypto backend implements. |
| [Test support](#test-support-test) | Test harness files under `test/`. |

---

## Conventions

### The Result type

Fallible functions return a **Result** instead of throwing:

```javascript
{
    ok:      bool,    // true = success, false = failure
    data:    any,     // the value, when ok == true
    error:   string,  // an error code, when ok == false
    details: any      // optional context, when ok == false
}
```

Error codes are usually constants from `luci_sso.errors` (see [Log Messages](log-messages.md)); a few internal codes, such as `NO_ROLES_MATCHED` or `CSPRNG_FAILURE`, never leave their module. When `details` is an object with `http_status` (and optionally `retry_after`), `entry.uc` uses it for the HTTP response.

Functions `die()` on contract violations (wrong argument types), which the CGI entry turns into a logged crash and a generic `500` page.

### The `deps` object

Every function that touches the system takes `deps` as its first argument. `luci_sso.deps.create()` builds it:

| Field | Type | Description |
| :--- | :--- | :--- |
| `fs` | module `fs` | Filesystem access. |
| `native` | module `luci_sso.native` | The compiled crypto bridge (see [below](#luci_ssonative)). |
| `http` | `HttpClient` | HTTPS client from `luci_sso.components.http_client`. |
| `ubus` | `{ call(obj, method, args) → Result }` | ubus channel from `luci_sso.deps.ubus_channel`. |
| `uci` | UCI cursor | From `uci.cursor()`. |
| `clock` | `Clock` | From `luci_sso.components.clock`. |
| `log` | `(level, msg) → void` | Syslog writer; `level` is `"error"`, `"warn"`, `"info"` or `"debug"`. |

Functions document the fields they use, for example `deps: { fs, clock }`. The crypto functions take only the native module, as their first argument `native`.

---

## `luci_sso.entry`

The CGI pipeline.

### `run(deps, web_deps)` → `void`

Parses the request, loads the configuration, calls `router.handle()` and writes the response or error page. Catches any exception and writes the crash page.

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `deps` | `Deps` | The full `deps` object. |
| `web_deps` | object | `{ getenv, stdout, log }`: the CGI environment reader, the output stream and the log function. |

When `config.load()` fails with `SSO_DISABLED` and the request is `GET /?action=enabled`, the router is called with a `null` config so the probe still answers. Any other configuration failure is rendered with status `500`, after logging `Configuration rejected: <details>`.

---

## `luci_sso.web`

HTTP request parsing and response rendering. Uses `deps`-style arguments that hold only CGI I/O.

### `request(deps)` → `Result<{path, query, cookies, client}>`

Reads `PATH_INFO`, `QUERY_STRING`, `HTTP_COOKIE` and `REMOTE_ADDR` through `deps.getenv`. `path` defaults to `"/"`. Fails with `INPUT_TOO_LARGE` (`http_status: 431`) when a value exceeds 16 384 bytes or a list has more than 100 entries.

### `parse_params(str)` → `Result<object>`

Parses a query string into an object of URL-decoded keys and values. A key without `=` maps to `null`.

### `parse_cookies(str)` → `Result<object>`

Parses a `Cookie` header into an object. Strips surrounding double quotes from values.

### `render(deps, res)` → `void`

Writes `res` (`{ status, headers, body }`) to `deps.stdout` with the security headers. A `302` gets a fixed HTML body.

### `render_error(deps, code, status, extra)` → `void`

Logs `[<status>] <code>` through `deps.log` and writes an HTML error page with a fixed user message for `code`. `status` defaults to `500`; `extra` adds headers, such as `Retry-After`.

### `error(deps, e)` → `void`

Logs `Router crash: <e>` with the stack trace and writes a generic `500` page.

---

## `luci_sso.router`

Request dispatch by path.

### `handle(deps, config, request)` → `Result<{status, headers, body}>`

Dispatches one request. `config` is the result of `config.load()`, or `null` when SSO is disabled. `request` is the result of `web.request()`.

| Path | Behaviour |
| :--- | :--- |
| `/` with `action=enabled` | Returns `{"enabled": true}` or `{"enabled": false}` from `config.is_enabled()`. Not rate-limited; works with a `null` config. |
| `/` | Reaps stale handshakes, calls `handshake.initiate()`, and redirects to the IdP with the `__Host-luci_sso_state` cookie. |
| `/callback` | Calls `handshake.authenticate()` and redirects to `/cgi-bin/luci/` with the session cookies. |
| `/logout` | Without a valid session, redirects to `/`. Otherwise checks `stoken` against the session's CSRF token, destroys the session, and redirects to the IdP's `end_session_endpoint` or `/`. |
| anything else | `NOT_FOUND` (`404`). |

Every path except the probe first spends the client's rate-limit budget (`TOO_MANY_REQUESTS`, `429`). With a `null` config, every path except the probe fails with `SSO_DISABLED` (`500`, the status `entry.run()` renders for disabled SSO); `entry.run()` never calls it that way.

---

## `luci_sso.handshake`

The OIDC orchestrator for both legs of the authorization code flow.

### `initiate(deps, config)` → `Result<{url, token}>`

Runs discovery, creates the handshake state and builds the authorization URL. `deps: { fs, http, native, clock, log }`.

| Field | Type | Description |
| :--- | :--- | :--- |
| `url` | string | Redirect URL to the IdP's `authorization_endpoint`. |
| `token` | string | Opaque handshake handle. Set it as the `__Host-luci_sso_state` cookie. |

Fails with `OIDC_DISCOVERY_FAILED` (`502`), `HANDSHAKE_CAPACITY_EXCEEDED` (`503`), or an error from `session.create_state()` or `oidc.get_auth_url()`.

### `authenticate(deps, config, request)` → `Result<{sid, email}>`

Processes the callback. `deps`: all fields. In order, it:

1. checks `error`, `code` and the handshake cookie;
2. verifies the handshake against `state`;
3. runs discovery (from the cache when fresh);
4. exchanges the code;
5. fetches the JWK Set;
6. verifies the ID Token, forcing one JWK Set refresh on `KEY_NOT_FOUND`, or on `INVALID_SIGNATURE` when the token has a `kid`;
7. fetches UserInfo when the ID Token has no `email`;
8. registers the access token against replay;
9. maps the claims to the first matching role (`config.find_role_for_user`) and logs it, with any other matches;
10. creates the `rpcd` session from the role's `rpcd` login entry. Any failure there, including `MISSING_RPCD_LOGIN` and `INSECURE_RPCD_LOGIN`, ends as `UBUS_LOGIN_FAILED` (500).

| Field | Type | Description |
| :--- | :--- | :--- |
| `sid` | string | The `rpcd` session ID. Set it as the `sysauth_https` and `sysauth` cookies. |
| `email` | string | The user's email address. |

The HTTP status of each failure is listed in the [HTTP API Reference](http-api.md#error-responses).

---

## `luci_sso.oidc`

OIDC protocol steps. `exchange_code()` and `fetch_userinfo()` perform HTTP requests through `deps.http`.

### `get_auth_url(deps, config, discovery_doc, params)` → `Result<string>`

Builds the authorization URL with `response_type=code`, `client_id`, `redirect_uri`, `scope` (default `openid profile email`), `state`, `nonce`, `code_challenge` and `code_challenge_method=S256`. `params` is the result of `session.create_state()`; `state` and `nonce` must be at least 16 characters.

### `exchange_code(deps, config, discovery, code, verifier, session_id)` → `Result<object>`

POSTs the authorization code, the PKCE `verifier` (43–128 characters) and the client credentials to `discovery.token_endpoint`. Returns the parsed token response. `session_id` only correlates log lines. Fails with `INSECURE_TOKEN_ENDPOINT`, `INVALID_PKCE_VERIFIER`, `TOKEN_ENDPOINT_NETWORK_ERROR`, `OIDC_INVALID_GRANT`, `TOKEN_EXCHANGE_FAILED` or `TOKEN_RESPONSE_INVALID_JSON`. The last four are failures of the IdP and carry `details.http_status` `502`; the token endpoint's own status is only logged.

### `verify_id_token(deps, tokens, keys, config, handshake, discovery, now)` → `Result<{sub, email, name, groups}>`

Validates `tokens.id_token`: algorithm (`RS256` or `ES256` only, fixed in code), key lookup by `kid`, signature, `iss`, `aud`, `exp`, `nbf`, `iat` (through `crypto.jwt_verify`), then `sub`, `exp` and `iat` presence, `nonce`, `azp`, the access token's presence, and `at_hash` when the token has one (an ID Token without it is accepted).

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `tokens` | object | Token response with `id_token` and `access_token`. |
| `keys` | array | JWK objects from `discovery.fetch_jwks()`. |
| `config` | object | Provides `issuer_url`, `client_id` and `clock_tolerance`. |
| `handshake` | object | Provides the expected `nonce`. |
| `discovery` | object | Its `issuer` must match `config.issuer_url`. |
| `now` | int | Current Unix time, from `deps.clock.time()`. |

On success, `email` and `name` are `null` unless they are strings in the token, and `groups` is `[]` unless it is an array.

### `fetch_userinfo(deps, endpoint, access_token)` → `Result<object>`

GETs the UserInfo endpoint with the access token as a Bearer token and returns the claims. Fails with `INSECURE_USERINFO_ENDPOINT`, `MISSING_ACCESS_TOKEN`, `USERINFO_NETWORK_ERROR`, `USERINFO_FETCH_FAILED`, `USERINFO_INVALID_JSON` or `MISSING_SUB_CLAIM`.

---

## `luci_sso.discovery`

Discovery document and JWK Set fetching, with a 24-hour cache in `/var/run/luci-sso/` keyed by a hash of the URL. When a fetch fails, an expired cache entry is used instead. `deps: { fs, http, native, clock, log }`.

### `discover(deps, issuer, options)` → `Result<discovery_doc>`

Fetches `<issuer>/.well-known/openid-configuration`, checks that its `issuer` equals `issuer` after normalization, and that `authorization_endpoint`, `token_endpoint` and `jwks_uri` are present and HTTPS. Drops a non-HTTPS `userinfo_endpoint` or `end_session_endpoint`.

| Option | Description |
| :--- | :--- |
| `internal_issuer_url` | Fetch from this origin instead, keeping the issuer's path. |
| `cache_path` | Override the cache file. |
| `ttl` | Cache lifetime in seconds (default `86400`). |

### `fetch_jwks(deps, jwks_uri, options)` → `Result<array>`

Returns the `keys` array of the JWK Set. Options: `force` (skip the cache), `cache_path`, `ttl`.

### `find_jwk(keys, kid)` → `Result<jwk>`

Returns the key whose `kid` equals `kid`, or the first key when `kid` is empty. Fails with `KEY_NOT_FOUND` or `NO_KEYS_AVAILABLE`.

---

## `luci_sso.config`

UCI configuration loader and role mapper. `deps: { uci, log }`.

### `is_enabled(deps)` → `Result<bool>`

`true` when `luci-sso.default.enabled` is `'1'`. Fails with `UCI_ERROR` when there is no cursor.

### `load(deps)` → `Result<config>`

Reads and validates `/etc/config/luci-sso`. Fails with `SSO_DISABLED`, `UCI_ERROR`, or `CONFIG_ERROR` with the reason in `details`.

| Field | Type | Source |
| :--- | :--- | :--- |
| `issuer_url` | string | `luci-sso.default.issuer_url` |
| `internal_issuer_url` | string | `luci-sso.default.internal_issuer_url`, or `issuer_url` when unset |
| `client_id` | string | `luci-sso.default.client_id` |
| `client_secret` | string | `luci-sso.default.client_secret` |
| `redirect_uri` | string | `luci-sso.default.redirect_uri` |
| `scope` | string or null | `luci-sso.default.scope` |
| `clock_tolerance` | int | `luci-sso.default.clock_tolerance` (0–3600) |
| `roles` | array | Every `config role` section with an email or group, in config order: `{ name, emails, groups }`. A role's `read` or `write` options are not read; when present, a warning names the role's `rpcd` login entry. |

### `find_role_for_user(config, claims)` → `Result<{role_name, also_matched}>`

Matches `claims.email` (case-insensitive) and `claims.groups` (case-sensitive, only when it is an array) against every role, in config order. `role_name` is the first matching role; `also_matched` lists the other matching roles, in order. Rights are never merged. Fails with `NO_ROLES_MATCHED` when nothing matches.

---

## `luci_sso.session`

Facade over `luci_sso.session.handshake`: the handshake state files in `/var/run/luci-sso/`.

| Export | Implementation |
| :--- | :--- |
| `create_state` | `session.handshake.create` |
| `verify_state` | `session.handshake.verify` |
| `consume_state` | `session.handshake.consume` |
| `reap_stale_handshakes` | `session.handshake.reap` |

### `create(deps, clock_tolerance)` → `Result<{token, state, nonce, code_challenge}>`

Writes a new handshake file (mode `0600`) holding `state`, `nonce`, the PKCE verifier, `iat` and `exp` (`iat` + 300 s), and returns the opaque `token` for the cookie. At 500 pending handshakes it first removes expired ones; if none can be removed, it fails with `HANDSHAKE_CAPACITY_EXCEEDED`. Other failures: `CRYPTO_INIT_FAILED`, `STATE_SAVE_FAILED`. `deps: { fs, clock, native, log }`.

### `verify(deps, handle, expected_state, clock_tolerance)` → `Result<handshake>`

Reads the handshake for `handle`, checks its fields, compares `state` with `expected_state` in constant time, checks `exp` and `iat` against the clock, and only then claims the file by renaming it. Returns `{ id, state, code_verifier, nonce, iat, exp }`. A wrong `state` fails with `STATE_PARAMETER_MISMATCH` and keeps the file; `STATE_CORRUPTED`, `HANDSHAKE_EXPIRED` and `HANDSHAKE_NOT_YET_VALID` remove it. Other failures: `MALFORMED_STATE_COOKIE`, `STATE_NOT_FOUND`.

### `consume(deps, handle)` → `void`

Deletes the handshake file for `handle`.

### `reap(deps, clock_tolerance)` → `Result<int>`

Deletes handshake files older than 300 s + `clock_tolerance` + 60 s and returns how many were removed.

### `luci_sso.session.common`

Constants `HANDSHAKE_DURATION` (`300`), `HANDSHAKE_DIR` (`"/var/run/luci-sso"`), `REAP_GRACE_PERIOD` (`60`), `LIMIT_PENDING_HANDSHAKES` (`500`), and `ensure_handshake_dir(deps)`.

---

## `luci_sso.ubus`

The `rpcd` session and the access-token replay registry. `deps: { ubus, fs, native, log }`, plus `uci` for `create_passwordless_session`.

### `create_passwordless_session(deps, role, oidc_email, access_token, refresh_token, id_token)` → `Result<string>`

Creates an `rpcd` session for `role` with the rights of its `rpcd` login entry. Before creating anything, it reads `rpcd.luci_sso_<role>` through `deps.uci`:

- a missing entry, one that is not a `login`, or one whose `username` is not `sso:<role>` fails with `MISSING_RPCD_LOGIN`;
- an entry with a `password` option, whatever its value, fails with `INSECURE_RPCD_LOGIN`.

It then creates the session with LuCI's idle timeout (`luci.sauth.sessiontime`, default `3600`) and grants exactly what `rpcd` grants a password login with the entry's `read` and `write` lists (`rpcd_login.permits` over the ACL files in `/usr/share/rpcd/acl.d/`). Only list options count; nothing is added. A plain group name that no ACL file defines is logged as a warning. Returns the session ID. Other failures: `UBUS_SESSION_FAILED` or `CRYPTO_INIT_FAILED`; a failure after the session is created destroys it. `deps.ubus.call`, `deps.uci` and a non-empty `role` are required (`die()` otherwise).

The session holds these values:

| Value | Content |
| :--- | :--- |
| `username` | `sso:<role>`, the entry's user name, from which `rpcd` rebuilds the session's rights on reload. |
| `oidc_user` | The email. |
| `oidc_access_token` | The access token. |
| `oidc_refresh_token` | The refresh token. |
| `oidc_id_token` | The ID token. |
| `token` | A random CSRF token. |

### `get_session(deps, sid)` → `Result<object>`

Returns the session's values.

### `destroy_session(deps, sid)` → `Result`

Destroys the session.

### `register_token(deps, access_token)` → `Result`

Creates `/var/run/luci-sso/tokens/<sha256 hex>` with `mkdir`, which succeeds only once per token. Fails with `TOKEN_REPLAYED`, `INVALID_TOKEN`, `SYSTEM_ERROR` or a hashing error.

---

## `luci_sso.rpcd_login`

The roles' `rpcd` login entries (`luci_sso_<role>` in `/etc/config/rpcd`, `username 'sso:<role>'`, never a password) and `rpcd`'s rules for them. Shared by `luci_sso.ubus`, the `luci-sso` ubus object (`files/usr/share/rpcd/ucode/luci-sso.uc`), the install script `20-luci-sso-rpcd` and the package's removal script. No `deps`: functions that write take a UCI cursor, and the caller commits.

| Constant | Value |
| :--- | :--- |
| `CONFIG` | `"rpcd"` |
| `SECTION_PREFIX` | `"luci_sso_"` |
| `USERNAME_PREFIX` | `"sso:"` |
| `BASELINE_GROUP` | `"unauthenticated"`: the access group every stored `read` list grants. |
| `NAME_MAX` | `32`: the longest role name. |
| `LIST_MAX` | `128`: the most entries in a list. |
| `ENTRY_MAX` | `128`: the longest list entry. |
| `DEFAULT_ROLE` | `"admin"`: the role the package ships. |
| `PLACEHOLDER_EMAIL` | `"admin@example.com"`: the shipped role's only email. |

### `section_name(role)` → `string`

`luci_sso_<role>`.

### `username(role)` → `string`

`sso:<role>`.

### `check_name(name)` → `Result<string>`

1 to `NAME_MAX` letters, digits and underscores. Fails with `INVALID_NAME`.

### `check_list(label, list)` → `Result<array>`

An array of at most `LIST_MAX` non-empty strings of at most `ENTRY_MAX` characters, without control characters. `label` (`"read"` or `"write"`) names the list in the message. Fails with `INVALID_LIST`.

### `permits(lists, perm, group)` → `bool`

Whether an entry with `lists` (`{ read, write }`) has `perm` (`"read"` or `"write"`) on `group`, as `rpcd` decides it: `fnmatch(3)` patterns; a negation in the permission's own list denies before any positive entry allows; a read that the `read` list neither allows nor denies falls back to the `write` list. Only arrays count.

### `with_baseline(read)` → `Result<array>`

The `read` list to store: as given when it already grants `BASELINE_GROUP`, otherwise with it appended. Applying it twice gives the same list. Fails with `INVALID_LIST` when a negation in the list denies the group.

### `entry(name, read, write)` → `Result<{name, section, username, read, write}>`

Checks the name and both lists and returns the entry to store, with `read` from `with_baseline()`. Fails with `INVALID_NAME` or `INVALID_LIST`.

### `stage(uci, e)` → `void`

Stages an entry from `entry()` on a UCI cursor: the section becomes a `login` (a section of another type under the name is replaced), `username` is set, a `password` option is removed, and each list is replaced, or removed when empty. Touches no other section.

### `is_placeholder(s)` → `bool`

Whether a `luci-sso` role section, as `uci.foreach()` passes it, is the shipped role untouched: named `DEFAULT_ROLE`, with `PLACEHOLDER_EMAIL` as its only email and no group. A single option counts as a one-entry list.

### `migrate(uci, warn)` → `{rpcd, luci_sso}`

Moves role permissions from `/etc/config/luci-sso` into `rpcd` login entries. Run by `20-luci-sso-rpcd` on install and upgrade. For each role, in config order:

1. a role with a `read` or `write` option gets its entry created or replaced from them (a single option is a one-entry list), and loses the options; a role whose name or lists `entry()` refuses keeps them, and `warn` is called;
2. a role without lists that has an entry is left alone;
3. the shipped role (`is_placeholder()`) without lists or entry gets `read '*'` and `write '*'`;
4. any other role without lists or entry gets an entry that grants only `BASELINE_GROUP`, and `warn` is called; a role whose name `entry()` refuses gets no entry, and `warn` is called.

Touches only `luci_sso_*` sections of `rpcd`, never reorders roles, and changes nothing when there is nothing to do. Returns whether each configuration changed. The caller commits `rpcd` before `luci-sso`.

### `demigrate(uci, warn)` → `{rpcd, luci_sso}`

The reverse of `migrate()`, for the package's removal. For each `luci_sso_*` section of `rpcd`, in config order: if it is a `login` and `/etc/config/luci-sso` has the role, its `read` and `write` lists replace the role's options, as stored (`BASELINE_GROUP` included; an empty list removes the option). The section is then deleted; a section without a role, or not a login, is deleted with a `warn` call. `migrate()` then recreates the same entries. Returns whether each configuration changed. The caller commits `luci-sso` before `rpcd`.

---

## `luci_sso.ratelimit`

Per-client request budgets, stored in `STATE_FILE`. `deps: { fs, clock, native, log }`.

| Export | Value |
| :--- | :--- |
| `STATE_FILE` | `"/var/run/luci-sso/ratelimit.json"` |
| `LIMITS` | `{ login: { requests: 10, window: 300 }, client: { requests: 30, window: 60 }, tracked: 256 }` |
| `UNKNOWN_CLIENT` | `"unknown"`, the shared key for unparseable addresses |

### `client_key(addr)` → `string`

Maps `REMOTE_ADDR` to a key: `"v4:<address>"` for IPv4 and IPv4-mapped IPv6, `"v6:<first four groups>"` (the `/64`) for IPv6, `UNKNOWN_CLIENT` otherwise.

### `check(deps, key, is_login)` → `{allowed, retry_after, budget}`

Counts one request for `key` (and one login when `is_login`), saves the state, and returns whether it is allowed. When not, `budget` is `"login"` or `"client"` and `retry_after` is the seconds until that window ends.

---

## `luci_sso.crypto`

Facade over `luci_sso.crypto.*`. Every function except `constant_time_eq` takes the native module as its first argument.

| Export | Implementation |
| :--- | :--- |
| `constant_time_eq` | `crypto.base.constant_time_eq` |
| `random` | `crypto.base.random` |
| `safe_id` | `crypto.base.safe_id` |
| `jwt_verify` | `crypto.jwt.verify` |
| `hash_sha256` | `crypto.hash.sha256` |
| `hash_sha256_hex` | `crypto.hash.sha256_hex` |
| `pkce_pair` | `crypto.pkce.pair` |
| `jwk_to_pem` | `crypto.jwk.to_pem` |

### `constant_time_eq(a, b)` → `bool`

Compares two strings without an early exit: it XOR-accumulates over the length of the longer string. Pure ucode, and best-effort only: an interpreter cannot guarantee constant time. Returns `false` for non-strings and for inputs over 16 384 bytes.

### `random(native, len)` → `Result<string>`

Returns `len` random bytes (default `32`; the native module accepts 1–4096). `die()`s if `len` is not an integer. Fails with `CSPRNG_FAILURE`.

### `safe_id(native, token)` → `string`

Returns the first 16 hex characters (64 bits) of the SHA-256 of `token`, for log correlation. Returns `"[INVALID]"` for a non-string or a string under 8 characters, and `"[ERROR]"` if hashing fails.

### `jwt_verify(native, token, pubkey, options)` → `Result<payload>`

Verifies a compact JWT with a PEM public key and returns the decoded payload.

| Option | Description |
| :--- | :--- |
| `alg` | `"RS256"` or `"ES256"`. The header must match. |
| `iss` | Expected issuer (compared after URL normalization). Required. |
| `aud` | Expected audience. Required. |
| `now` | Current Unix time. Required integer. |
| `clock_tolerance` | Allowed skew in seconds. Required integer. |
| `pre_parsed_header` | Optional already-decoded header. |

Rejects tokens over 16 KB (`TOKEN_TOO_LARGE`); checks `exp`, `nbf` (if present) and that `iat` is not in the future.

### `hash_sha256(native, str)` → `Result<string>`

The SHA-256 digest of `str` as 32 raw bytes. Fails with `INVALID_ARGUMENT` for a non-string, `CRYPTO_ERROR` if the native call fails.

### `hash_sha256_hex(native, str)` → `Result<string>`

The SHA-256 digest as 64 lowercase hex characters.

### `pkce_pair(native, len)` → `Result<{verifier, challenge}>`

Generates a PKCE verifier from `len` random bytes (default `43`, range 32–96; `die()`s outside it), Base64URL-encoded, and its S256 challenge.

### `jwk_to_pem(native, jwk)` → `Result<string>`

Converts an `RSA` or `EC` (`P-256`) JWK to a PEM public key. Fails with `MISSING_KTY`, `UNSUPPORTED_KTY`, `MISSING_RSA_PARAMS`, `INVALID_RSA_PARAMS_ENCODING`, `UNSUPPORTED_CURVE`, `MISSING_EC_PARAMS`, `INVALID_EC_PARAMS_ENCODING` or `PEM_CONVERSION_FAILED`.

`luci_sso.crypto.pkce` also exports `generate_verifier(native, len)` and `calculate_challenge(native, verifier)`.

---

## `luci_sso.encoding`

Pure helpers.

| Function | Returns | Description |
| :--- | :--- | :--- |
| `b64url_decode(str)` | `Result<string>` | Base64URL to raw bytes. Fails with `TOKEN_TOO_LARGE` over 32 KB, `INVALID_ENCODING` on bad input. |
| `b64url_encode(str)` | `Result<string>` | Raw bytes to unpadded Base64URL. |
| `binary_truncate(data, len)` | `Result<string>` | The first `len` bytes. |
| `safe_json(data)` | `Result<any>` | Parses JSON from a string, a Result holding one, or an object with `read()`. |
| `normalize_url(url)` | `Result<string>` | Lower-case scheme and host, default port removed, trailing slashes removed. |
| `split_origin(url)` | `Result<{origin, rest}>` | The normalized origin and the untouched path, query and fragment. Refuses URLs with userinfo. |
| `is_origin(url)` | `bool` | `true` for `scheme://host[:port]` with at most a trailing `/`. |
| `rebase_origin(url, from, to)` | `string` | Moves `url` from `from`'s origin to `to`'s, keeping its path; otherwise returns it unchanged. |
| `normalize_sub(sub)` | `Result<string>` | Lower-cases a `sub` claim. |
| `is_https(url)` | `bool` | `true` if `url` starts with `https://`, in any case. |
| `log_safe(value, max)` | `string` | Replaces every byte outside printable ASCII with `?` and cuts the result to `max` bytes (default `200`), adding `...`. A non-string gives `""`. For untrusted values in log lines. |

---

## `luci_sso.result`

Constructors and helpers for [the Result type](#the-result-type).

| Function | Description |
| :--- | :--- |
| `ok(data)` | A successful Result. |
| `err(error, details)` | A failed Result. |
| `is(obj)` | `true` if `obj` was made by `ok()` or `err()`. |
| `describe(res)` | `"<error> (<details>)"` when `details` is a non-empty string, otherwise `"<error>"`. Used in log lines. |

---

## `luci_sso.errors`

One exported string constant per public error code, equal to its name. [Log Messages](log-messages.md) documents every one; `make lint` keeps the two in sync.

---

## `luci_sso.deps`

The production wiring of [the `deps` object](#the-deps-object).

### `create()` → `Deps`

Builds the production `deps` object. Called once by the CGI script; never in tests.

### `ubus_channel(conn)` → `{ call(obj, method, args) → Result }`

Wraps a ubus connection. A `null` reply is a success unless `conn.error()` reports one (`UBUS_ERROR`); a missing connection gives `UBUS_CONNECT_FAILED`.

### `syslog_channel(log_mod)` → `(level, msg) → void`

Opens syslog with the tag `luci-sso` and returns the `deps.log` function.

---

## `luci_sso.components.http_client`

The HTTPS client behind `deps.http`, used for every request from the router to the IdP.

### `create(uclient, uloop, fs)` → `HttpClient`

Returns `{ get(url, opts), post(url, opts) }`. `opts.headers` sets request headers; `post` sends `opts.body`. Both return `Result<{status, body}>`.

- Only HTTPS URLs are accepted (`HTTPS_REQUIRED`).
- Certificates are verified against every `*.crt` and `*.pem` file in `/etc/ssl/certs/` plus the usual bundle paths.
- Requests time out after 10 seconds and bodies are capped at 256 KB.
- A failed request is `HTTP_REQUEST_FAILED` with the cause in `details`: `CONNECT_NOT_STARTED`, `CONNECTION_FAILED`, `TIMED_OUT`, `CERT_UNTRUSTED`, `CERT_NAME_MISMATCH`, `SSL_INIT_FAILED`, `RESPONSE_TOO_LARGE` or `UCLIENT_ERROR_<n>`, among others.

---

## `luci_sso.components.clock`

The time source behind `deps.clock`.

### `create(uloop, time_fn)` → `Clock`

Returns `{ time(), sleep(seconds) }`. `time_fn` defaults to the built-in `time()`. `sleep` accepts 0–30 seconds.

---

## `luci_sso.native`

The compiled bridge, `/usr/lib/ucode/luci_sso/native.so`, installed by one `luci-sso-crypto-*` package. The functions are registered only if the backend initializes; failures return `false` or `null`.

| Function | Returns | Description |
| :--- | :--- | :--- |
| `verify_rs256(msg, sig, pem)` | `bool` | RS256 signature check. |
| `verify_es256(msg, sig, pem)` | `bool` | ES256 check; `sig` is 64 bytes, `R` then `S`. |
| `sha256(str)` | string or `null` | 32 raw bytes. |
| `hmac_sha256(key, msg)` | string or `null` | 32 raw bytes. An empty key fails. |
| `random(len)` | string or `null` | `len` bytes (1–4096, default 32) from the backend's CSPRNG. |
| `jwk_rsa_to_pem(n, e)` | string or `null` | PEM from raw modulus and exponent; only `e` = 65537. |
| `jwk_ec_p256_to_pem(x, y)` | string or `null` | PEM from raw 32-byte P-256 coordinates. |

Every input over 16 384 bytes (`NATIVE_MAX_INPUT_SIZE`) is rejected before it reaches the backend.

---

## Native C bridge (`mod/native.h`)

The C interface that every crypto backend implements. See [How to Add a New Crypto Backend](../how-to/developer/adding-crypto-backend.md) for the full walkthrough.

These are the backend functions. Callers do not reach them directly: `mod/native_api.c` wraps each one with the input guards (the `NATIVE_MAX_INPUT_SIZE` 16 384-byte ceiling on every input, exact ES256 signature and EC coordinate lengths, the F4-only RSA exponent, the empty-HMAC-key rejection, the random length bounds) and guarantees NUL-terminated PEM output. The ucode binding in `mod/native_ucode.c` calls those wrappers.

### `native_crypto_init()` → `int`

Initializes the backend (PSA Crypto for mbedTLS, the RNG for wolfSSL; nothing for OpenSSL). Called from the module's init; the functions are registered only if it returns `0`.

### `native_crypto_deinit()` → `void`

Releases backend resources. Used by tests and the fuzzer.

### `native_verify_rs256(msg, msg_len, sig, sig_len, key_pem, key_len)` → `bool`

Verifies an RS256 signature. Rejects RSA keys shorter than `NATIVE_RSA_MIN_BITS` (2048 bits).

### `native_verify_es256(msg, msg_len, sig, sig_len, key_pem, key_len)` → `bool`

Verifies an ES256 (ECDSA P-256) signature given as 64 bytes of `R` followed by `S`.

### `native_sha256(input, input_len, output)` → `int`

Computes SHA-256. `output` must be at least `NATIVE_SHA256_SIZE` (32) bytes. Returns `0` on success.

### `native_hmac_sha256(key, key_len, msg, msg_len, output)` → `int`

Computes HMAC-SHA256. `output` must be at least 32 bytes. Returns `0` on success.

### `native_random(buf, len)` → `int`

Fills `buf` with `len` bytes from a CSPRNG. Returns `0` on success. **Must not use a predictable source.**

### `native_memzero(p, len)` → `void`

Zeroizes `len` bytes at `p` with a method the compiler cannot optimize away (`mbedtls_platform_zeroize`, `OPENSSL_cleanse` or an equivalent).

### `native_jwk_rsa_to_pem(n, n_len, e, e_len, out, out_len)` → `int`

Converts RSA JWK modulus (`n`) and exponent (`e`) to a PEM-encoded public key. `out` must be at least `NATIVE_RSA_PEM_MAX` (4096) bytes.

### `native_jwk_ec_p256_to_pem(x, x_len, y, y_len, out, out_len)` → `int`

Converts EC P-256 JWK coordinates (`x`, `y`) to a PEM-encoded public key. `out` must be at least `NATIVE_EC_PEM_MAX` (2048) bytes.

---

## Test support (`test/`)

The tests run on utest (the `ucode-utest` package), which is not part of the installed package.

| Path | Purpose |
| :--- | :--- |
| `test/utest.config.uc` | Module search paths and the modules utest proxies. |
| `test/context.uc` | `with_context(cfg, cb)`: builds a full `deps` object from proxies for integration tests. `rpcd_logins(roles)`: the UCI data of the roles' `rpcd` login entries, for a test whose login must succeed. |
| `test/lib/rpcd.uc` | System-bucket helpers for the real `rpcd`: login entries, session ACLs, and `await_reload()`, which waits for the reload a write triggers. |
| `test/proxies/` | Proxies for `clock`, `http_client` and `native`. |
| `test/fixtures/` | Shared fixtures (`fixtures.oidc`, `fixtures.rsa`). |
| `test/lib/helpers.uc` | Helpers that produce real signed JWTs. |

See [Testing Architecture](testing-architecture.md) for the test buckets and [How to Run Tests](../how-to/developer/testing.md) for usage.
