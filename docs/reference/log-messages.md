# Log Messages and Error Codes

All `luci-sso` events are written to the system log under the tag `luci-sso`.

--8<-- "check-log.md"

For steps to resolve common errors, see [How to Debug luci-sso](../how-to/sysadmin/debugging.md). For the HTTP endpoints that produce these codes, see the [HTTP API Reference](http-api.md).

**Terms used on this page**

- **IdP** (identity provider): the OIDC service that signs the user in and issues the tokens.
- **Back channel**: a request the router sends to the IdP itself, not through the browser: discovery, JWK Set, token exchange and UserInfo.
- **Handshake**: the record of one login in progress (`state`, `nonce`, PKCE verifier and timestamps). It is stored on the router in `/var/run/luci-sso/`, and the `__Host-luci_sso_state` cookie points to it.

---

## Codes by phase

The error codes are grouped by the step of the login where they occur. Find the step that failed, then look the code up in its table.

| Section | When the codes occur |
| :--- | :--- |
| [Configuration Errors](#configuration-errors) | On the first request that needs the configuration |
| [Discovery Errors](#discovery-errors) | While fetching the IdP's discovery document or JWK Set |
| [Login Initiation Errors](#login-initiation-errors) | When a login starts, before the browser goes to the IdP |
| [Callback Errors](#callback-errors) | When the browser comes back from the IdP |
| [Token Exchange Errors](#token-exchange-errors) | During the back-channel request to the token endpoint |
| [Token Validation Errors](#token-validation-errors) | While checking the ID Token |
| [ID Token Verification Detail Codes](#id-token-verification-detail-codes) | The exact ID Token check that failed |
| [UserInfo Errors](#userinfo-errors) | While asking the UserInfo endpoint for missing claims |
| [Authorization Errors](#authorization-errors) | When mapping the user to a role, and at logout |
| [Session Errors](#session-errors) | When creating the LuCI session through `rpcd` |
| [Role Lines](#role-lines) | Lines without a code about roles and their `rpcd` login entries, at login, at install, upgrade and removal |
| [System Errors](#system-errors) | Transport, crypto, rate-limit and input-size failures at any step |

---

## How codes appear in the log

An error code reaches the log in one of four ways. The **In the log** column of each table below says which applies to that code:

| The **In the log** column shows | How the code appears |
| :--- | :--- |
| `[<status>] CODE` | [As the result of a request](#as-the-result-of-a-request) |
| `In <line>`, `Detail of …` or `As the cause: …` | [Inside another line](#inside-another-line) |
| `CODE: …`, then `[<status>] <broader code>` | [Named in the line before a broader code](#named-in-the-line-before-a-broader-code) |
| `Not logged by name: <line>` or `Not logged` | [Not at all](#not-at-all) |

### As the result of a request

A request that fails ends with one line that holds the HTTP status sent to the browser and the code:

```
Sat Sep 26 23:15:06 2026 user.err luci-sso[1289]: [502] OIDC_DISCOVERY_FAILED
```

The examples on this page leave out the date and priority: `luci-sso[1289]: [502] OIDC_DISCOVERY_FAILED`.

Only one code is ever written this way per request. The lines logged just before it, with the same process ID, usually say what went wrong.

### Inside another line

Many codes describe a lower-level failure. They never get a `[<status>]` line of their own. They appear in the text of another line:

| Line | Carries |
| :--- | :--- |
| `OAuth flow failed [session_id: …]: ID_TOKEN_VERIFICATION_FAILED ({ "details": "<CODE>", "http_status": 401 })` | The ID Token check that failed. See [ID Token Verification Detail Codes](#id-token-verification-detail-codes). |
| `Discovery fetch failed for [id: …]: HTTP_REQUEST_FAILED (<cause>)` | A transport failure. The same form appears in `JWKS fetch failed`, `Token exchange network error` and `UserInfo fetch network error` lines. |
| `UserInfo fallback failed [session_id: …]: <CODE>` | Why the optional UserInfo request failed. |
| `Access token registry write failed [session_id: …]: <CODE>` | Why the replay registry could not be written. |

At the callback, most failures after the handshake check also log `OAuth flow failed [session_id: …]: <CODE> ({ "http_status": <status> })` just before the `[<status>]` line. This covers discovery, token exchange, JWK Set, UserInfo identity and the replay registry. The line repeats the code and status of the `[<status>]` line. Only for `ID_TOKEN_VERIFICATION_FAILED` does it add the detail code.

A failed back-channel request to the IdP (discovery, token exchange, JWK Set) always ends as `[502]`, whatever the IdP answered. The IdP's own HTTP status is logged once, in the line that names the request, such as `Token exchange HTTP 401 [session_id: …]`. A transport failure logs its cause there instead.

### Named in the line before a broader code

Every discovery failure ends as `[502] OIDC_DISCOVERY_FAILED`. The line before it names the specific code where there is one:

```
luci-sso[1289]: DISCOVERY_ISSUER_MISMATCH: issuer_url is "https://id.example.com" but the discovery document declares "https://id.example.com/application/o/luci/" [id: 8dbb9352769748c6]
luci-sso[1289]: [502] OIDC_DISCOVERY_FAILED
```

In the same way, `MISSING_RPCD_LOGIN` and `INSECURE_RPCD_LOGIN` are named in the line before `[500] UBUS_LOGIN_FAILED`.

### Not at all

A few codes are never written. The request ends with a broader code, and a descriptive line may precede it, as the tables below say.

### Values from the IdP or the browser

Values that come from the IdP or the browser, such as the declared issuer or the IdP's `error`, are sanitized before they are logged:

- every byte outside printable ASCII becomes `?`;
- long values are cut to 200 characters (100 for endpoint URLs), followed by `...`.

### `[id: …]` values

In discovery and JWKS lines, `[id: …]` is the first 16 hex characters of the SHA-256 of the normalized URL: scheme and host in lower case, no `:443`, no trailing slash. In rate-limit lines, `[id: …]` is the same kind of hash of the client key, so no address is logged.

To check which URL an id belongs to, hash the candidate on the router:

```bash
printf '%s' 'https://id.example.com' | sha256sum | cut -c1-16
```

### Crashes

A crash is logged as `Router crash: <message>` with a stack trace, and has no code.

---

## Configuration Errors

These occur on the first request that needs the configuration.

| Code | Trigger | What it means | In the log |
| :--- | :--- | :--- | :--- |
| `SSO_DISABLED` | A login, callback or logout request arrives while `enabled` is not `1` | SSO is turned off. The `?action=enabled` probe returns `{"enabled": false}` instead and logs nothing. | `[500] SSO_DISABLED` |
| `CONFIG_ERROR` | SSO is enabled, but a required option is missing or invalid (see notes) | The configuration cannot be used. Every request fails, including the `?action=enabled` probe. | `[500] CONFIG_ERROR`, preceded by `Configuration rejected: <reason>` |
| `UCI_ERROR` | The UCI cursor could not be created | The UCI system itself is unavailable, which points to a deeper OpenWrt problem. | `[500] UCI_ERROR` |

Notes:

- `CONFIG_ERROR`: the configuration is rejected when the `default` section is missing, when `issuer_url`, `client_id`, `client_secret`, `redirect_uri`, `clock_tolerance` or `internal_issuer_url` is missing or invalid, or when no role has an email or group. The `<reason>` names the option but never its value.

---

## Discovery Errors

These occur when the router fetches the IdP's `/.well-known/openid-configuration` document or its JWK Set.

A cached copy (24 hours) is used when present. When the IdP is unreachable, an expired copy is used instead, and `Using stale discovery cache due to network failure` or `Using stale JWKS cache due to network failure` is logged.

| Code | Trigger | What it means | In the log |
| :--- | :--- | :--- | :--- |
| `OIDC_DISCOVERY_FAILED` | Any discovery failure during login or callback | The request-level code for every discovery problem below. | `[502] OIDC_DISCOVERY_FAILED`, preceded by a line naming the cause |
| `INSECURE_ISSUER_URL` | `issuer_url` does not begin with `https://` | The configuration check rejects this first, as `CONFIG_ERROR`. | Not logged |
| `INSECURE_FETCH_URL` | The split-horizon fetch URL is not HTTPS | The configuration check rejects a non-HTTPS `internal_issuer_url` first, as `CONFIG_ERROR`. | Not logged |
| `DISCOVERY_FAILED` | The discovery endpoint returned a status other than 200 | The IdP is reachable but refused the request. Check the issuer path and the IdP logs. | Not logged by name: `Discovery fetch HTTP <status> from [id: …]` |
| `DISCOVERY_NETWORK_ERROR` | The discovery request did not complete | Transport failure before any HTTP response. The cause is in parentheses. | Not logged by name: `Discovery fetch failed for [id: …]: HTTP_REQUEST_FAILED (<cause>)` |
| `INVALID_DISCOVERY_DOC` | The discovery response is not valid JSON | The IdP returned a malformed discovery document, or the URL serves something else. | Not logged by name: `Discovery JSON parse error: …` |
| `DISCOVERY_MISSING_ISSUER` | The discovery document has no `issuer` field | The IdP's discovery document is not OIDC compliant. | Not logged by name: `Discovery document missing issuer field from [id: …]` |
| `DISCOVERY_ISSUER_MISMATCH` | The document's `issuer` differs from the configured `issuer_url` after normalization | `issuer_url` is not the IdP's exact issuer identifier (see notes). | `DISCOVERY_ISSUER_MISMATCH: issuer_url is "<configured>" but the discovery document declares "<declared>" [id: …]`, then `[502] OIDC_DISCOVERY_FAILED` |
| `DISCOVERY_MISSING_ENDPOINT` | The document lacks `authorization_endpoint`, `token_endpoint` or `jwks_uri` | The IdP's discovery document is incomplete. | `DISCOVERY_MISSING_ENDPOINT: the discovery document has no <field> [id: …]`, then `[502] OIDC_DISCOVERY_FAILED` |
| `INSECURE_ENDPOINT` | One of those three endpoints is not HTTPS | The IdP advertises a plain-HTTP endpoint. `luci-sso` refuses to use it. | `INSECURE_ENDPOINT: <field> in the discovery document is not HTTPS: "<url>" [id: …]`, then `[502] OIDC_DISCOVERY_FAILED` |
| `JWKS_FETCH_FAILED` | Any JWK Set failure during the callback; also the JWKS endpoint returning a status other than 200 | The router could not get the IdP's signing keys. | `[502] JWKS_FETCH_FAILED`, preceded by a JWKS line naming the cause, such as `JWKS fetch HTTP <status> from [id: …]` |
| `JWKS_NETWORK_ERROR` | The JWKS request did not complete | Transport failure before any HTTP response. | Not logged by name: `JWKS fetch failed for [id: …]: HTTP_REQUEST_FAILED (<cause>)` |
| `INSECURE_JWKS_URI` | `jwks_uri` is not HTTPS | Discovery rejects a plain-HTTP `jwks_uri` first, as `INSECURE_ENDPOINT`. | Not logged |
| `INVALID_JWKS_FORMAT` | The JWKS response is not valid JSON or has no `keys` array | The IdP returned a malformed JWK Set. | Not logged by name: `JWKS JSON parse error: …` |

Notes:

- `DISCOVERY_ISSUER_MISMATCH`: the comparison ignores trailing slashes, letter case in the host and `:443`. It does not ignore path differences. The code can also appear as the detail of `ID_TOKEN_VERIFICATION_FAILED`.

---

## Login Initiation Errors

These occur when a login starts: the router saves the handshake and builds the authorization URL to redirect the browser to the IdP.

| Code | Trigger | What it means | In the log |
| :--- | :--- | :--- | :--- |
| `INSECURE_AUTH_ENDPOINT` | `authorization_endpoint` is not HTTPS | Discovery normally rejects this first, as `INSECURE_ENDPOINT`. | `[500] INSECURE_AUTH_ENDPOINT` |
| `INVALID_AUTH_ENDPOINT` | `authorization_endpoint` contains a fragment (`#`) | Forbidden by RFC 6749 §3.1. An IdP configuration issue. | `[500] INVALID_AUTH_ENDPOINT` |
| `MISSING_STATE_PARAMETER` | The handshake has no usable `state` | Internal error. File a bug. | `[500] MISSING_STATE_PARAMETER` |
| `MISSING_NONCE_PARAMETER` | The handshake has no usable `nonce` | Internal error. File a bug. | `[500] MISSING_NONCE_PARAMETER` |
| `MISSING_PKCE_CHALLENGE` | The handshake has no PKCE code challenge | Internal error. File a bug. | `[500] MISSING_PKCE_CHALLENGE` |
| `STATE_SAVE_FAILED` | The router could not write the handshake file when a login started | Check free space and permissions on `/var/run/luci-sso/`. | `[500] STATE_SAVE_FAILED`, preceded by `Failed to save handshake state …` |
| `HANDSHAKE_CAPACITY_EXCEEDED` | 500 logins are already in progress and none of them has expired | The new login is refused (see notes). Usually a flood of login requests. | `[503] HANDSHAKE_CAPACITY_EXCEEDED`, preceded by `Handshake capacity reached` |

Notes:

- `HANDSHAKE_CAPACITY_EXCEEDED`: logins already at the IdP are unaffected, and password login still works. Pending handshakes expire after 5 minutes.

---

## Callback Errors

These occur when the browser returns from the IdP. A failed callback is final: nothing retries it, and the user has to start again from the login page.

| Code | Trigger | What it means | In the log |
| :--- | :--- | :--- | :--- |
| `IDP_ERROR` | The callback URL has an `error` parameter | The IdP refused the authorization request, for example `access_denied` when the user cancelled or is not allowed to use the client. | `IDP_ERROR: the IdP returned error=<error> (<error_description>)`, then `[400] IDP_ERROR` |
| `MISSING_CODE` | The callback URL has no `code` parameter | The IdP redirect did not include an authorization code. | `[400] MISSING_CODE` |
| `MISSING_HANDSHAKE_COOKIE` | The request has no `__Host-luci_sso_state` cookie | The browser did not send the handshake cookie (see notes). | `[401] MISSING_HANDSHAKE_COOKIE` |
| `STATE_PARAMETER_MISMATCH` | The `state` parameter does not match the stored handshake | The callback did not come from the flow this browser started: possible CSRF, or a stale link. The handshake is kept. | `[403] STATE_PARAMETER_MISMATCH`, preceded by `Callback state does not match the handshake; handshake kept` |
| `STATE_NOT_FOUND` | No handshake file exists for the cookie | The handshake was already used (a replayed or double-submitted callback) or was removed as stale. | `[401] STATE_NOT_FOUND`, preceded by `Handshake state not found or already consumed` or `Handshake state already consumed` |
| `STATE_CORRUPTED` | The handshake file exists but its contents are invalid | A truncated write or tampering under `/var/run/luci-sso/`. The file is removed. | `[401] STATE_CORRUPTED`, preceded by a `Handshake state …` line naming the problem |
| `MALFORMED_STATE_COOKIE` | The cookie value has characters outside Base64URL | The cookie was tampered with or corrupted. | `[401] MALFORMED_STATE_COOKIE` |
| `HANDSHAKE_EXPIRED` | The handshake's `exp` is more than `clock_tolerance` seconds in the past | The handshake file outlived its 5 minutes (see notes). The file is removed. | `[401] HANDSHAKE_EXPIRED`, preceded by `Handshake state expired` |
| `HANDSHAKE_NOT_YET_VALID` | The handshake's `iat` is more than `clock_tolerance` seconds in the future | The router's clock moved backwards between the start of the login and the callback (see notes). The file is removed. | `[401] HANDSHAKE_NOT_YET_VALID`, preceded by `Handshake state not yet valid` |

Notes:

- `IDP_ERROR`: both logged values are sanitized. The page shows only a fixed message.
- `MISSING_HANDSHAKE_COOKIE`: the cookie expires 300 seconds after the login starts, so a slow login ends here. The cookie is also host-only, so it is missing when the login started on a different host name than the one in `redirect_uri`.
- `STATE_PARAMETER_MISMATCH`: because the handshake is kept, the matching callback can still complete.
- `HANDSHAKE_EXPIRED`: the browser normally drops the cookie first, so this is rare. It points to the router's clock jumping forward during the login, for example at the first NTP sync after boot.
- `HANDSHAKE_NOT_YET_VALID`: the handshake was written by this router, so only the router's clock matters. The browser's clock plays no part.

---

## Token Exchange Errors

These occur during the back-channel request from the router to the IdP's token endpoint.

| Code | Trigger | What it means | In the log |
| :--- | :--- | :--- | :--- |
| `INSECURE_TOKEN_ENDPOINT` | The token endpoint URL is not HTTPS | Discovery normally rejects this first, as `INSECURE_ENDPOINT`. | `[500] INSECURE_TOKEN_ENDPOINT` |
| `INVALID_PKCE_VERIFIER` | The stored PKCE verifier is not 43–128 characters | Internal error. File a bug. | `[500] INVALID_PKCE_VERIFIER`, preceded by `Rejected token exchange …` |
| `TOKEN_ENDPOINT_NETWORK_ERROR` | The token request did not complete | Transport failure on the router-to-IdP back channel. The cause is in parentheses. | `[502] TOKEN_ENDPOINT_NETWORK_ERROR`, preceded by `Token exchange network error [session_id: …]: HTTP_REQUEST_FAILED (<cause>)` |
| `OIDC_INVALID_GRANT` | The token endpoint answered `invalid_grant` | The authorization code was already used or expired, the PKCE verifier is wrong, or `redirect_uri` does not match the one registered. The page asks the user to sign in again. | `[502] OIDC_INVALID_GRANT`, preceded by `Token exchange failed (invalid_grant, HTTP <status>)` |
| `TOKEN_EXCHANGE_FAILED` | The token endpoint returned any other status than 200 | The IdP rejected the request, often because of a wrong client secret or a public client. Check the IdP logs. | `[502] TOKEN_EXCHANGE_FAILED`, preceded by `Token exchange HTTP <status>` with the token endpoint's status |
| `TOKEN_RESPONSE_INVALID_JSON` | The token response is not valid JSON | The IdP returned a malformed token response. | `[502] TOKEN_RESPONSE_INVALID_JSON`, preceded by `Token exchange JSON parse error …` |

---

## Token Validation Errors

These occur while validating the ID Token returned by the IdP. Only `ID_TOKEN_VERIFICATION_FAILED` is logged as the result of the request. The other codes in this table are its detail.

| Code | Trigger | What it means | In the log |
| :--- | :--- | :--- | :--- |
| `ID_TOKEN_VERIFICATION_FAILED` | The ID Token failed any validation step: signature (even after a JWK Set refresh), claims, or key conversion | The request-level code for every ID Token problem. | `[401] ID_TOKEN_VERIFICATION_FAILED`, preceded by `OAuth flow failed [session_id: …]: ID_TOKEN_VERIFICATION_FAILED ({ "details": "<CODE>", "http_status": 401 })` |
| `MISSING_ID_TOKEN` | The token response has no `id_token` | The IdP did not issue an ID Token. Plain OAuth 2.0 services, such as GitHub, do this. | Detail of `ID_TOKEN_VERIFICATION_FAILED` |
| `UNSUPPORTED_ALGORITHM` | The ID Token `alg` is not `RS256` or `ES256` | Configure the IdP to sign with RS256 or ES256. Symmetric algorithms (HS256) are rejected on purpose. | Detail of `ID_TOKEN_VERIFICATION_FAILED` |
| `INVALID_SIGNATURE` | The signature does not verify | See notes. | Detail of `ID_TOKEN_VERIFICATION_FAILED` |
| `MISSING_SUB_CLAIM` | The ID Token has no `sub` claim | The user identifier is missing. Required by OIDC Core. | Detail of `ID_TOKEN_VERIFICATION_FAILED`, or in `UserInfo fallback failed` |
| `MISSING_EXP_CLAIM` | The ID Token has no `exp` claim | Required by OIDC Core. | Detail of `ID_TOKEN_VERIFICATION_FAILED` |
| `MISSING_IAT_CLAIM` | The ID Token has no `iat` claim | Required by OIDC Core. | Detail of `ID_TOKEN_VERIFICATION_FAILED` |
| `MISSING_NONCE` | The ID Token has no `nonce` claim, or the handshake has no nonce | Replay protection requires a nonce. | Detail of `ID_TOKEN_VERIFICATION_FAILED` |
| `NONCE_MISMATCH` | The `nonce` claim does not match the handshake | The token was not issued for this login. Possible replay or token substitution. | Detail of `ID_TOKEN_VERIFICATION_FAILED` |
| `MISSING_AZP_CLAIM` | The ID Token has several `aud` values but no `azp` | OIDC Core requires `azp` in that case. An IdP configuration issue. | Detail of `ID_TOKEN_VERIFICATION_FAILED` |
| `AZP_MISMATCH` | `azp` does not equal the configured `client_id` | The token was issued for a different client. | Detail of `ID_TOKEN_VERIFICATION_FAILED` |
| `MISSING_ACCESS_TOKEN` | The token response has no `access_token` | `luci-sso` needs the access token to check `at_hash` when present and to register the login against replay. | Detail of `ID_TOKEN_VERIFICATION_FAILED` |
| `AT_HASH_MISMATCH` | The ID Token has an `at_hash` that does not match the access token, or is empty or not a string | The access token was substituted, or the IdP computed `at_hash` wrongly. An ID Token without `at_hash` is accepted. | Detail of `ID_TOKEN_VERIFICATION_FAILED` |

Notes:

- `INVALID_SIGNATURE`: when the token names a key (`kid`), the JWK Set is first fetched again and the check retried. That retry logs `Unrecognized or stale key detected …; forcing JWKS refresh`.

---

## ID Token Verification Detail Codes

These never reach the browser and never get a `[<status>]` line. They appear only as the `details` of the `OAuth flow failed` line and name the exact check that failed:

```
luci-sso[1234]: OAuth flow failed [session_id: 1a2b...]: ID_TOKEN_VERIFICATION_FAILED ({ "details": "TOKEN_EXPIRED", "http_status": 401 })
luci-sso[1234]: [401] ID_TOKEN_VERIFICATION_FAILED
```

Codes from the [Token Validation Errors](#token-validation-errors) table can also appear here, as can `DISCOVERY_ISSUER_MISMATCH` (when the cached discovery document's issuer no longer matches) and `CRYPTO_ERROR`.

The tables below have no **In the log** column: every code in them is logged only as the detail of `ID_TOKEN_VERIFICATION_FAILED`.

### Token format

The ID Token is not a well-formed compact JWS.

| Code | Trigger | What it means |
| :--- | :--- | :--- |
| `INVALID_JWT_HEADER` | The ID Token's first segment is not Base64URL-encoded JSON | The IdP returned a malformed token. |
| `TOKEN_TOO_LARGE` | The ID Token exceeds 16 KB | Rejected before parsing as a hardening measure. An IdP stuffing very large claims into the token can trigger it. |
| `MALFORMED_JWT` | The ID Token does not have exactly three dot-separated segments | The IdP returned something that is not a compact JWS. |
| `INVALID_PAYLOAD_ENCODING` | The ID Token payload segment is not valid Base64URL | Malformed token from the IdP. |
| `INVALID_SIGNATURE_ENCODING` | The ID Token signature segment is empty or not valid Base64URL | Malformed token from the IdP. |
| `INVALID_PAYLOAD_JSON` | The ID Token payload is not valid JSON | Malformed token from the IdP. |

### Signing key

The router could not find or use the key that signed the token.

| Code | Trigger | What it means |
| :--- | :--- | :--- |
| `NO_KEYS_AVAILABLE` | The token has no `kid` header and the JWK Set is empty | The IdP publishes no signing keys at its `jwks_uri`. |
| `KEY_NOT_FOUND` | No key in the JWK Set has the token's `kid`, even after a forced refresh | The IdP signed with a key it does not publish (see notes). |
| `MISSING_KTY` | The selected JWK has no `kty` field | The IdP's JWK Set is malformed. |
| `UNSUPPORTED_KTY` | The selected JWK's `kty` is not `RSA` or `EC` | The IdP uses a key type `luci-sso` cannot verify (see notes). |
| `MISSING_RSA_PARAMS` | An `RSA` JWK lacks `n` or `e` | The IdP's JWK Set is malformed. |
| `INVALID_RSA_PARAMS_ENCODING` | An `RSA` JWK's `n` or `e` is not valid Base64URL | The IdP's JWK Set is malformed. |
| `UNSUPPORTED_CURVE` | An `EC` JWK uses a curve other than `P-256` | Only ES256 (P-256) is supported. Configure the IdP to sign with P-256 or RS256. |
| `MISSING_EC_PARAMS` | An `EC` JWK lacks `x` or `y` | The IdP's JWK Set is malformed. |
| `INVALID_EC_PARAMS_ENCODING` | An `EC` JWK's `x` or `y` is not valid Base64URL | The IdP's JWK Set is malformed. |
| `PEM_CONVERSION_FAILED` | The native crypto bridge rejected the key | The key has a value the bridge refuses (see notes). |

Notes:

- `KEY_NOT_FOUND`: usually a key rotation that has not propagated. Retry, then check the IdP's `jwks_uri`.
- `UNSUPPORTED_KTY`: symmetric (`oct`) keys are refused. ID tokens must be signed with RS256 or ES256.
- `PEM_CONVERSION_FAILED`: the bridge refuses an RSA exponent other than 65537, an RSA modulus over 16 KB, or an EC point that is not on the P-256 curve. RSA keys under 2048 bits are rejected later, at signature verification, and surface as `INVALID_SIGNATURE`.

### Time claims

The token's `exp`, `nbf` or `iat` is malformed, or out of range once `clock_tolerance` is applied.

| Code | Trigger | What it means |
| :--- | :--- | :--- |
| `INVALID_EXP_CLAIM` | `exp` is present but not an integer | The IdP issued a non-compliant token. |
| `TOKEN_EXPIRED` | `exp` is earlier than now minus `clock_tolerance` | The token had already expired when it arrived. Check NTP on the router and the IdP. |
| `INVALID_NBF_CLAIM` | `nbf` is present but not an integer | The IdP issued a non-compliant token. |
| `TOKEN_NOT_YET_VALID` | `nbf` is later than now plus `clock_tolerance` | The router clock is behind the IdP. Check NTP synchronization. |
| `INVALID_IAT_CLAIM` | `iat` is present but not an integer | The IdP issued a non-compliant token. |
| `TOKEN_ISSUED_IN_FUTURE` | `iat` is later than now plus `clock_tolerance` | The router clock is behind the IdP. Check NTP synchronization. |

### Issuer, audience and access token

The token was issued by or for someone else, or the access token needed to check `at_hash` is unusable.

| Code | Trigger | What it means |
| :--- | :--- | :--- |
| `ISSUER_MISMATCH` | The token's `iss` claim does not match the configured `issuer_url` | The token was issued by a different issuer. Verify `issuer_url` matches the IdP's issuer identifier exactly. |
| `INVALID_AUDIENCE` | `aud` is an empty array | The IdP issued a non-compliant token. |
| `MALFORMED_AUDIENCE` | An element of the `aud` array is not a string | The IdP issued a non-compliant token. |
| `AUDIENCE_MISMATCH` | No `aud` value equals the configured `client_id` | The token was issued for a different client. Check `client_id`. |
| `INVALID_ARGUMENT` | The ID Token has `at_hash`, and the access token in the token response is not a string, so the hash cannot be computed | The IdP returned a malformed token response. |

---

## UserInfo Errors

These occur only when the ID Token has no `email` claim. The router then asks the IdP's UserInfo endpoint for the email, and for `name` and `groups` if the ID Token lacks them.

A failure here does not stop the login. It is logged as a warning, and the login continues with the ID Token's claims alone. When roles match by email, that usually ends in `USER_NOT_AUTHORIZED`. `IDENTITY_MISMATCH` is the exception: it refuses the login.

| Code | Trigger | What it means | In the log |
| :--- | :--- | :--- | :--- |
| `INSECURE_USERINFO_ENDPOINT` | The UserInfo endpoint is not HTTPS | Discovery drops a plain-HTTP UserInfo endpoint first and logs `Insecure userinfo_endpoint ignored`. | In `UserInfo fallback failed [session_id: …]: <CODE>` |
| `USERINFO_FETCH_FAILED` | The UserInfo endpoint returned a status other than 200 | The IdP rejected the request. Usually a scope or permission issue. | In `UserInfo fallback failed`, preceded by `UserInfo fetch HTTP <status>` |
| `USERINFO_NETWORK_ERROR` | The UserInfo request did not complete | Transport failure before any HTTP response. | In `UserInfo fallback failed`, preceded by `UserInfo fetch network error: HTTP_REQUEST_FAILED (<cause>)` |
| `USERINFO_INVALID_JSON` | The UserInfo response is not valid JSON | The IdP returned a malformed UserInfo response. | In `UserInfo fallback failed`, preceded by `UserInfo JSON parse error: …` |
| `IDENTITY_MISMATCH` | The UserInfo `sub` differs from the ID Token `sub` | The IdP returned claims for a different subject. The login is refused. | `[403] IDENTITY_MISMATCH`, preceded by `UserInfo 'sub' mismatch` |

---

## Authorization Errors

These occur after token validation, when mapping the user's identity to a LuCI role, and at logout.

| Code | Trigger | What it means | In the log |
| :--- | :--- | :--- | :--- |
| `USER_NOT_AUTHORIZED` | The user's email and groups match no `config role` section | The user has no role (see notes). | `[403] USER_NOT_AUTHORIZED`, preceded by `User [sub_id: …] matched no roles` |
| `TOKEN_REPLAYED` | The access token is already in the local replay-protection registry | A previously used token was submitted again: a replay attack, or an IdP that reissues access tokens. | `[403] TOKEN_REPLAYED`, preceded by `Replay attack detected: access token already registered` |
| `TOKEN_REGISTRY_ERROR` | The router could not write the access token to the replay-protection registry | Check free space and permissions on `/var/run/luci-sso/tokens/`. | `[500] TOKEN_REGISTRY_ERROR`, preceded by `Access token registry write failed [session_id: …]: <CODE>` naming `INVALID_TOKEN`, `SYSTEM_ERROR` or `CRYPTO_ERROR` |
| `INVALID_TOKEN` | The access token to register is missing or not a string | The IdP's token response has no usable `access_token`. | In `Access token registry write failed` |
| `SYSTEM_ERROR` | Creating the registry entry raised an exception | A filesystem failure under `/var/run/luci-sso/tokens/`. | In `Access token registry write failed`, with the exception text on an earlier `Exception in register_token` line |
| `CSRF_CHECK_FAILED` | A logout request has a missing or wrong `stoken` parameter | Possible CSRF attack on the logout endpoint, or a logout link from another session. | `[403] CSRF_CHECK_FAILED`, preceded by `Logout attempt with invalid or missing CSRF token` |

Notes:

- `USER_NOT_AUTHORIZED`: a role whose permissions grant nothing does not cause it; its users log in and see nothing. Claim values are never logged. The debug line `ID Token verified. Claims present: …` lists the claim names the IdP sent.

---

## Session Errors

These occur when creating the LuCI session through `rpcd` after successful authorization. `rpcd` is the OpenWrt daemon that holds LuCI sessions. The router reaches it over ubus, OpenWrt's local message bus.

Only `UBUS_LOGIN_FAILED` is logged as the result of the request.

| Code | Trigger | What it means | In the log |
| :--- | :--- | :--- | :--- |
| `UBUS_LOGIN_FAILED` | The session could not be created, granted or labelled, or the role's `rpcd` login entry is refused | Check the line before it. For the session lines, check that `rpcd` is running and that `/usr/share/rpcd/acl.d/` is readable. | `[500] UBUS_LOGIN_FAILED`, preceded by a `MISSING_RPCD_LOGIN` or `INSECURE_RPCD_LOGIN` line, `UBUS session creation failed`, `Failed to load LuCI ACLs for role`, `UBUS session set failed` or `CRITICAL: CSPRNG failure during CSRF token generation` |
| `UBUS_CONNECT_FAILED` | The router could not connect to the ubus socket | `ubusd` is not running or the socket is inaccessible. | Not logged by name: `UBUS session creation failed`, then `[500] UBUS_LOGIN_FAILED` |
| `UBUS_ERROR` | A ubus call reached `rpcd` but was rejected | Usually `rpcd`'s `session` object refused the call. | Not logged by name |
| `UBUS_SESSION_FAILED` | Creating, granting or labelling the session failed | `rpcd` did not create the session, the ACL files could not be read, or the session variables could not be set. | Not logged by name: one of the lines listed under `UBUS_LOGIN_FAILED` |
| `MISSING_RPCD_LOGIN` | The matched role has no usable `rpcd` login entry: no section `luci_sso_<role>` of type `login` with `username` `sso:<role>` | The role's permissions are missing, so no session is created. Save the role's permissions on the settings page, or with `ubus call luci-sso set_role`. | `MISSING_RPCD_LOGIN: role '<role>' has no rpcd login entry 'luci_sso_<role>' with username 'sso:<role>'`, then `[500] UBUS_LOGIN_FAILED` |
| `INSECURE_RPCD_LOGIN` | The role's `rpcd` login entry has a `password` option | The entry could be used for a password login, so no session is created. Remove the option. | `INSECURE_RPCD_LOGIN: rpcd login entry 'luci_sso_<role>' of role '<role>' has a password option; remove it`, then `[500] UBUS_LOGIN_FAILED` |

---

## Role Lines

Lines about roles and their `rpcd` login entries that carry no error code of their own.

### At login and on configuration load

Logged by the CGI script under `luci-sso[<pid>]`.

| Line | Level | When |
| :--- | :--- | :--- |
| `User [sub_id: …] mapped to role '<role>' [session_id: …]` | info | The user got `<role>`. When other roles matched too, the line reads `mapped to role '<role>', the first match; also matched: <role>, <role>`. |
| `Successful Passwordless SSO login for [oidc_id: …] mapped to sso:<role>` | info | The session was created with the role's rights. |
| `Role '<role>' grants unknown access group '<name>'; no ACL file defines it` | warn | A plain name in the entry's `read` or `write` list matches no access group. It grants nothing. Globs and negations are not checked. |
| `Ignoring read/write on role '<role>': its permissions are the rpcd login entry 'luci_sso_<role>'` | warn | The role in `/etc/config/luci-sso` still has `read` or `write` options, which grant nothing. |
| `Ignoring role '<role>': missing email or group list` | warn | The role has neither an `email` nor a `group` value. |

### At install, upgrade and removal

Logged by the package's scripts with `logger -t luci-sso -p user.warn`, so they appear under `luci-sso:` without a process ID, and printed on the package manager's output. The install and upgrade script is `/etc/uci-defaults/20-luci-sso-rpcd`; the removal lines come from the package's pre-removal script.

| Line | When | What to do |
| :--- | :--- | :--- |
| `role '<role>' keeps its read/write lists and has no rpcd login entry: <reason>; save its permissions on the settings page` | Install or upgrade. The role's old `read`/`write` lists break the entry's rules: the name is invalid or too long, or a list is invalid or denies `unauthenticated`. | The role's users cannot log in. Fix the role and save its permissions. The line comes back on every upgrade until then. |
| `role '<role>' has no rpcd login entry: <reason>; its users cannot log in` | Install or upgrade. A role without lists or entry has a name the entry cannot use. | Rename the role (letters, digits and underscores, at most 32). The line comes back on every upgrade until then. |
| `role '<role>' had no permissions to move: its rpcd login entry grants nothing but 'unauthenticated'; set its permissions on the settings page` | Install or upgrade. The role had no lists and no entry, and is not the untouched shipped `admin` role. | Its users log in and see nothing. Set its permissions. |
| `rpcd section 'luci_sso_<name>' has no luci-sso role to keep its permissions; deleted` | Removal. An entry has no role in `/etc/config/luci-sso`, or is not a login. | None. Its lists are gone. |
| `could not write /etc/config/luci-sso: the rpcd login entries are kept` | Removal. The roles' permissions could not be saved back. | The `luci_sso_*` entries stay in `/etc/config/rpcd`. |

---

## System Errors

These indicate infrastructure-level failures unrelated to a specific OIDC step: transport, crypto, rate limits and input size.

| Code | Trigger | What it means | In the log |
| :--- | :--- | :--- | :--- |
| `HTTPS_REQUIRED` | A back-channel request was attempted to a non-HTTPS URL | Normally unreachable, because every endpoint is HTTPS-checked earlier. | In a `Discovery fetch failed`, `JWKS fetch failed`, `Token exchange network error` or `UserInfo fetch network error` line |
| `HTTP_REQUEST_FAILED` | A back-channel HTTPS request did not complete | Followed by the cause in parentheses (see notes). | In the same lines as `HTTPS_REQUIRED` |
| `SSL_INIT_FAILED` | TLS could not be set up before connecting | The TLS library or the system CA store is missing. An untrusted IdP certificate is reported as `CERT_UNTRUSTED` instead. | As the cause: `HTTP_REQUEST_FAILED (SSL_INIT_FAILED)` |
| `CRYPTO_ERROR` | A native hash operation returned no result | Internal error in the native crypto bridge. | In `Access token registry write failed`, or as the detail of `ID_TOKEN_VERIFICATION_FAILED` |
| `CRYPTO_INIT_FAILED` | The random number generator (CSPRNG) returned no data or too little | The crypto backend could not produce random bytes. | At login: `[500] CRYPTO_INIT_FAILED`, preceded by `CRITICAL: CSPRNG failure during handshake state generation` (see notes) |
| `TOO_MANY_REQUESTS` | One client exceeded a per-client budget: 10 login initiations in 5 minutes, or 30 requests in a minute | Other clients are unaffected. Usually automated scanning or a client retrying in a loop. | `[429] TOO_MANY_REQUESTS`, preceded by `Login rate limit exceeded` or `Request rate limit exceeded` with the budget and a hashed client id |
| `INPUT_TOO_LARGE` | The query string, cookies or an environment variable exceeds 16 KB, or there are more than 100 parameters or cookies | The request exceeded the hard input limit. | `[431] INPUT_TOO_LARGE` |
| `NOT_FOUND` | The request path is not `/`, `/callback` or `/logout` | The browser or a client asked for an unknown path under the CGI script. | `[404] NOT_FOUND` |

Notes:

- `HTTP_REQUEST_FAILED`: the cause is one of `CONNECT_NOT_STARTED`, `CONNECTION_FAILED`, `TIMED_OUT`, `CERT_UNTRUSTED`, `CERT_NAME_MISMATCH`, `SSL_INIT_FAILED`, `RESPONSE_TOO_LARGE`, `UCLIENT_ERROR_<n>`, or, rarely, `REQUEST_START_FAILED`, `UCLIENT_ALLOC_FAILED` or `INVALID_DATA_TYPE`. See [How to Debug luci-sso](../how-to/sysadmin/debugging.md#a-back-channel-request-to-the-idp-failed) for what each means.
- `CRYPTO_INIT_FAILED`: this can happen with any backend (mbedtls, wolfssl or openssl). At the callback, the same failure ends as `[500] UBUS_LOGIN_FAILED`.
