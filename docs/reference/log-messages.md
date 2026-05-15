# Log Messages and Error Codes

All `luci-sso` events are written to the system log.

=== "Browser (LuCI)"

    Navigate to **Status > System Log** and filter for `luci-sso`.

=== "Terminal (SSH)"

    ```bash
    logread -e luci-sso
    ```

Each error code entry follows this structure:

```
luci-sso[<pid>]: [<http-status>] <CODE>
```

For example:

```
luci-sso[1234]: [503] SSO_DISABLED
```

Some codes are preceded by a diagnostic line that provides additional context; those cases are noted in the Description column. The tables below describe every code, what triggers it, and what it indicates. For steps to resolve common errors, see [How to Debug luci-sso](../how-to/sysadmin/debugging.md). For the HTTP endpoints that produce these codes, see the [HTTP API Reference](http-api.md).

---

## Configuration Errors

These occur before any OIDC flow begins, during startup or on the first request.

| Code | Trigger | What it means |
| :--- | :--- | :--- |
| `SSO_DISABLED` | `enabled` option is not `1` in UCI, or no valid configuration exists when a request arrives | The `enabled` option is not set to `1` in the UCI configuration, or no valid configuration exists. |
| `CONFIG_ERROR` | `issuer_url`, `client_id`, `client_secret`, or `clock_tolerance` is missing or invalid | Required UCI option is absent or malformed. Check `uci show luci-sso`. |
| `UCI_ERROR` | UCI cursor could not be created | The UCI system itself is unavailable — indicates a deeper OpenWrt system problem. |

---

## Discovery Errors

These occur when the router fetches the IdP's `/.well-known/openid-configuration` document.

| Code | Trigger | What it means |
| :--- | :--- | :--- |
| `INSECURE_ISSUER_URL` | `issuer_url` does not begin with `https://` | The configured issuer URL uses HTTP. All OIDC endpoints must use HTTPS. |
| `INSECURE_FETCH_URL` | `internal_issuer_url` does not begin with `https://` | The split-horizon fetch URL uses HTTP. Must be HTTPS even for internal addresses. |
| `OIDC_DISCOVERY_FAILED` | Router cannot reach `<issuer_url>/.well-known/openid-configuration` | DNS resolution or network connectivity failure between router and IdP. Check firewall rules. |
| `DISCOVERY_FAILED` | Discovery endpoint returned a non-200 HTTP status | IdP is reachable but returned an error. Check IdP logs. |
| `DISCOVERY_NETWORK_ERROR` | TCP/DNS failure during the discovery document fetch | Low-level transport failure before any HTTP response was received. |
| `INVALID_DISCOVERY_DOC` | Discovery response is not valid JSON | IdP returned a malformed discovery document. |
| `DISCOVERY_MISSING_ISSUER` | Discovery document does not contain an `issuer` field | IdP's discovery document is incomplete — not OIDC Core 1.0 compliant. |
| `DISCOVERY_ISSUER_MISMATCH` | `issuer` in discovery document does not match configured `issuer_url` | The IdP's declared issuer differs from what was configured. Verify `issuer_url` exactly matches the IdP's issuer identifier. |
| `DISCOVERY_MISSING_ENDPOINT` | Discovery document is missing `authorization_endpoint`, `token_endpoint`, or `jwks_uri` | IdP's discovery document is incomplete. |
| `INSECURE_ENDPOINT` | A required endpoint URL in the discovery document uses HTTP | IdP is advertising non-HTTPS endpoints. `luci-sso` refuses to proceed. |
| `JWKS_FETCH_FAILED` | JWKS endpoint returned a non-200 HTTP status | IdP rejected the JWKS request. Check IdP logs. |
| `JWKS_NETWORK_ERROR` | TCP/DNS failure during the JWKS fetch | Low-level transport failure before any HTTP response was received. |
| `INSECURE_JWKS_URI` | `jwks_uri` from discovery document uses HTTP | IdP is advertising an insecure JWK Set endpoint. |
| `INVALID_JWKS_FORMAT` | JWKS response is not valid JSON or missing the `keys` array | IdP returned a malformed JWK Set. |

---

## Login Initiation Errors

These occur when the router builds the authorization URL to redirect the browser to the IdP.

| Code | Trigger | What it means |
| :--- | :--- | :--- |
| `INSECURE_AUTH_ENDPOINT` | `authorization_endpoint` from discovery document uses HTTP | IdP is advertising a non-HTTPS authorization endpoint. `luci-sso` refuses to redirect. |
| `INVALID_AUTH_ENDPOINT` | `authorization_endpoint` contains a fragment (`#`) | The authorization URL has an illegal fragment component per RFC 6749 §3.1. IdP configuration issue. |
| `MISSING_STATE_PARAMETER` | PKCE state was not generated before building the auth URL | Internal error: handshake state is incomplete. File a bug. |
| `MISSING_NONCE_PARAMETER` | Nonce was not generated before building the auth URL | Internal error: handshake state is incomplete. File a bug. |
| `MISSING_PKCE_CHALLENGE` | PKCE code challenge was not generated before building the auth URL | Internal error: handshake state is incomplete. File a bug. |

---

## Callback Errors

These occur when the browser returns from the IdP with an authorization code.

| Code | Trigger | What it means |
| :--- | :--- | :--- |
| `IDP_ERROR` | IdP returned an `error` parameter in the callback URL | The IdP explicitly rejected the authorization request. The error value (e.g. `access_denied`) is logged alongside this code. |
| `MISSING_CODE` | Callback URL contains no `code` parameter | IdP redirect did not include an authorization code. |
| `MISSING_HANDSHAKE_COOKIE` | `__Host-luci_sso_state` cookie is absent from the request | Browser did not send the handshake state cookie. Usually means the browser blocked the cookie (check `SameSite`/`Secure` requirements) or the session timed out. |
| `STATE_PARAMETER_MISMATCH` | `state` parameter does not match the stored handshake state | Possible CSRF attempt, or the user completed the flow in a different browser tab. |
| `STATE_NOT_FOUND` | Handshake state file does not exist on the router filesystem | State was already consumed (replay attempt) or expired and was cleaned up. |
| `STATE_CORRUPTED` | Handshake state file exists but contains invalid data | Filesystem corruption or truncated write during state creation. |
| `STATE_SAVE_FAILED` | Router could not write the handshake state file | Check disk space and write permissions on `/var/run/luci-sso/`. |
| `MALFORMED_STATE_COOKIE` | State cookie value contains characters outside Base64URL | Cookie was tampered with or corrupted in transit. |
| `HANDSHAKE_EXPIRED` | State cookie is valid but the 5-minute handshake window elapsed | User took too long to complete the IdP login. Normal; the browser will restart the flow on the next attempt. |
| `HANDSHAKE_NOT_YET_VALID` | State cookie `iat` is in the future beyond the configured clock tolerance | Router clock is ahead of the client by more than `clock_tolerance`. Check NTP synchronization. |
| `HANDSHAKE_CAPACITY_EXCEEDED` | More than 100 concurrent in-flight handshakes exist and emergency reap did not free enough space | Likely a denial-of-service flood. Check the rate limiter and inspect `/var/run/luci-sso/` for stale handshake files. |

---

## Token Exchange Errors

These occur during the back-channel request from the router to the IdP's token endpoint.

| Code | Trigger | What it means |
| :--- | :--- | :--- |
| `INSECURE_TOKEN_ENDPOINT` | Token endpoint URL uses HTTP | IdP is advertising a non-HTTPS token endpoint. |
| `INVALID_PKCE_VERIFIER` | PKCE code verifier length is outside the 43–128 character range | Internal error: the PKCE verifier generated during login initiation is malformed. File a bug. |
| `TOKEN_ENDPOINT_NETWORK_ERROR` | TCP/DNS failure on the back-channel request to the token endpoint | Network or DNS failure on the router-to-IdP back channel. |
| `OIDC_INVALID_GRANT` | IdP returned `invalid_grant` | The authorization code was already used, expired, or the PKCE verifier is wrong. Codes are single-use. |
| `TOKEN_EXCHANGE_FAILED` | Token endpoint returned a non-200 HTTP status | IdP rejected the token exchange request. Check IdP logs for the specific reason. |
| `TOKEN_RESPONSE_INVALID_JSON` | Token endpoint response is not valid JSON | IdP returned a malformed token response. |

---

## Token Validation Errors

These occur while validating the ID Token returned by the IdP.

| Code | Trigger | What it means |
| :--- | :--- | :--- |
| `MISSING_ID_TOKEN` | Token endpoint response does not include an `id_token` field | IdP returned a token response without an ID Token. The IdP must include `id_token` in the authorization code flow response. |
| `UNSUPPORTED_ALGORITHM` | ID Token `alg` header is not `RS256` or `ES256` | The IdP signed the token with an unsupported algorithm. Configure the IdP to use RS256 or ES256. Symmetric algorithms (HS256) are intentionally rejected. |
| `INVALID_SIGNATURE` | JWT signature verification failed | The token's cryptographic signature is invalid. Triggers an automatic JWKS refresh and retry; if it fails again, `ID_TOKEN_VERIFICATION_FAILED` is emitted. |
| `ID_TOKEN_VERIFICATION_FAILED` | Signature verification failed even after refreshing the JWK Set | The token cannot be verified with any of the IdP's published public keys. |
| `MISSING_SUB_CLAIM` | ID Token has no `sub` (subject) claim | Token is missing the user identifier. Required by OIDC Core. |
| `MISSING_EXP_CLAIM` | ID Token has no `exp` (expiration) claim | Token is missing expiration. Required by OIDC Core. |
| `MISSING_IAT_CLAIM` | ID Token has no `iat` (issued at) claim | Token is missing issue time. Required by OIDC Core. |
| `MISSING_NONCE` | ID Token has no `nonce` claim, or handshake has no nonce | Replay protection requires a nonce. Token or handshake state is malformed. |
| `NONCE_MISMATCH` | `nonce` in ID Token does not match the handshake nonce | Token was not issued for this specific flow. Possible replay or token substitution. |
| `MISSING_AZP_CLAIM` | ID Token has multiple `aud` values but no `azp` claim | OIDC Core requires `azp` when there are multiple audiences. IdP configuration issue. |
| `AZP_MISMATCH` | `azp` claim does not match the configured `client_id` | Token was issued for a different client. |
| `MISSING_ACCESS_TOKEN` | Token endpoint response does not include an `access_token` field | The IdP returned an ID Token but no access token. `luci-sso` requires an access token to verify `at_hash` binding. |
| `MISSING_AT_HASH` | ID Token has no `at_hash` claim | Access token binding is mandatory. IdP must include `at_hash` when issuing ID Tokens with an access token. |
| `AT_HASH_MISMATCH` | `at_hash` does not match the hash of the access token | The access token has been substituted. Token binding violation. |

---

## UserInfo Errors

These occur during the optional UserInfo endpoint request (used to fetch group claims).

| Code | Trigger | What it means |
| :--- | :--- | :--- |
| `INSECURE_USERINFO_ENDPOINT` | UserInfo endpoint URL uses HTTP | IdP advertising a non-HTTPS UserInfo endpoint. |
| `USERINFO_FETCH_FAILED` | UserInfo endpoint returned a non-200 status | IdP rejected the UserInfo request. Usually a scope or permission issue. |
| `USERINFO_NETWORK_ERROR` | TCP/DNS failure fetching the UserInfo endpoint | Low-level transport failure before any HTTP response was received. |
| `USERINFO_INVALID_JSON` | UserInfo response is not valid JSON | IdP returned a malformed UserInfo response. |
| `IDENTITY_MISMATCH` | `sub` claim in UserInfo response differs from `sub` in the ID Token | IdP returned user info for a different subject. Indicates an IdP configuration error. |

---

## Authorization Errors

These occur after token validation, when mapping the user's identity to a LuCI role.

| Code | Trigger | What it means |
| :--- | :--- | :--- |
| `USER_NOT_AUTHORIZED` | User's email and groups match no configured `config role` section, **or** a matching role exists but has no `read` or `write` permissions defined | The user's identity matched no role, or the matched role defines no permissions. The log line immediately preceding this code identifies which condition was triggered. |
| `TOKEN_REPLAYED` | The access token is already present in the local replay-protection registry | A previously used token was submitted again. This is either a replay attack or the user completed two logins with the same token. |
| `TOKEN_REGISTRY_ERROR` | The router could not write the access token to the local replay-protection registry | Check disk space and write permissions on `/var/run/luci-sso/tokens/`. |
| `CSRF_CHECK_FAILED` | Logout request is missing or has an invalid `stoken` CSRF parameter | Possible CSRF attack on the logout endpoint, or an expired/replayed logout link. |

---

## Session Errors

These occur when creating the LuCI session via UBUS after successful authorization.

| Code | Trigger | What it means |
| :--- | :--- | :--- |
| `UBUS_LOGIN_FAILED` | UBUS session creation returned an error | LuCI's session manager rejected the login. Check that `rpcd` and `uhttpd` are running. |
| `UBUS_CONNECT_FAILED` | Router could not connect to the UBUS socket | `ubusd` is not running or the socket path is inaccessible. |
| `UBUS_ERROR` | A UBUS method call returned null | UBUS call failed at the transport level. |
| `UBUS_SESSION_FAILED` | Session grant injection failed | UBUS session was created but ACL injection failed. Check `rpcd` permissions. |

---

## System Errors

These indicate infrastructure-level failures unrelated to the OIDC flow.

| Code | Trigger | What it means |
| :--- | :--- | :--- |
| `SYSTEM_INIT_FAILED` | Secret key subsystem failed during the first login attempt — covers key generation failures, write failures, and lock-wait timeouts | The secret key subsystem failed on first use. A `CRITICAL:` diagnostic line immediately precedes this code in the log, identifying the specific cause (e.g. `Failed to write secret key`, `CSPRNG failure`). |
| `SSL_INIT_FAILED` | TLS initialization failed | TLS context initialization failed. The system CA certificate store is missing or inaccessible. |
| `CRYPTO_ERROR` | A cryptographic operation returned an unexpected error | Internal error in the native C crypto bridge. |
| `CRYPTO_INIT_FAILED` | The PSA Crypto subsystem failed to initialize | MbedTLS PSA layer unavailable. May indicate a missing `mbedtls` package. |
| `TOO_MANY_REQUESTS` | More than 50 requests in a 60-second window across all sources (global counter) | Rate limit hit. Indicates automated scanning or a misconfigured client retrying rapidly. |
| `INPUT_TOO_LARGE` | Query string, cookies, or environment variable exceeds 16 KB | Request exceeded the hard input limit. Rejects excessively large inputs as a hardening measure. |
| `NOT_FOUND` | Request path is not `/`, `/callback`, or `/logout` | The browser or a client hit an unrecognized path under the CGI script. |

