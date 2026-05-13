# Log Messages and Error Codes

All `luci-sso` events are written to the system log. Read them with:

```bash
logread -e luci-sso
```

Each log entry contains an error code in `SCREAMING_SNAKE_CASE`. The tables below describe every code, what triggers it, and what it indicates. For steps to resolve common errors, see [How to Debug luci-sso](../how-to/sysadmin/debugging.md). For the HTTP endpoints that produce these codes, see the [HTTP API Reference](http-api.md).

---

## Configuration Errors

These occur before any OIDC flow begins, during startup or on the first request.

| Code | Trigger | What it means |
| :--- | :--- | :--- |
| `DISABLED` | `enabled` option is not `1` in UCI | SSO is installed but not activated. Set `uci set luci-sso.default.enabled='1'`. |
| `CONFIG_ERROR` | `issuer_url`, `client_id`, `client_secret`, or `clock_tolerance` is missing or invalid | Required UCI option is absent or malformed. Check `uci show luci-sso`. |
| `UCI_ERROR` | UCI cursor could not be created | The UCI system itself is unavailable — indicates a deeper OpenWrt system problem. |
| `SSO_DISABLED` | Config is null when a protected endpoint is accessed | No valid configuration exists. Equivalent to `CONFIG_ERROR` at request time. |

---

## Discovery Errors

These occur when the router fetches the IdP's `/.well-known/openid-configuration` document.

| Code | Trigger | What it means |
| :--- | :--- | :--- |
| `INSECURE_ISSUER_URL` | `issuer_url` does not begin with `https://` | The configured issuer URL uses HTTP. All OIDC endpoints must use HTTPS. |
| `INSECURE_FETCH_URL` | `internal_issuer_url` does not begin with `https://` | The split-horizon fetch URL uses HTTP. Must be HTTPS even for internal addresses. |
| `OIDC_DISCOVERY_FAILED` | Router cannot reach `<issuer_url>/.well-known/openid-configuration` | DNS resolution or network connectivity failure between router and IdP. Check firewall rules. |
| `DISCOVERY_FAILED` | Discovery endpoint returned a non-200 HTTP status | IdP is reachable but returned an error. Check IdP logs. |
| `INVALID_DISCOVERY_DOC` | Discovery response is not valid JSON | IdP returned a malformed discovery document. |
| `DISCOVERY_MISSING_ISSUER` | Discovery document does not contain an `issuer` field | IdP's discovery document is incomplete — not OIDC Core 1.0 compliant. |
| `DISCOVERY_ISSUER_MISMATCH` | `issuer` in discovery document does not match configured `issuer_url` | The IdP's declared issuer differs from what was configured. Verify `issuer_url` exactly matches the IdP's issuer identifier. |
| `MISSING_REQUIRED_FIELD` | Discovery document is missing `authorization_endpoint`, `token_endpoint`, or `jwks_uri` | IdP's discovery document is incomplete. |
| `INSECURE_ENDPOINT` | A required endpoint URL in the discovery document uses HTTP | IdP is advertising non-HTTPS endpoints. `luci-sso` refuses to proceed. |
| `JWKS_FETCH_FAILED` | Router cannot reach the `jwks_uri` | Network failure fetching the IdP's public key set. |
| `INSECURE_JWKS_URI` | `jwks_uri` from discovery document uses HTTP | IdP is advertising an insecure JWK Set endpoint. |
| `INVALID_JWKS_FORMAT` | JWKS response is not valid JSON or missing the `keys` array | IdP returned a malformed JWK Set. |

---

## Callback Errors

These occur when the browser returns from the IdP with an authorization code.

| Code | Trigger | What it means |
| :--- | :--- | :--- |
| `IDP_ERROR` | IdP returned an `error` parameter in the callback URL | The IdP explicitly rejected the authorization request. The error value (e.g. `access_denied`) is logged alongside this code. |
| `MISSING_CODE` | Callback URL contains no `code` parameter | IdP redirect did not include an authorization code. |
| `MISSING_HANDSHAKE_COOKIE` | `__Host-luci_sso_state` cookie is absent from the request | Browser did not send the handshake state cookie. Usually means the browser blocked the cookie (check `SameSite`/`Secure` requirements) or the session timed out. |
| `STATE_MISMATCH` | `state` parameter does not match the stored handshake state | Possible CSRF attempt, or the user completed the flow in a different browser tab. |
| `STATE_NOT_FOUND` | Handshake state file does not exist on the router filesystem | State was already consumed (replay attempt) or expired and was cleaned up. |
| `STATE_CORRUPTED` | Handshake state file exists but contains invalid data | Filesystem corruption or truncated write during state creation. |
| `STATE_SAVE_FAILED` | Router could not write the handshake state file | Check disk space and write permissions on `/etc/luci-sso/`. |

---

## Token Exchange Errors

These occur during the back-channel request from the router to the IdP's token endpoint.

| Code | Trigger | What it means |
| :--- | :--- | :--- |
| `INSECURE_TOKEN_ENDPOINT` | Token endpoint URL uses HTTP | IdP is advertising a non-HTTPS token endpoint. |
| `NETWORK_ERROR` | HTTP request to the token endpoint failed | Network or DNS failure on the router-to-IdP back channel. |
| `OIDC_INVALID_GRANT` | IdP returned `invalid_grant` | The authorization code was already used, expired, or the PKCE verifier is wrong. Codes are single-use. |
| `TOKEN_EXCHANGE_FAILED` | Token endpoint returned a non-200 HTTP status | IdP rejected the token exchange request. Check IdP logs for the specific reason. |
| `INVALID_JSON` | Token endpoint response is not valid JSON | IdP returned a malformed token response. |

---

## Token Validation Errors

These occur while validating the ID Token returned by the IdP.

| Code | Trigger | What it means |
| :--- | :--- | :--- |
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
| `MISSING_AT_HASH` | ID Token has no `at_hash` claim | Access token binding is mandatory. IdP must include `at_hash` when issuing ID Tokens with an access token. |
| `AT_HASH_MISMATCH` | `at_hash` does not match the hash of the access token | The access token has been substituted. Token binding violation. |

---

## UserInfo Errors

These occur during the optional UserInfo endpoint request (used to fetch group claims).

| Code | Trigger | What it means |
| :--- | :--- | :--- |
| `INSECURE_USERINFO_ENDPOINT` | UserInfo endpoint URL uses HTTP | IdP advertising a non-HTTPS UserInfo endpoint. |
| `USERINFO_FETCH_FAILED` | UserInfo endpoint returned a non-200 status | IdP rejected the UserInfo request. Usually a scope or permission issue. |
| `INVALID_JSON` | UserInfo response is not valid JSON | IdP returned a malformed UserInfo response. |
| `IDENTITY_MISMATCH` | `sub` claim in UserInfo response differs from `sub` in the ID Token | IdP returned user info for a different subject. Indicates an IdP configuration error. |

---

## Authorization Errors

These occur after token validation, when mapping the user's identity to a LuCI role.

| Code | Trigger | What it means |
| :--- | :--- | :--- |
| `NO_ROLES_MATCHED` | User's email and groups match no configured `config role` section | The authenticated user has no matching UCI role. Add their email or group to `/etc/config/luci-sso`. See [UCI Configuration](uci-config.md). |
| `USER_NOT_AUTHORIZED` | Matched role has no `read` or `write` permissions defined | A matching role exists but grants no LuCI access groups. Check the `read`/`write` options in the matched role. |
| `AUTH_FAILED` | Access token registration in the local session registry failed | Internal failure registering the token for replay protection. Check disk space on the router. |

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
| `SYSTEM_INIT_FAILED` | `/etc/luci-sso/` directory is missing or has wrong permissions, or the crypto backend failed to initialize | Check that the package was installed correctly. Re-run `opkg install luci-sso`. |
| `SYSTEM_KEY_GENERATION_FAILED` | Router could not generate the session signing key | Entropy source unavailable or filesystem write failure. |
| `SYSTEM_KEY_UNAVAILABLE` | Session signing key file does not exist and could not be created | Filesystem issue on the router. |
| `SYSTEM_KEY_WRITE_FAILED` | Session signing key could not be persisted to disk | Disk full or permission error on `/etc/luci-sso/`. |
| `SSL_INIT_FAILED` | TLS initialization failed | The router's CA bundle is missing or corrupt. Run `opkg install ca-bundle`. |
| `CRYPTO_ERROR` | A cryptographic operation returned an unexpected error | Internal error in the native C crypto bridge. |
| `CRYPTO_SYSTEM_FAILURE` | The PSA Crypto subsystem failed to initialize | MbedTLS PSA layer unavailable. May indicate a missing `mbedtls` package. |
| `TOO_MANY_REQUESTS` | More than 50 requests in a 60-second window from a single source | Rate limit hit. Indicates automated scanning or a misconfigured client retrying rapidly. |
| `INPUT_TOO_LARGE` | Query string, cookies, or environment variable exceeds 16 KB | Request exceeded the hard input limit. Rejects excessively large inputs as a hardening measure. |

