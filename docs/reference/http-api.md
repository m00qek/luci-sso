# HTTP API Reference

`luci-sso` exposes a CGI script at `https://<router>/cgi-bin/luci-sso/`. This document describes every endpoint, the cookies it reads and sets, the headers present on every response, the error response format, and the constraints applied to all requests.

---

## Base URL

```
https://<router>/cgi-bin/luci-sso
```

All paths below are relative to this base. Only HTTPS is accepted — the router's `uhttpd` configuration should not serve this path over HTTP.

---

## Endpoints

### `GET /` — Probe or initiate login

**Without parameters:** Starts the OIDC authorization code flow. Generates a PKCE pair, nonce, and state token; saves them to a handshake file; and redirects the browser to the IdP's authorization endpoint.

| | |
| :--- | :--- |
| Rate-limited | Yes |
| Requires configuration | Yes |
| **Success response** | `302` with `Location: <IdP authorize URL>` |
| **Sets cookie** | `__Host-luci_sso_state` (see [Cookies](#cookies)) |

**With `?action=enabled`:** Returns whether SSO is configured and enabled. Does not touch the OIDC flow. Safe to poll from scripts.

| | |
| :--- | :--- |
| Rate-limited | No |
| Requires configuration | No |
| **Success response** | `200 application/json` — `{"enabled": true}` or `{"enabled": false}` |

---

### `GET /callback` — Handle IdP redirect

Called automatically by the browser after the user authenticates at the IdP. The IdP appends `code` and `state` to the URL.

| Query parameter | Description |
| :--- | :--- |
| `code` | Authorization code issued by the IdP. Single-use, short-lived. |
| `state` | Must match the value stored in the `__Host-luci_sso_state` cookie. |

| | |
| :--- | :--- |
| Rate-limited | Yes |
| Requires configuration | Yes |
| **Success response** | `302` with `Location: /cgi-bin/luci/` |
| **Sets cookies** | `sysauth_https`, `sysauth` (see [Cookies](#cookies)) |
| **Clears cookie** | `__Host-luci_sso_state` (Max-Age=0) |

On failure, returns an error page (see [Error responses](#error-responses)).

---

### `GET /logout` — End the session

Destroys the active LuCI session and redirects the browser. If the IdP advertises an `end_session_endpoint` in its discovery document, the browser is sent there (RP-Initiated Logout). Otherwise, the browser is sent to `/`.

| Query parameter | Description |
| :--- | :--- |
| `stoken` | CSRF token. Must match the `token` field of the current UBUS session. LuCI includes this automatically in logout links. |

| | |
| :--- | :--- |
| Rate-limited | Yes |
| Requires configuration | Yes — discovery runs to find `end_session_endpoint` |
| **Success response** | `302` with `Location: <end_session_endpoint or />` |
| **Clears cookies** | `sysauth_https`, `sysauth` (Max-Age=0) |
| **Error on missing/invalid `stoken`** | `403` — CSRF check failure |

If no active session is found (cookie absent or session already expired), the endpoint returns `302 /` without error.

---

## Cookies

### `__Host-luci_sso_state`

Carries the handshake state token during the OIDC flow. The `__Host-` prefix enforces that the cookie is only sent over HTTPS and is scoped to the root path.

| Attribute | Value |
| :--- | :--- |
| Name | `__Host-luci_sso_state` |
| `HttpOnly` | Yes |
| `Secure` | Yes |
| `SameSite` | `Lax` |
| `Path` | `/` |
| `Max-Age` | `300` (5 minutes) — matches the handshake lifetime |

### `sysauth_https`

The LuCI session cookie for HTTPS connections.

| Attribute | Value |
| :--- | :--- |
| Name | `sysauth_https` |
| `HttpOnly` | Yes |
| `Secure` | Yes |
| `SameSite` | `Strict` |
| `Path` | `/` |
| `Max-Age` | Not set — session cookie (expires when browser closes) |

### `sysauth`

A compatibility alias for `sysauth_https`. LuCI reads whichever is present.

| Attribute | Value |
| :--- | :--- |
| Name | `sysauth` |
| `HttpOnly` | Yes |
| `Secure` | Yes |
| `SameSite` | `Strict` |
| `Path` | `/` |

---

## Security headers

Every response — success, redirect, and error — includes these headers:

| Header | Value |
| :--- | :--- |
| `Content-Security-Policy` | `default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; frame-ancestors 'none';` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Cache-Control` | `no-store` |
| `Referrer-Policy` | `no-referrer` |

These are set unconditionally in `web.uc:render()` and cannot be suppressed.

---

## Error responses

When a request fails, the CGI returns a plain-text body with a user-facing message. Internal error codes are **not** included in the response body — they appear only in the system log (`logread -e luci-sso`).

```
HTTP/1.1 400 Bad Request
Content-Type: text/plain

Error: Your session has expired or is invalid. You MUST try logging in again.
```

| HTTP status | When it occurs |
| :--- | :--- |
| `400 Bad Request` | Malformed callback parameters |
| `401 Unauthorized` | Authentication flow failed |
| `403 Forbidden` | CSRF token missing or invalid on logout |
| `404 Not Found` | Path does not match any endpoint |
| `429 Too Many Requests` | Rate limit exceeded |
| `431 Request Header Fields Too Large` | Input exceeded 16 KB |
| `503 Service Unavailable` | SSO is not configured or not enabled |
| `500 Internal Server Error` | Unexpected crash or system failure |

For the mapping from internal error codes to HTTP statuses, see [Log Messages](log-messages.md).

---

## Request limits

These constraints apply to all rate-limited endpoints:

<!-- LIMIT_REQUESTS=50 -->
<!-- LIMIT_WINDOW=60 -->
<!-- LIMIT_INPUT_LEN=16384 -->
<!-- LIMIT_PARAM_COUNT=100 -->

| Limit | Value |
| :--- | :--- |
| Maximum query string length | 16 384 bytes |
| Maximum cookie header length | 16 384 bytes |
| Maximum number of query parameters | 100 |
| Maximum number of cookies | 100 |
| Rate limit | 50 requests per 60-second window |

The rate limit is global — it counts all requests across all source addresses. It does not apply to `?action=enabled`.

Requests that exceed the size limits return `431`. Requests that exceed the rate limit return `429`.

---

## Back-channel limits

These constraints apply to the router's outbound requests to the IdP (discovery, JWKS, token endpoint, UserInfo).

<!-- LIMIT_RESPONSE_SIZE=262144 -->
<!-- LIMIT_TOKEN_SIZE=16384 -->

| Limit | Value |
| :--- | :--- |
| Maximum IdP response body (discovery, JWKS, token, UserInfo) | 256 KB |
| Maximum ID Token size | 16 KB |

Responses that exceed the response size limit are rejected before being parsed — the router logs `OIDC_DISCOVERY_FAILED`, `JWKS_FETCH_FAILED`, `TOKEN_ENDPOINT_NETWORK_ERROR`, or `USERINFO_NETWORK_ERROR` depending on which back-channel call triggered it. ID Tokens that exceed the token size limit cause `ID_TOKEN_VERIFICATION_FAILED`.
