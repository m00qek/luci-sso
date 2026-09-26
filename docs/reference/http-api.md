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
| `stoken` | CSRF token. Must match the `token` field of the current UBUS session. |

| | |
| :--- | :--- |
| Rate-limited | Yes |
| Requires configuration | Yes — discovery runs to find `end_session_endpoint` |
| **Success response** | `302` with `Location: <end_session_endpoint or />` |
| **Clears cookies** | `sysauth_https`, `sysauth` (Max-Age=0) |
| **Error on missing/invalid `stoken`** | `403` — CSRF check failure |

If no active session is found (cookie absent or session already expired), the endpoint returns `302 /` without error.

!!! note "LuCI's own logout does not call this endpoint"
    The **Log out** link in LuCI's menu goes to LuCI's dispatcher, not here. It ends the router session, but no RP-Initiated Logout happens and the user stays signed in at the IdP. `luci-sso` does not currently rewrite that link. To end the IdP session as well, send the browser to this endpoint with the session's `token` value as `stoken`.

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
| `SameSite` | `Lax` |
| `Path` | `/` |
| `Max-Age` | Not set — session cookie (expires when browser closes) |

### `sysauth`

A compatibility alias for `sysauth_https`. LuCI reads whichever is present.

| Attribute | Value |
| :--- | :--- |
| Name | `sysauth` |
| `HttpOnly` | Yes |
| `Secure` | Yes |
| `SameSite` | `Lax` |
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

When a request fails, the CGI returns a small HTML page: a heading, one plain-language message and a link back to the LuCI login page at `/cgi-bin/luci/`. Internal error codes are **not** included in the response body — they appear only in the system log (`logread -e luci-sso`). The page has no inline style or script, so it is served under the same Content-Security-Policy as every other response.

```
HTTP/1.1 401 Unauthorized
Content-Type: text/html; charset=utf-8

<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Single sign-on</title></head>
<body>
<h1>Single sign-on</h1>
<p>Your sign-in attempt expired or was already used. Please try signing in again.</p>
<p><a href="/cgi-bin/luci/">Back to the login page</a></p>
</body>
</html>
```

An unexpected crash returns the same page with status `500` and a generic message; the exception text is logged, never sent.

| HTTP status | When it occurs |
| :--- | :--- |
| `400 Bad Request` | Malformed callback parameters |
| `401 Unauthorized` | Authentication flow failed |
| `403 Forbidden` | CSRF token missing or invalid on logout |
| `404 Not Found` | Path does not match any endpoint |
| `429 Too Many Requests` | Per-client rate limit exceeded; `Retry-After` says when to retry |
| `431 Request Header Fields Too Large` | Input exceeded 16 KB |
| `503 Service Unavailable` | SSO is not configured or not enabled, or 500 logins are already in progress |
| `500 Internal Server Error` | Unexpected crash or system failure |

For the mapping from internal error codes to HTTP statuses, see [Log Messages](log-messages.md).

---

## Request limits

These constraints apply to all rate-limited endpoints:

<!-- LIMIT_LOGIN_REQUESTS=10 -->
<!-- LIMIT_LOGIN_WINDOW=300 -->
<!-- LIMIT_CLIENT_REQUESTS=30 -->
<!-- LIMIT_CLIENT_WINDOW=60 -->
<!-- LIMIT_TRACKED_CLIENTS=256 -->
<!-- LIMIT_INPUT_LEN=16384 -->
<!-- LIMIT_PARAM_COUNT=100 -->
<!-- LIMIT_PENDING_HANDSHAKES=500 -->

| Limit | Value |
| :--- | :--- |
| Maximum query string length | 16 384 bytes |
| Maximum cookie header length | 16 384 bytes |
| Maximum number of query parameters | 100 |
| Maximum number of cookies | 100 |
| Login initiations (`GET /`) per client | 10 per 5 minutes |
| Rate-limited requests per client | 30 per minute |
| Clients tracked at once | 256; the least recently seen is forgotten first |
| Logins in progress (handshakes) | 500 at once; expired ones are removed to make room, live ones never are. Beyond that, a new login gets `503` |

Rate limits are per client. A client is its source address as uhttpd reports it (`REMOTE_ADDR`): the full address for IPv4, the `/64` prefix for IPv6, and one shared bucket for an address that cannot be parsed. `GET /` spends both budgets; `/callback`, `/logout` and unknown paths spend only the per-minute one. `?action=enabled` is never limited. There is no router-wide limit: uhttpd's cap on concurrent CGI processes bounds the total load.

Behind a reverse proxy, every client arrives with the proxy's address and shares one budget. `X-Forwarded-For` is not trusted.

Requests that exceed the size limits return `431`. Requests that exceed a rate limit return `429` with a `Retry-After` header giving the seconds until that budget resets.

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
