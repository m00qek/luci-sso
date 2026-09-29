# HTTP API Reference

`luci-sso` exposes a CGI script at `https://<router>/cgi-bin/luci-sso/`. This document describes every endpoint, the cookies it reads and sets, the headers present on every response, the error response format, and the constraints applied to all requests.

---

## Base URL

```
https://<router>/cgi-bin/luci-sso
```

All paths below are relative to this base. The script does not check the scheme itself, but every cookie it sets is `Secure`, so the flow works only when the browser uses HTTPS. `uhttpd` should not serve this path to browsers over HTTP; it may serve it over HTTP to a reverse proxy that terminates TLS. The script does not read the `Host` header: it builds its redirects from `redirect_uri` or as relative paths. See [How to Run LuCI Behind a Reverse Proxy](../how-to/sysadmin/reverse-proxy.md).

The endpoints are listed as `GET`, the method the browser uses. The script does not check the request method.

---

## Endpoints

The three paths the CGI script answers. Each entry lists whether the endpoint is rate-limited, whether it needs a valid configuration, and the cookies it sets or clears.

### `GET /` — Probe or initiate login

**Without parameters:** Starts the OIDC authorization code flow. Removes stale handshake files, loads the IdP's discovery document (cached for 24 hours), generates a PKCE pair, nonce, and state token, saves them to a handshake file, and redirects the browser to the IdP's authorization endpoint.

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
| Requires configuration | No, unless SSO is enabled |
| **Success response** | `200 application/json` — `{"enabled": true}` or `{"enabled": false}` |
| **Error response** | `500` error page when `enabled` is `1` but the configuration is invalid (`CONFIG_ERROR`) |

---

### `GET /callback` — Handle IdP redirect

Called automatically by the browser after the user authenticates at the IdP. The IdP appends `code` and `state` to the URL, or `error` when it refused the request.

| Query parameter | Description |
| :--- | :--- |
| `code` | Authorization code issued by the IdP. Single-use, short-lived. |
| `state` | Must match the `state` stored on the router in the handshake that the `__Host-luci_sso_state` cookie points to. |
| `error` | Set by the IdP instead of `code` when it refused the authorization request (RFC 6749 §4.1.2.1), for example `access_denied`. Checked first: the request fails with `[400] IDP_ERROR`. |
| `error_description` | Optional text from the IdP that explains `error`. Logged, sanitized, with `error`; never shown on the page. |

| | |
| :--- | :--- |
| Rate-limited | Yes |
| Requires configuration | Yes |
| **Success response** | `302` with `Location: /cgi-bin/luci/` |
| **Sets cookies** | `sysauth_https`, `sysauth` (see [Cookies](#cookies)) |
| **Clears cookies** | `__Host-luci_sso_state`, and any `sysauth_https` and `sysauth` at `Path=/cgi-bin/luci` (Max-Age=0) |

On failure, returns an error page (see [Error responses](#error-responses)).

---

### `GET /logout` — End the session

Destroys the active LuCI session and redirects the browser. If the IdP advertises an HTTPS `end_session_endpoint` in its discovery document, the browser is sent there (RP-Initiated Logout) with `id_token_hint` (the ID token stored in the session) and `post_logout_redirect_uri` (the origin of `redirect_uri` followed by `/`). Otherwise, the browser is sent to `/`.

| Query parameter | Description |
| :--- | :--- |
| `stoken` | CSRF token. Must match the `token` field of the current UBUS session. |

| | |
| :--- | :--- |
| Rate-limited | Yes |
| Requires configuration | Yes — discovery runs to find `end_session_endpoint` |
| **Success response** | `302` with `Location: <end_session_endpoint or />` |
| **Clears cookies** | `sysauth_https`, `sysauth`, at both `Path=/` and `Path=/cgi-bin/luci` (Max-Age=0) |
| **Error on missing/invalid `stoken`** | `403` — CSRF check failure |

If no active session is found (cookie absent or session already expired), the endpoint returns `302 /` without error. An ended session is logged as `Logout for [sub_id: …] (role=<role>)`; see [Log Messages](log-messages.md#logout).

!!! note "LuCI's Log out entry uses this endpoint for SSO sessions"
    `luci-sso` overrides the action of LuCI's `admin/logout` menu entry (`/usr/share/luci/menu.d/luci-sso-logout.json`, handled by `luci.controller.sso`). For a session whose username is `sso:<role>` and that has a CSRF token it redirects to `/cgi-bin/luci-sso/logout?stoken=<session token>`; for any other session it runs LuCI's own logout unchanged.

---

## Cookies

The cookies `luci-sso` sets. The handshake cookie lives only during a login; the two session cookies carry the LuCI session afterwards. None sets `Domain`, so the browser returns each only to the host it used; behind a reverse proxy, that is the proxy's public host name.

### `__Host-luci_sso_state`

Carries an opaque handle to the handshake during the OIDC flow. The handshake itself (`state`, `nonce`, PKCE verifier and timestamps) is stored on the router in `/var/run/luci-sso/`. The `__Host-` prefix makes the browser send the cookie only over HTTPS, only to the exact host that set it, and only with `Path=/`.

| Attribute | Value |
| :--- | :--- |
| Name | `__Host-luci_sso_state` |
| `HttpOnly` | Yes |
| `Secure` | Yes |
| `SameSite` | `Lax` |
| `Path` | `/` |
| `Max-Age` | `300` (5 minutes) — matches the handshake lifetime |

### `sysauth_https`

The LuCI session cookie for HTTPS connections. Its value is the `rpcd` session ID. `sysauth_http`, which LuCI's password login sets over plain HTTP, is never set.

LuCI's own password login sets its cookies at `Path=/cgi-bin/luci`. Because a cookie with a longer path is sent first and would shadow this one, the callback and `/logout` also expire any `sysauth_https` and `sysauth` at that path.

| Attribute | Value |
| :--- | :--- |
| Name | `sysauth_https` |
| `HttpOnly` | Yes |
| `Secure` | Yes |
| `SameSite` | `Lax` |
| `Path` | `/` |
| `Max-Age` | Not set — session cookie (expires when browser closes) |

### `sysauth`

The legacy session cookie name, read by older LuCI versions. It carries the same session ID as `sysauth_https`, and `/logout` reads either one.

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

`web.uc` adds these to every response it writes (`render`, `render_error` and the crash handler `error`); they cannot be suppressed.

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

| HTTP status | When it occurs | Error codes |
| :--- | :--- | :--- |
| `400 Bad Request` | The IdP sent the browser back with an error or without a code | `IDP_ERROR`, `MISSING_CODE` |
| `401 Unauthorized` | The handshake is missing, invalid or expired, or the ID Token failed validation | `MISSING_HANDSHAKE_COOKIE`, `MALFORMED_STATE_COOKIE`, `STATE_NOT_FOUND`, `STATE_CORRUPTED`, `HANDSHAKE_EXPIRED`, `HANDSHAKE_NOT_YET_VALID`, `ID_TOKEN_VERIFICATION_FAILED` |
| `403 Forbidden` | The request is not allowed: wrong `state`, no matching role, UserInfo for another subject, a replayed access token, or a bad logout CSRF token | `STATE_PARAMETER_MISMATCH`, `USER_NOT_AUTHORIZED`, `IDENTITY_MISMATCH`, `TOKEN_REPLAYED`, `CSRF_CHECK_FAILED` |
| `404 Not Found` | Path does not match any endpoint | `NOT_FOUND` |
| `429 Too Many Requests` | Per-client rate limit exceeded; `Retry-After` says when to retry | `TOO_MANY_REQUESTS` |
| `431 Request Header Fields Too Large` | Input exceeded a size or count limit | `INPUT_TOO_LARGE` |
| `502 Bad Gateway` | A back-channel request from the router to the IdP failed: no response, a status other than 200, an unusable body, or a refused authorization code | `OIDC_DISCOVERY_FAILED`, `TOKEN_ENDPOINT_NETWORK_ERROR`, `TOKEN_EXCHANGE_FAILED`, `OIDC_INVALID_GRANT`, `TOKEN_RESPONSE_INVALID_JSON`, `JWKS_FETCH_FAILED` |
| `503 Service Unavailable` | 500 logins are already in progress | `HANDSHAKE_CAPACITY_EXCEEDED` |
| `500 Internal Server Error` | SSO is disabled or misconfigured, a system failure, or a crash | `SSO_DISABLED`, `CONFIG_ERROR`, `UBUS_LOGIN_FAILED` and every other code |

The IdP's own HTTP status is never passed on to the browser. A token endpoint that answers `401` to a wrong client secret still produces `502`: the router's credentials were refused, not the browser's. The IdP's status, or the transport cause, is in the log line before the `[502]` line; see [Log Messages](log-messages.md#how-codes-appear-in-the-log).

For what each code means and how it is logged, see [Log Messages](log-messages.md).

---

## Request limits

The size limits apply to every request, including `?action=enabled`. The rate limits apply to every request except `?action=enabled`.

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
| Maximum `PATH_INFO` or `REMOTE_ADDR` length | 16 384 bytes |
| Maximum number of query parameters | 100 |
| Maximum number of cookies | 100 |
| Login initiations (`GET /`) per client | 10 per 5 minutes |
| Rate-limited requests per client | 30 per minute |
| Clients tracked at once | 256; the least recently seen is forgotten first |
| Logins in progress (handshakes) | 500 at once; expired ones are removed to make room, live ones never are. Beyond that, a new login gets `503` |

Rate limits are per client:

- **Client identity.** A client is its source address as uhttpd reports it (`REMOTE_ADDR`): the full address for IPv4, the `/64` prefix for IPv6, and one shared bucket for an address that cannot be parsed.
- **Budgets spent.** `GET /` spends both budgets; `/callback`, `/logout` and unknown paths spend only the per-minute one. `?action=enabled` is never limited.
- **No global limit.** There is no router-wide limit: uhttpd's cap on concurrent CGI processes bounds the total load.
- **Reverse proxies.** Behind a reverse proxy, every client arrives with the proxy's address and shares one budget. `X-Forwarded-For` is not trusted. See [How to Run LuCI Behind a Reverse Proxy](../how-to/sysadmin/reverse-proxy.md).

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
| Request timeout | 10 seconds |

Only HTTPS URLs are requested, and the IdP's certificate is always verified against the router's CA store.

Responses that exceed the response size limit are rejected before being parsed, with the cause `HTTP_REQUEST_FAILED (RESPONSE_TOO_LARGE)`. The request then ends with `OIDC_DISCOVERY_FAILED`, `JWKS_FETCH_FAILED` or `TOKEN_ENDPOINT_NETWORK_ERROR`, depending on which back-channel call triggered it, unless an expired cached discovery document or JWK Set can be used instead; a UserInfo response only logs `UserInfo fallback failed`. ID Tokens that exceed the token size limit cause `ID_TOKEN_VERIFICATION_FAILED`.
